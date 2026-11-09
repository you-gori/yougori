//! The engine's setup service: the one writer of setup state.
//!
//! A plan is reviewed first and kept here; applying it saves the operation (durable intent) and
//! claims the setup before any handler runs. The claim is the setup's `current_operation` and its
//! revision, both on disk, so it holds across restarts and between the desktop and the CLI: a
//! second request either joins the same operation or gets a precise conflict. Each step saves
//! its intent before acting and its receipt right after. A step interrupted in between is
//! settled by looking (`recover`/`observe`), never by doing it again blindly.
use super::{
    adopt,
    handler::{words, Admission, HandlerError, Handlers, Observation, Outcome, Peer, Planned, Recovery, ResourceHandler, StepContext},
    journal::{step_key, valid_operation_id, Action, Operation, OperationKind, OperationState, Receipt, Step, StepState},
    model::{
        credential_field, digest, new_id, now, valid_id, valid_resource_id, Borrower, Cost, Desired, Diagnostic, Health,
        HistoryEntry, Instance, InstanceChange, Lifecycle, Observed, OwnerRef, Resource, Tombstone,
    },
    ordinary::folder_sync,
    store::{Registry, Store},
    views,
};
use crate::foundation::evidence::ClockReading;
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;
use yougori_setup::{dto, resource::Kind};

const PLAN_LIFETIME: Duration = Duration::from_secs(30 * 60);
const PLAN_LIMIT: usize = 64;
const FINISHED_PER_SETUP: usize = 32;
const FINISHED_TOTAL: usize = 512;
const SETUP_LIMIT: usize = 256;
/// How long one look at the legacy products' records is reused.
const ADOPTION_CACHE: Duration = Duration::from_secs(3);
const STEP_LIMIT: usize = 128;
const SPEC_LIMIT: usize = 64 * 1024;
const HISTORY_LIMIT: usize = 50;

/// One resource as the planner declared it, in dependency order.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DeclaredResource {
    pub id: String,
    pub kind: Kind,
    pub spec: Value,
    /// Other resources of the same setup this one needs.
    pub requires: Vec<String>,
    /// Set when this resource is a binding to a resource another setup owns.
    pub owner: Option<OwnerRef>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct SetupDraft {
    pub change: InstanceChange,
    pub resources: Vec<DeclaredResource>,
}

pub(crate) enum PlanIntent {
    /// Built from a template by the planner (`planning`).
    Create(SetupDraft),
    Update { setup: String, draft: SetupDraft },
    Start { setup: String },
    Stop { setup: String },
    Remove { setup: String },
    /// Recreate resources found missing, from their saved specification. Never automatic.
    Repair { setup: String },
    /// One part of a setup on its own: start or stop a part that runs, remove a part the setup
    /// owns, or detach a part it borrows. Applied as a change to the setup, so the rest of it is
    /// left as it is and the setup itself stays running or stopped.
    Part { setup: String, resource: String, action: Action },
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PlannedStep {
    pub id: String,
    pub resource: String,
    pub kind: Kind,
    pub action: Action,
    pub depends_on: Vec<String>,
    pub requires: Vec<String>,
    pub spec: Value,
    pub generation: u64,
    pub owner: Option<OwnerRef>,
}

/// A plan as the person reviews it. Applying refers to it by ID and digest; a plan that no
/// longer matches the setup is refused rather than applied over newer changes.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReviewedPlan {
    pub plan_id: String,
    pub setup_id: String,
    pub intent: OperationKind,
    pub base_revision: u64,
    pub digest: String,
    pub steps: Vec<PlannedStep>,
    pub change: Option<InstanceChange>,
    /// Plain notes for the review: kept data, borrowed resources left alone, removed declarations.
    pub notes: Vec<String>,
    /// What this review offers to do only if the person ticks it (`{id, message}`): a removal's
    /// choice to delete a volume and its backups. Kept in memory with the plan, and part of its
    /// digest, so an apply can agree only to what was offered on the review it applies.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub offered: Vec<Value>,
    pub expires_at: String,
    /// The planner's own digest when the plan came from a template. The client may apply by it.
    #[serde(skip)]
    pub source_digest: Option<String>,
    /// The template package the plan came from, kept beside the setup when it is applied.
    #[serde(skip)]
    pub package: Option<Arc<yougori_setup::format::Files>>,
}

pub(crate) fn plan_digest(plan: &ReviewedPlan) -> String {
    let mut reviewed = json!({
        "setup": plan.setup_id,
        "intent": plan.intent,
        "baseRevision": plan.base_revision,
        "steps": plan.steps,
        "change": plan.change,
    });
    // Only when there is something on offer, so every plan without one keeps the digest it had.
    if !plan.offered.is_empty() {
        reviewed["offered"] = json!(plan.offered.iter().map(|offer| &offer["id"]).collect::<Vec<_>>());
    }
    digest(&reviewed)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Submitted {
    pub operation_id: String,
    pub setup_id: String,
    pub joined: bool,
}

impl Submitted {
    pub(crate) fn reference(&self) -> dto::OperationRef {
        dto::OperationRef { operation_id: self.operation_id.clone(), setup_id: self.setup_id.clone() }
    }
}

pub(crate) struct Service {
    store: Store,
    data_root: PathBuf,
    /// `<setups>/projects`: each setup's project and package copy.
    projects: PathBuf,
    handlers: Handlers,
    /// The current registry for readers, who never wait for a save. `Err` when the registry file
    /// was refused; every call then reports why, and nothing writes.
    snapshot: RwLock<Result<Arc<Registry>, Diagnostic>>,
    /// Serialises writers: change a copy, save it, then publish it as the snapshot.
    writer: Mutex<()>,
    plans: Mutex<BTreeMap<String, (ReviewedPlan, Instant)>>,
    /// Operations a runner or a reconciliation is working on in this engine.
    running: Mutex<HashMap<String, CancellationToken>>,
    secrets: Mutex<HashMap<String, Arc<BTreeMap<String, String>>>>,
    adopted: Mutex<Option<(Instant, Vec<adopt::Adopted>)>>,
    /// Scheduled backups, wired once the engine has started (`setups::start`). Both are absent
    /// in tests that do not use them, and every call that reads them says so plainly.
    backups: std::sync::OnceLock<Arc<super::backups::Backups>>,
    scheduler: std::sync::OnceLock<Arc<super::schedules::Scheduler>>,
    /// What each part of each setup said about its health when it was last checked, in its own
    /// words: kept in memory only, so the setup page and the watcher can say why, and gone after a
    /// restart until the next check. Never written to the registry.
    health_reports: Mutex<HashMap<String, BTreeMap<String, PartHealth>>>,
    /// Jobs' event addresses, wired once the engine has started; absent in tests that don't use them.
    events: std::sync::OnceLock<Arc<dyn EventsSync>>,
}

/// What follows every change to a setup outside the registry: its jobs' event addresses
/// (`setups::events`).
pub(crate) trait EventsSync: Send + Sync {
    fn sync<'a>(&'a self, setup: &'a str) -> super::ordinary::BoxFuture<'a, ()>;
}

/// What one part said about its health at its last check.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct PartHealth {
    pub health: Health,
    pub detail: String,
    pub at: String,
}

/// Removes an operation from the running table however its runner ends.
struct RunGuard<'a> {
    running: &'a Mutex<HashMap<String, CancellationToken>>,
    operation: String,
}

impl Drop for RunGuard<'_> {
    fn drop(&mut self) {
        lock(self.running).remove(&self.operation);
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Runs disk work so it doesn't stall the async runtime's other tasks: on a multi-threaded
/// runtime the worker hands its queue to others while it waits.
fn blocking<T>(work: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => tokio::task::block_in_place(work),
        _ => work(),
    }
}

fn invalid(message: &str) -> Diagnostic {
    Diagnostic::new("invalid_request", message)
}

fn not_found(setup: &str) -> Diagnostic {
    Diagnostic::new("setup_not_found", "This setup is not on this computer.").resource(setup)
}

fn legacy_managed(setup: &str) -> Diagnostic {
    // Swarm Mining isn't listed in My setups, so its message sends nobody there.
    let message = if adopt::is_swarm_mining_id(setup) {
        "Swarm Mining is left as it is; it is managed on its own, not from here."
    } else {
        "This older grid was found on this computer and is still managed from its own tab in My setups. Setup actions can't change it yet."
    };
    Diagnostic::new("legacy_managed", message).resource(setup)
}

fn busy(operation: &Operation) -> Diagnostic {
    Diagnostic::new(
        "setup_busy",
        format!(
            "Another change to this setup is {} right now. Wait for it to finish, or cancel it first.",
            match operation.state {
                OperationState::Unknown => "waiting to be checked",
                OperationState::AwaitingInput => "waiting for your answers",
                _ => "in progress",
            }
        ),
    )
    .operation(&operation.id)
    .retryable()
    .next(match operation.state {
        OperationState::Unknown => &["reconcile"],
        OperationState::AwaitingInput => &["continue", "cancel"],
        _ => &["wait", "cancel"],
    })
}

fn removed(setup: &str) -> Diagnostic {
    Diagnostic::new(
        "setup_removed",
        "This setup was removed. An older plan or request can't bring it back; start a new setup instead.",
    )
    .resource(setup)
}

impl Service {
    /// Opens the registry in `folder`. Operations a previous engine left running are settled
    /// first: a step that was mid-call becomes unknown, to be reconciled by looking.
    pub(crate) fn open(folder: &Path, data_root: &Path, handlers: Handlers) -> Self {
        let store = Store::new(folder);
        let loaded = store.load().map(Arc::new);
        let service = Self {
            store,
            data_root: data_root.to_owned(),
            projects: folder.join("projects"),
            handlers,
            snapshot: RwLock::new(loaded),
            writer: Mutex::new(()),
            plans: Default::default(),
            running: Default::default(),
            secrets: Default::default(),
            adopted: Default::default(),
            backups: Default::default(),
            scheduler: Default::default(),
            health_reports: Default::default(),
            events: Default::default(),
        };
        let settle = |registry: &mut Registry| {
            interrupted(registry);
            Ok(())
        };
        if let Err(error) = service.commit(settle) {
            if error.code == "durable_storage_unavailable" {
                // Disk still shows the old states; a later start settles them the same way.
                let _ = service.ephemeral(settle);
            }
        }
        service
    }

    pub(crate) fn handler_kinds(&self) -> Vec<Kind> {
        self.handlers.kinds()
    }

    /// Why the registry is unusable, if it is.
    pub(crate) fn availability(&self) -> Option<Diagnostic> {
        self.current().err()
    }

    fn current(&self) -> Result<Arc<Registry>, Diagnostic> {
        self.snapshot.read().unwrap_or_else(|poisoned| poisoned.into_inner()).clone()
    }

    fn publish(&self, registry: Registry) {
        *self.snapshot.write().unwrap_or_else(|poisoned| poisoned.into_inner()) = Ok(Arc::new(registry));
    }

    fn read<T>(&self, view: impl FnOnce(&Registry) -> Result<T, Diagnostic>) -> Result<T, Diagnostic> {
        let registry = self.current()?;
        view(&registry)
    }

    /// Applies `change` to a copy, saves the copy, and only then publishes it. A failed save
    /// leaves memory and disk exactly as they were. Readers keep the previous snapshot meanwhile.
    fn commit<T>(&self, change: impl FnOnce(&mut Registry) -> Result<T, Diagnostic>) -> Result<T, Diagnostic> {
        let _writer = lock(&self.writer);
        let current = self.current()?;
        let mut candidate = (*current).clone();
        let value = change(&mut candidate)?;
        if candidate != *current {
            candidate.revision = current.revision + 1;
            blocking(|| match self.store.save(&candidate) {
                Err(error) if error.code == "registry_full" => {
                    // Make room from old history, so the change that frees space can still land.
                    shrink(&mut candidate);
                    self.store.save(&candidate)
                }
                other => other,
            })?;
            self.publish(candidate);
        }
        Ok(value)
    }

    /// Changes memory only. Used when a save failed after an effect happened, so this engine
    /// shows the truth (outcome unknown) while the disk still holds the intent.
    fn ephemeral<T>(&self, change: impl FnOnce(&mut Registry) -> Result<T, Diagnostic>) -> Result<T, Diagnostic> {
        let _writer = lock(&self.writer);
        let mut candidate = (*self.current()?).clone();
        let value = change(&mut candidate)?;
        self.publish(candidate);
        Ok(value)
    }

    /// This engine's own live data folder, read-only. The migration dry run compares a folder it
    /// was given against this one so it can refuse to read the installation that is running
    /// (plan 19.5). Nothing is written through this.
    pub(crate) fn data_root(&self) -> &Path {
        &self.data_root
    }

    /// The legacy products' records, looked at no more often than every few seconds. Only file
    /// metadata is read, so a product saving its own records is never in the way.
    fn adopted(&self) -> Vec<adopt::Adopted> {
        let mut cache = lock(&self.adopted);
        if let Some((at, records)) = cache.as_ref() {
            if at.elapsed() < ADOPTION_CACHE {
                return records.clone();
            }
        }
        let records = adopt::scan(&self.data_root);
        *cache = Some((Instant::now(), records.clone()));
        records
    }

    /// The plan that adopts a grid hub the legacy product runs on this computer into a new setup.
    /// Bookkeeping only: its one resource records the hub that is already here (its hub ID is
    /// read from the product's status when applied); nothing is moved, restarted or re-keyed, and
    /// the product's own records are never written. Swarm Mining is left as it is, managed on its
    /// own, and a record Yougori can't look at is never adopted.
    pub(crate) fn adoption(&self, adopted: &str) -> Result<PlanIntent, Diagnostic> {
        let record = self.adopted().into_iter().find(|record| record.id == adopted).ok_or_else(|| not_found(adopted))?;
        if record.profile == dto::GridProfile::SwarmMiningGrid {
            return Err(Diagnostic::new("unsupported_here", "Swarm Mining is left as it is; it is managed on its own, not from here, and can't be adopted into a setup. Nothing was changed."));
        }
        if !record.readable {
            return Err(Diagnostic::new("unreadable", "Yougori can't look at this grid's records, so it won't adopt it. Nothing was changed."));
        }
        if record.role != "hub" {
            return Err(Diagnostic::new("unsupported_here", "Only a grid whose hub runs on this computer can be adopted for now; a membership stays managed from its own tab in My setups. Nothing was changed."));
        }
        // The first grid of a kind is in the product's first instance; a later one says which.
        let key = record.instance.clone().unwrap_or_else(|| super::grids::FIRST.to_owned());
        if self.read(|registry| Ok(owned_grids(registry)))?.contains(&(record.profile.id().to_owned(), record.role, key)) {
            return Err(Diagnostic::new("already_adopted", "This grid already belongs to a setup. Nothing was changed."));
        }
        let name = record.name.split(" (").next().unwrap_or("Grid").to_owned();
        let change = InstanceChange {
            name,
            source: super::model::Source { reference: dto::SourceRef::InstalledSetup { setup_id: record.id.clone() }, digest: format!("sha256:{}", digest(&json!({ "adopted": record.id }))) },
            format_version: 2,
            protocol_version: dto::CONTRACT_VERSION,
            lock_digest: None,
            answers: BTreeMap::new(),
            secret_bindings: BTreeMap::new(),
            lock: None,
            capabilities: Vec::new(),
        };
        let mut spec = json!({ "profile": record.profile.id(), "mode": "create", "adopted": true });
        if let Some(instance) = &record.instance {
            spec["instance"] = json!(instance);
        }
        let grid = DeclaredResource { id: "grid".into(), kind: Kind::Grid, spec, requires: Vec::new(), owner: None };
        Ok(PlanIntent::Create(SetupDraft { change, resources: vec![grid] }))
    }

    /// The plan that joins this computer to a Neo or Sandbox Grid with the invitation it was
    /// given. The invitation is read here only to tell which grid it is for and its company's
    /// name; it is never kept with the plan. It comes again, with the company password, as the
    /// apply secrets `invitation` and `join_password`.
    pub(crate) fn joining(&self, invitation: &str) -> Result<PlanIntent, Diagnostic> {
        use yougori_grid::invite;
        let text = invitation.trim();
        // A person's scoped invitation: their own account in a Sandbox or Access Grid, which
        // this computer signs in to. Everything it carries comes again, as the apply secret
        // `invitation`; only the grid it is for and the username are read here.
        if let Some(scoped) = super::grids::scoped::decode(text) {
            let (profile, product, decoded) = if scoped.invite.starts_with(invite::DESK_PREFIX) {
                ("sandbox_grid", "Sandbox Grid", invite::decode_desk(&scoped.invite))
            } else if scoped.invite.starts_with(invite::ACCESS_PREFIX) {
                ("access_grid", "Access Grid", invite::decode_access(&scoped.invite))
            } else {
                return Err(invalid("That invitation is for a person, but not to a Sandbox or Access Grid."));
            };
            // The company's name, for the setup's; the product checks the invite itself.
            let company = decoded.map(|invite| invite.company).unwrap_or_default();
            let name = format!("{company} {product}").trim().chars().take(64).collect::<String>();
            let change = InstanceChange {
                name: if name.trim().is_empty() { product.to_owned() } else { name },
                source: super::model::Source { reference: dto::SourceRef::InstalledSetup { setup_id: "joined".into() }, digest: format!("sha256:{}", digest(&json!({ "joined": profile, "as": "person" }))) },
                format_version: 2,
                protocol_version: dto::CONTRACT_VERSION,
                lock_digest: None,
                answers: BTreeMap::new(),
                secret_bindings: BTreeMap::from([("invitation".to_owned(), "apply.invitation".to_owned())]),
                lock: None,
                capabilities: vec!["grid.join".into(), "people.invites".into()],
            };
            let membership = DeclaredResource {
                id: "membership".into(),
                kind: Kind::Grid,
                spec: json!({ "profile": profile, "mode": "join", "member": "person", "sign_in": "password", "username": scoped.username, "secrets": { "invitation": "apply.invitation", "password": "apply.invitation" } }),
                requires: Vec::new(),
                owner: None,
            };
            return Ok(PlanIntent::Create(SetupDraft { change, resources: vec![membership] }));
        }
        let (profile, product, decoded) = if text.starts_with(invite::DESK_PREFIX) {
            ("sandbox_grid", "Sandbox Grid", invite::decode_desk(text))
        } else if text.starts_with(invite::ACCESS_PREFIX) {
            return Err(Diagnostic::new("unsupported_here", "An Access Grid invitation is for a person to sign in, with their username and password: sign in from the Access Grid in My setups. Nothing was changed."));
        } else if text.starts_with(invite::BOUNTY_PREFIX) {
            return Err(Diagnostic::new("unsupported_here", "Swarm Mining is left as it is; it is joined and managed on its own, not from here. Nothing was changed."));
        } else if text.starts_with("grid-invite:") {
            ("neo_grid", "Neo Grid", invite::decode(text))
        } else {
            return Err(invalid("That isn't a grid invitation. Copy the whole code the grid's admin gave you."));
        };
        let company = decoded.map_err(|problem| invalid(&problem).at("invitation"))?.company;
        let name = format!("{company} {product}").chars().take(64).collect::<String>();
        let change = InstanceChange {
            name: if name.trim().is_empty() { product.to_owned() } else { name },
            source: super::model::Source { reference: dto::SourceRef::InstalledSetup { setup_id: "joined".into() }, digest: format!("sha256:{}", digest(&json!({ "joined": profile }))) },
            format_version: 2,
            protocol_version: dto::CONTRACT_VERSION,
            lock_digest: None,
            answers: BTreeMap::new(),
            secret_bindings: BTreeMap::from([("invitation".to_owned(), "apply.invitation".to_owned()), ("join_password".to_owned(), "apply.join_password".to_owned())]),
            lock: None,
            capabilities: vec!["grid.join".into()],
        };
        let membership = DeclaredResource {
            id: "membership".into(),
            kind: Kind::Grid,
            spec: json!({ "profile": profile, "mode": "join", "member": "computer", "secrets": { "invitation": "apply.invitation", "join_password": "apply.join_password" } }),
            requires: Vec::new(),
            owner: None,
        };
        Ok(PlanIntent::Create(SetupDraft { change, resources: vec![membership] }))
    }

    /// Secret values are dropped as soon as their operation has finished.
    fn forget_finished_secrets(&self) {
        let Ok(registry) = self.current() else { return };
        lock(&self.secrets).retain(|operation, _| registry.operations.get(operation).is_some_and(|found| !found.state.is_terminal()));
    }

    /// Adds secret values to an operation's, keeping any given earlier.
    fn remember_secrets(&self, operation: &str, secrets: BTreeMap<String, String>) {
        if secrets.is_empty() {
            return;
        }
        let mut held = lock(&self.secrets);
        let mut merged = held.get(operation).map(|existing| (**existing).clone()).unwrap_or_default();
        merged.extend(secrets);
        held.insert(operation.to_owned(), Arc::new(merged));
    }

    // ----- Reading -----

    /// Every setup on this computer: the engine's own, then those adopted read-only from the
    /// products that predate setups.
    pub(crate) fn list(&self) -> Result<Vec<dto::SetupSummary>, Diagnostic> {
        let mut setups = self.read(|registry| {
            Ok(registry
                .instances
                .values()
                .filter(|instance| instance.lifecycle != Lifecycle::Removed)
                .map(views::summary)
                .collect::<Vec<_>>())
        })?;
        // The list says what `get` says: a setup whose synced folder stopped or held files back
        // is not simply ready.
        for summary in &mut setups {
            if summary.health == Some(dto::CapabilityHealth::Ready) && !self.sync_notes(&summary.setup_id).is_empty() {
                summary.health = Some(dto::CapabilityHealth::Degraded);
            }
        }
        let owned = self.read(|registry| Ok(owned_grids(registry)))?;
        let workers_held = self.read(|registry| Ok(self.swarm_workers_held(registry)))?;
        setups.extend(
            self.adopted()
                .iter()
                .filter(|record| !owned.contains(&(record.profile.id().to_owned(), record.role, record.instance.clone().unwrap_or_else(|| super::grids::FIRST.to_owned()))))
                .filter(|record| !(record.role == "workers" && workers_held))
                .map(adopt::Adopted::summary),
        );
        Ok(setups)
    }

    /// Whether every worker in Swarm Mining's own record of its workers is one a setup made, so
    /// that record is those setups' and not something to list beside them. A worker the person
    /// started in Swarm Mining itself keeps the record listed.
    fn swarm_workers_held(&self, registry: &Registry) -> bool {
        let held: BTreeSet<&str> = registry
            .instances
            .values()
            .filter(|instance| instance.lifecycle != Lifecycle::Removed)
            .flat_map(|instance| instance.resources.values())
            .filter(|resource| resource.kind == Kind::WorkerGroup)
            .filter_map(|resource| resource.runtime_id.as_deref())
            .collect();
        if held.is_empty() {
            return false;
        }
        let Some(record) = std::fs::read(self.data_root.join("swarm").join("workers.json")).ok().and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok()) else { return false };
        match record.as_object() {
            Some(workers) => workers.keys().all(|id| held.contains(id.as_str())),
            None => false,
        }
    }

    /// Read the detail and its product document from one registry snapshot. Reading the
    /// evidence clock first never pairs an old detail with a newer permission document.
    pub(crate) fn get_with_product(&self, setup: &str, now: Result<ClockReading, String>) -> Result<views::Detail, Diagnostic> {
        self.get_snapshot(setup, Some(now))
    }

    pub(crate) fn get(&self, setup: &str) -> Result<views::Detail, Diagnostic> {
        self.get_snapshot(setup, None)
    }

    fn get_snapshot(&self, setup: &str, now: Option<Result<ClockReading, String>>) -> Result<views::Detail, Diagnostic> {
        if adopt::is_adopted_id(setup) {
            return self
                .adopted()
                .into_iter()
                .find(|record| record.id == setup)
                .map(|record| record.detail())
                .ok_or_else(|| not_found(setup));
        }
        self.read(|registry| {
            if registry.tombstones.contains_key(setup) {
                return Err(removed(setup));
            }
            let instance = registry.instances.get(setup).ok_or_else(|| not_found(setup))?;
            let parts = instance.resources.values().map(|part| (part.id.clone(), part_actions(&self.handlers, instance, part))).collect::<Vec<_>>();
            // A part made by a product this version no longer carries is said plainly, with
            // the honest ways out, rather than failing every action on the setup silently.
            let mut left_alone = instance.resources.values().filter_map(|part| unmanaged(&self.handlers, part)).collect::<Vec<_>>();
            if !left_alone.is_empty() {
                left_alone.push(UNMANAGED_WAYS_OUT.to_owned());
            }
            let mut detail = views::detail(registry, instance);
            if let Some(now) = now {
                match now.and_then(|now| super::product::of_instance(instance, now)) {
                    Ok(product) => detail.product = Some(product),
                    Err(reason) => detail.product_unavailable = Some(reason),
                }
            }
            Ok((detail, parts, left_alone))
        })
        .map(|(mut detail, parts, left_alone)| {
            // What each part allows on its own, by the same rule its review applies.
            for (id, allowed) in parts {
                if let Some(extra) = detail.resource_details.get_mut(&id) {
                    extra["actions"] = json!(allowed.iter().map(|action| action.as_str()).collect::<Vec<_>>());
                }
            }
            detail.notes.extend(left_alone);
            detail.customization = self.customization(setup).ok();
            // The standard views its template asks for, from the package kept beside it.
            detail.setup.views = self.package_files(setup).and_then(|files| yougori_setup::format::template(&files).ok()).map(|checked| checked.views).unwrap_or_default();
            // Each output under its template's own label.
            let labels = self.output_labels(setup);
            for output in &mut detail.setup.outputs {
                if let Some(label) = labels.get(&output.key) {
                    output.label.clone_from(label);
                }
            }
            let said = self.sync_notes(setup);
            sync_readiness(&mut detail, &said);
            detail.notes.extend(said);
            // What each part said at its last check, beside it, so the page can say why.
            for (id, report) in self.health_reports(setup) {
                if let Some(extra) = detail.resource_details.get_mut(&id) {
                    extra["health"] = json!(views::health(report.health));
                    extra["healthDetail"] = json!(report.detail);
                    extra["healthCheckedAt"] = json!(views::seconds(&report.at));
                }
            }
            detail
        })
    }

    /// What this setup's synced folders have to say: one line per folder that stopped or held
    /// files back at its last pass. A sync that FAILS is reported through the operation, and a
    /// pass that stopped fails its step, but a pass that succeeded while holding a conflicted or
    /// unstorable file back is not a failure and would otherwise say nothing at all. The lines
    /// come from each folder's own record, which is a side file: nothing here reads or writes
    /// `registry.json`, and a record that is missing or unreadable simply says nothing.
    fn sync_notes(&self, setup: &str) -> Vec<String> {
        let folder = self.projects.join(setup);
        let resources = self
            .read(|registry| {
                Ok(registry
                    .instances
                    .get(setup)
                    .map(|instance| {
                        instance
                            .resources
                            .values()
                            .filter(|resource| resource.kind == Kind::Environment && !resource.borrowed())
                            .map(|resource| (resource.id.clone(), resource.spec.clone()))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default())
            })
            .unwrap_or_default();
        resources.iter().flat_map(|(id, spec)| folder_sync::notes(&folder, id, spec)).collect()
    }

    /// What the person chose for a setup: its public answers, the on/off state of each optional
    /// or default capability of its template (read from the kept package copy), and what they
    /// added beyond the template. An update merges these with the new version.
    fn customization(&self, setup: &str) -> Result<Value, Diagnostic> {
        let (answers, chosen, added) = self.read(|registry| {
            let instance = registry.instances.get(setup).ok_or_else(|| not_found(setup))?;
            Ok((instance.answers.clone(), instance.capabilities.clone(), instance.customizations.keys().cloned().collect::<Vec<_>>()))
        })?;
        let declared = self
            .package_files(setup)
            .and_then(|files| yougori_setup::format::template(&files).ok())
            .map(|checked| {
                checked
                    .capabilities
                    .iter()
                    .filter(|capability| capability.selection != yougori_setup::format::Selection::Required)
                    .map(|capability| (capability.id.clone(), json!(chosen.contains(&capability.id))))
                    .collect::<serde_json::Map<_, _>>()
            })
            .unwrap_or_else(|| chosen.iter().map(|id| (id.clone(), json!(true))).collect());
        let answers = answers.into_iter().map(|(id, value)| (id, json!(value.as_str().map(str::to_owned).unwrap_or_else(|| value.to_string())))).collect::<serde_json::Map<_, _>>();
        Ok(json!({ "answers": answers, "capabilities": declared, "added": added }))
    }

    /// The source a setup was made from, with its package digest, to plan a change to it from
    /// the same package.
    pub(crate) fn source_record(&self, setup: &str) -> Result<super::model::Source, Diagnostic> {
        if adopt::is_adopted_id(setup) {
            return Err(legacy_managed(setup));
        }
        self.read(|registry| {
            if registry.tombstones.contains_key(setup) {
                return Err(removed(setup));
            }
            Ok(registry.instances.get(setup).ok_or_else(|| not_found(setup))?.source.clone())
        })
    }

    /// What a setup was last planned with: its public answers, chosen capabilities and secret
    /// binding names, to plan a change to it without asking everything again.
    pub(crate) fn chosen(&self, setup: &str) -> Result<(BTreeMap<String, Value>, Vec<String>, BTreeMap<String, String>), Diagnostic> {
        self.read(|registry| {
            let instance = registry.instances.get(setup).ok_or_else(|| not_found(setup))?;
            Ok((instance.answers.clone(), instance.capabilities.clone(), instance.secret_bindings.clone()))
        })
    }

    /// The lock a setup was last applied from, when it has one.
    pub(crate) fn lock(&self, setup: &str) -> Result<Option<yougori_setup::lock::Lock>, Diagnostic> {
        self.read(|registry| {
            let instance = registry.instances.get(setup).ok_or_else(|| not_found(setup))?;
            Ok(instance.lock.clone().and_then(|lock| serde_json::from_value(lock).ok()))
        })
    }

    fn package_folder(&self, setup: &str) -> PathBuf {
        self.projects.join(setup).join("package")
    }

    /// The copy of the package a setup was made from, kept beside it.
    pub(crate) fn package_files(&self, setup: &str) -> Option<yougori_setup::format::Files> {
        valid_id(setup, "setup-").then(|| super::package::read(&self.package_folder(setup))).flatten()
    }

    /// The setup's current operation, or else its most recent one.
    pub(crate) fn latest_operation(&self, setup: &str) -> Result<String, Diagnostic> {
        if adopt::is_adopted_id(setup) {
            return Err(legacy_managed(setup));
        }
        self.read(|registry| {
            if registry.tombstones.contains_key(setup) {
                return Err(removed(setup));
            }
            let instance = registry.instances.get(setup).ok_or_else(|| not_found(setup))?;
            if let Some(current) = &instance.current_operation {
                return Ok(current.clone());
            }
            registry
                .operations
                .values()
                .filter(|operation| operation.setup == setup)
                .max_by(|a, b| a.created_at.cmp(&b.created_at))
                .map(|operation| operation.id.clone())
                .ok_or_else(|| Diagnostic::new("no_operation", "Nothing has been done to this setup yet.").resource(setup))
        })
    }

    /// The operation's progress from `cursor` on.
    pub(crate) fn operation(&self, operation: &str, cursor: u64) -> Result<dto::OperationProgress, Diagnostic> {
        self.read(|registry| {
            let found = registry.operations.get(operation).ok_or_else(|| operation_missing(operation))?;
            views::progress(found, cursor)
        })
    }

    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> Registry {
        self.read(|registry| Ok(registry.clone())).expect("registry is available")
    }

    #[cfg(test)]
    pub(crate) fn store(&self) -> &Store {
        &self.store
    }

    #[cfg(test)]
    pub(crate) fn holds_secrets(&self, operation: &str) -> bool {
        lock(&self.secrets).contains_key(operation)
    }

    // ----- Planning -----

    /// Reviews a change without touching anything, and keeps the plan for `submit`.
    pub(crate) fn plan(&self, intent: PlanIntent) -> Result<ReviewedPlan, Diagnostic> {
        self.plan_from(intent, None, None)
    }

    /// Reviews a change built from a template plan whose own digest is `source_digest`, from the
    /// files of `package`.
    pub(crate) fn plan_from(
        &self,
        intent: PlanIntent,
        source_digest: Option<String>,
        package: Option<Arc<yougori_setup::format::Files>>,
    ) -> Result<ReviewedPlan, Diagnostic> {
        let adopted = self.adopted();
        // Removing one part offers the same deletions as removing the whole setup would for it.
        let removing = matches!(intent, PlanIntent::Remove { .. } | PlanIntent::Part { action: Action::Remove, .. });
        let mut plan = self.read(|registry| review(registry, &self.handlers, &adopted, intent))?;
        if removing {
            self.removal_data(&mut plan);
        }
        plan.source_digest = source_digest;
        plan.package = package;
        plan.plan_id = new_id("plan-");
        plan.expires_at = (chrono::Utc::now() + chrono::Duration::from_std(PLAN_LIFETIME).unwrap_or_default()).to_rfc3339();
        plan.digest = plan_digest(&plan);
        let mut plans = lock(&self.plans);
        plans.retain(|_, (_, made)| made.elapsed() < PLAN_LIFETIME);
        while plans.len() >= PLAN_LIMIT {
            let oldest = plans.iter().min_by_key(|(_, (_, made))| *made).map(|(id, _)| id.clone());
            match oldest {
                Some(id) => plans.remove(&id),
                None => break,
            };
        }
        plans.insert(plan.plan_id.clone(), (plan.clone(), Instant::now()));
        Ok(plan)
    }

    /// What removing a setup does with its volumes' data, said exactly on the review.
    ///
    /// Every volume is kept, and so are its backups, unless its template says
    /// `retention.onRemove: ask` (the volume's own retention, or else the template's). For those,
    /// the review offers a choice, never ticked for the person, to delete the volume and all its
    /// backups, naming them and saying it cannot be undone. `Keep` has no "delete" value, so no
    /// template can make deletion happen by itself: it is always the person's tick, and
    /// `submit_agreed` refuses one this review did not offer.
    fn removal_data(&self, plan: &mut ReviewedPlan) {
        // What each part's own handler offers beyond keeping it, such as deleting a grid it made
        // at once instead of pausing it. Offered, never ticked.
        let offers = plan
            .steps
            .iter()
            .filter(|step| step.action == Action::Remove && step.owner.is_none())
            .flat_map(|step| self.handlers.get(step.kind).map(|handler| handler.removal_offers(&plan.setup_id, &step.resource, &step.spec)).unwrap_or_default())
            .collect::<Vec<_>>();
        plan.offered.extend(offers);
        let volumes = plan
            .steps
            .iter()
            .filter(|step| step.kind == Kind::Volume && step.action == Action::Remove && step.owner.is_none())
            .map(|step| (step.resource.clone(), step.spec["retention"]["on_remove"].as_str().map(str::to_owned)))
            .collect::<Vec<_>>();
        let checked = self.package_files(&plan.setup_id).and_then(|files| yougori_setup::format::template(&files).ok());
        // The volume's own retention, written in its settings, says it first; then what its
        // template says for that resource; then the template's default, as the planner reads it.
        let asks = |volume: &str, own: Option<&str>| match own {
            Some(said) => said == "ask",
            None => checked.as_ref().is_some_and(|checked| {
                let retention = checked.resources.get(volume).and_then(|resource| resource.retention).unwrap_or(checked.retention);
                retention.on_remove == yougori_setup::format::Keep::Ask
            }),
        };
        let schedules = self.schedules_of(&plan.setup_id).unwrap_or_default();
        for (volume, own) in volumes {
            let count = schedules.iter().find(|schedule| schedule.resource == volume).map_or(0, |schedule| schedule.backups.len());
            let kept = match count {
                0 => format!("The data of {volume} is kept."),
                1 => format!("The data of {volume} is kept, and so is its backup in Yougori's data folder on this computer."),
                _ => format!("The data of {volume} is kept, and so are its {count} backups in Yougori's data folder on this computer."),
            };
            let said = if asks(&volume, own.as_deref()) {
                // Everything on it and every backup at the time it is deleted, a copy taken
                // after this review included: so "all of its backups", with today's count.
                let backups = match count {
                    0 => String::new(),
                    1 => ", and all of its backups (1 now) in Yougori's data folder on this computer".to_owned(),
                    _ => format!(", and all of its backups ({count} now) in Yougori's data folder on this computer"),
                };
                plan.offered.push(json!({
                    "id": super::ordinary::delete_consent(&volume),
                    "message": format!("Also delete {volume}: everything on it{backups}. This can't be undone."),
                }));
                format!("{}, unless you tick its deletion below.", kept.trim_end_matches('.'))
            } else {
                kept
            };
            match plan.notes.iter().position(|note| *note == kept_note(&volume)) {
                Some(at) => plan.notes[at] = said,
                None => plan.notes.push(said),
            }
        }
        if !plan.offered.is_empty() {
            if let Some(at) = plan.notes.iter().position(|note| note == DATA_KEPT) {
                plan.notes[at] = "Data is kept by default. Only what you tick below is deleted, and that can't be undone.".into();
            }
        }
    }

    /// The plan reviewed earlier in this engine's life for `setup` with this digest.
    pub(crate) fn reviewed(&self, setup: &str, digest: &str) -> Result<ReviewedPlan, Diagnostic> {
        let plans = lock(&self.plans);
        plans
            .values()
            .find(|(plan, made)| {
                plan.setup_id == setup
                    && (plan.digest == digest || plan.source_digest.as_deref() == Some(digest))
                    && made.elapsed() < PLAN_LIFETIME
            })
            .map(|(plan, _)| plan.clone())
            .ok_or_else(|| {
                Diagnostic::new(
                    "plan_expired",
                    "Yougori no longer has the plan you approved, or it has changed. Review the change again, then apply it.",
                )
                .resource(setup)
                .next(&["plan"])
            })
    }

    // ----- Applying -----

    /// Saves the operation and claims the setup. Nothing outside the registry changes here.
    /// `operation` is chosen by the caller, so sending the same request again joins it.
    pub(crate) fn submit(
        &self,
        plan: &ReviewedPlan,
        operation: &str,
        expected_revision: u64,
        secrets: BTreeMap<String, String>,
    ) -> Result<Submitted, Diagnostic> {
        self.submit_agreed(plan, operation, expected_revision, secrets, BTreeSet::new())
    }

    /// `submit`, with what the person agreed to on the review (`consents`), kept with the
    /// operation so a retry honours the same answer and nothing more.
    pub(crate) fn submit_agreed(
        &self,
        plan: &ReviewedPlan,
        operation: &str,
        expected_revision: u64,
        secrets: BTreeMap<String, String>,
        consents: BTreeSet<String>,
    ) -> Result<Submitted, Diagnostic> {
        if !valid_operation_id(operation) {
            return Err(invalid("The operation ID must be 1 to 128 letters, digits or . : _ -"));
        }
        if plan.digest != plan_digest(plan) {
            return Err(Diagnostic::new("plan_changed", "This plan was altered after review. Review the change again.").next(&["plan"]));
        }
        if adopt::is_adopted_id(&plan.setup_id) {
            return Err(legacy_managed(&plan.setup_id));
        }
        if expected_revision != plan.base_revision {
            return Err(Diagnostic::new(
                "revision_conflict",
                "The plan was reviewed for a different version of this setup. Review the change again.",
            )
            .resource(&plan.setup_id)
            .next(&["plan"]));
        }
        // A deletion counts only if the review being applied offered it: a plan asks, it never
        // grants, and nothing is deleted that the person was not shown on this exact review.
        let offered = plan.offered.iter().filter_map(|offer| offer["id"].as_str()).collect::<BTreeSet<_>>();
        let consents = consents
            .into_iter()
            .filter(|id| !id.starts_with(DELETION) || offered.contains(id.as_str()))
            .collect::<BTreeSet<_>>();
        let handlers = &self.handlers;
        let adopted = self.adopted();
        let submitted = self.commit(|registry| claim(registry, handlers, &adopted, plan, operation, &consents))?;
        if !submitted.joined {
            if let Some(files) = &plan.package {
                // Before any step runs: a sandbox's files are copied in from here.
                if let Err(problem) = blocking(|| super::package::write(&self.package_folder(&plan.setup_id), files)) {
                    let error = Diagnostic::new("package_unwritable", problem).retryable().operation(operation);
                    let _ = self.commit(|registry| {
                        finish(registry, operation, OperationState::Failed, Some(error.clone().next(&["retry"])));
                        Ok(())
                    });
                    return Err(error);
                }
            }
            self.remember_secrets(&submitted.operation_id, secrets);
        } else if !secrets.is_empty() {
            self.resume_waiting(&submitted.operation_id, secrets)?;
        }
        Ok(submitted)
    }

    /// Joins an existing operation by its ID and digest, without needing the reviewed plan in
    /// memory (it may have expired or the engine restarted). Given secrets, an operation waiting
    /// for them continues. `None` when no such operation exists.
    pub(crate) fn continue_operation(
        &self,
        setup: &str,
        operation: &str,
        digest: &str,
        secrets: BTreeMap<String, String>,
    ) -> Result<Option<Submitted>, Diagnostic> {
        let found = self.read(|registry| {
            Ok(registry.operations.get(operation).map(|found| {
                (found.setup == setup && (found.plan_digest == digest || found.source_digest.as_deref() == Some(digest)), found.state)
            }))
        })?;
        match found {
            None => Ok(None),
            Some((false, _)) => Err(Diagnostic::new(
                "operation_id_reused",
                "This operation ID was already used for a different change. Send the new change with a new ID.",
            )
            .operation(operation)),
            Some((true, state)) => {
                if state == OperationState::AwaitingInput && !secrets.is_empty() {
                    self.resume_waiting(operation, secrets)?;
                }
                Ok(Some(Submitted { operation_id: operation.to_owned(), setup_id: setup.to_owned(), joined: true }))
            }
        }
    }

    /// Gives a waiting operation the answers it asked for, so its runner continues.
    fn resume_waiting(&self, operation: &str, secrets: BTreeMap<String, String>) -> Result<(), Diagnostic> {
        let waiting = self.commit(|registry| {
            let found = operation_mut(registry, operation)?;
            if found.state != OperationState::AwaitingInput {
                return Ok(false);
            }
            found.set_state(OperationState::Planned);
            found.error = None;
            found.event(None, "Received the missing answers. Continuing.");
            Ok(true)
        })?;
        if waiting {
            self.remember_secrets(operation, secrets);
        }
        Ok(())
    }

    /// The operation with this ID, when it exists: its setup and kind.
    pub(crate) fn operation_kind(&self, operation: &str) -> Option<(String, OperationKind)> {
        self.read(|registry| Ok(registry.operations.get(operation).map(|found| (found.setup.clone(), found.kind))))
            .ok()
            .flatten()
    }

    /// Runs the operation's remaining steps in this task. Returns when it is finished, waiting,
    /// unknown or cancelled. A second runner for the same operation returns at once.
    pub(crate) async fn run(&self, operation: &str) -> Result<(), Diagnostic> {
        let cancel = CancellationToken::new();
        {
            let mut running = lock(&self.running);
            if running.contains_key(operation) {
                return Ok(());
            }
            running.insert(operation.to_owned(), cancel.clone());
        }
        let _guard = RunGuard { running: &self.running, operation: operation.to_owned() };
        // A continue of an operation whose outcome is unknown looks first: what a cut-off step
        // left behind is found and recorded, and only then do the steps that didn't happen run.
        let result = match self.settle_before_continuing(operation).await {
            Err(error) => Err(error),
            Ok(()) => {
                let secrets = lock(&self.secrets).get(operation).cloned().unwrap_or_default();
                let result = self.run_steps(operation, &cancel, secrets).await;
                // A cancel that cut a step short is settled now, while the engine is here to
                // look: what that step left behind is recorded and the change ends as cancelled,
                // rather than as "outcome unknown" until someone asks what happened.
                let cut_by_cancel = self
                    .read(|registry| Ok(registry.operations.get(operation).is_some_and(|found| found.state == OperationState::Unknown && found.cancel_requested)))
                    .unwrap_or(false);
                if cut_by_cancel {
                    let _ = self.reconcile_steps(operation).await;
                }
                result
            }
        };
        self.forget_finished_secrets();
        // Its jobs' event addresses follow what it now is, before its outputs are read again so
        // a new address shows at once.
        if let (Some((setup, _)), Some(events)) = (self.operation_kind(operation), self.events.get()) {
            events.sync(&setup).await;
        }
        // What the setup shows of itself follows what it now is.
        if let Some((setup, _)) = self.operation_kind(operation) {
            self.refresh_outputs(&setup).await;
        }
        let removed = self.read(|registry| {
            Ok(registry.operations.get(operation).filter(|found| found.kind == OperationKind::Remove && found.state == OperationState::Completed).map(|found| found.setup.clone()))
        });
        if let Ok(Some(setup)) = removed {
            for handler in self.handlers.all() {
                handler.forget_setup(&setup).await;
            }
        }
        // The setup's backup times follow what it now is: a new or changed one gets them, a
        // stopped one pauses them, a removed one loses them. Its kept backups stay.
        if let Some((setup, _)) = self.operation_kind(operation) {
            if let Err(error) = self.sync_schedules(&setup) {
                eprintln!("Backup times could not be brought up to date: {}", error.message);
            }
        }
        result
    }

    async fn run_steps(
        &self,
        operation: &str,
        cancel: &CancellationToken,
        secrets: Arc<BTreeMap<String, String>>,
    ) -> Result<(), Diagnostic> {
        let started = self.commit(|registry| {
            let found = operation_mut(registry, operation)?;
            if found.state == OperationState::Planned {
                found.set_state(OperationState::Applying);
                found.event(None, "Started.");
            }
            Ok(())
        });
        if let Err(error) = started {
            return Err(self.stopped_unsaved(operation, error));
        }
        loop {
            let next = match self.commit(|registry| next_step(registry, operation, cancel, &secrets)) {
                Ok(next) => next,
                Err(error) => return Err(self.stopped_unsaved(operation, error)),
            };
            let Some(context) = next else { return Ok(()) };
            let result = if matches!(context.action, Action::Attach | Action::Detach) {
                // Binding to another setup's resource changes only these records; nothing is
                // created or touched, so no handler is called.
                self.read(|registry| Ok(binding_receipt(registry, &context))).unwrap_or_else(|error| {
                    Err(HandlerError::new(Outcome::NotStarted, &error.code, error.message))
                })
            } else if let Err(refusal) = (context.action == Action::Remove)
                .then(|| self.read(|registry| Ok(still_unborrowed(registry, &context))).unwrap_or(Ok(())))
                .unwrap_or(Ok(()))
            {
                Err(refusal)
            } else {
                match self.handlers.get(context.kind) {
                    Ok(handler) => call(handler.as_ref(), &context).await,
                    Err(diagnostic) => Err(HandlerError::new(Outcome::Unsupported, &diagnostic.code, diagnostic.message)),
                }
            };
            // A volume the person ticked for deletion on its removal: its backups go in the same
            // step, right after it, so the step is done only once everything the review named
            // is gone.
            let result = match result {
                Ok(receipt)
                    if context.kind == Kind::Volume
                        && context.action == Action::Remove
                        && context.consents.contains(&super::ordinary::delete_consent(&context.resource)) =>
                {
                    self.forget_backups(&context).await.map(|()| receipt)
                }
                other => other,
            };
            if let Err(error) = self.commit(|registry| record(registry, operation, &context, result.clone())) {
                // The effect may have happened, but its receipt is not on disk. Disk keeps the
                // saved intent, so the next start reconciles it; here it shows as unknown now.
                let _ = self.ephemeral(|registry| {
                    let found = operation_mut(registry, operation)?;
                    if let Some(step) = found.step_mut(&context.step) {
                        step.state = StepState::Unknown;
                    }
                    found.set_state(OperationState::Unknown);
                    found.error = Some(error.clone().operation(operation).next(&["reconcile"]));
                    Ok(())
                });
                return Err(error);
            }
        }
    }

    /// Settles an operation whose outcome is unknown before its runner continues it: each
    /// unknown step is looked at (`reconcile_steps`), what happened is recorded, and the
    /// operation is claimed again for the steps that remain. One that still can't be told
    /// apart from what the provider says stays unknown, and says so; nothing runs after it.
    async fn settle_before_continuing(&self, operation: &str) -> Result<(), Diagnostic> {
        let state = |registry: &Registry| Ok(registry.operations.get(operation).map(|found| found.state));
        if self.read(state)? != Some(OperationState::Unknown) {
            return Ok(());
        }
        self.reconcile_steps(operation).await?;
        match self.read(state)? {
            Some(OperationState::Failed | OperationState::Cancelled) => self.prepare_retry(operation),
            Some(OperationState::Unknown) => Err(self
                .read(|registry| Ok(registry.operations.get(operation).and_then(|found| found.error.clone())))?
                .unwrap_or_else(|| {
                    Diagnostic::new("outcome_unknown", "A step of this operation may already have taken effect, and Yougori still can't tell. Nothing more runs until it can.")
                        .retryable()
                        .operation(operation)
                        .next(&["reconcile"])
                })),
            _ => Ok(()),
        }
    }

    /// A save failed before the next effect, so nothing more is done. Disk still shows the
    /// operation as running, which the next start turns into the same failed, retryable state.
    fn stopped_unsaved(&self, operation: &str, error: Diagnostic) -> Diagnostic {
        if error.code == "durable_storage_unavailable" {
            let _ = self.ephemeral(|registry| {
                if registry.operations.get(operation).is_some_and(|found| !found.state.is_terminal() && !found.has_unknown()) {
                    finish(registry, operation, OperationState::Failed, Some(error.clone().operation(operation).next(&["retry"])));
                }
                Ok(())
            });
        }
        error
    }

    /// Submits and runs in one call.
    #[cfg(test)]
    pub(crate) async fn apply(
        &self,
        plan: &ReviewedPlan,
        operation: &str,
        secrets: BTreeMap<String, String>,
    ) -> Result<Submitted, Diagnostic> {
        let submitted = self.submit(plan, operation, plan.base_revision, secrets)?;
        self.run(&submitted.operation_id).await?;
        Ok(submitted)
    }

    /// Asks a running operation to stop after its current step. A call already in flight is
    /// cancelled; if it may have taken effect, the step is left unknown, not called failed.
    pub(crate) fn cancel(&self, operation: &str) -> Result<dto::OperationProgress, Diagnostic> {
        let view = self.commit(|registry| {
            let found = operation_mut(registry, operation)?;
            match found.state {
                state if state.is_terminal() => {}
                OperationState::Planned | OperationState::AwaitingInput => {
                    finish(registry, operation, OperationState::Cancelled, None);
                }
                OperationState::Applying => {
                    found.cancel_requested = true;
                    found.set_state(OperationState::Cancelling);
                    found.event(None, "Cancelling after the current step.");
                }
                OperationState::Cancelling => {}
                OperationState::Unknown => {
                    return Err(Diagnostic::new(
                        "outcome_unknown",
                        "A step of this operation may already have taken effect. Check it first; then it can be cancelled or retried.",
                    )
                    .operation(operation)
                    .next(&["reconcile"]));
                }
                _ => {}
            }
            let found = &registry.operations[operation];
            views::progress(found, found.next_seq)
        })?;
        if let Some(token) = lock(&self.running).get(operation) {
            token.cancel();
        }
        self.forget_finished_secrets();
        Ok(view)
    }

    /// Settles every operation whose outcome is unknown. Run once after the engine starts.
    /// After startup recovery: what each idle setup really has now. The record is from before
    /// Yougori closed, and closing stops the sandboxes, so without looking a setup would go on
    /// reading running with nothing running. Looking changes nothing; a busy setup is left to
    /// its operation.
    pub(crate) async fn refresh_all(&self) {
        let idle = self
            .read(|registry| {
                Ok(registry
                    .instances
                    .iter()
                    .filter(|(id, instance)| !adopt::is_adopted_id(id) && instance.current_operation.is_none() && matches!(instance.lifecycle, Lifecycle::Running | Lifecycle::Stopped))
                    .map(|(id, _)| id.clone())
                    .collect::<Vec<_>>())
            })
            .unwrap_or_default();
        for setup in idle {
            let _ = self.refresh(&setup).await;
        }
    }

    pub(crate) async fn reconcile_all(&self) {
        let unknown = self
            .read(|registry| {
                Ok(registry
                    .operations
                    .values()
                    .filter(|operation| operation.state == OperationState::Unknown)
                    .map(|operation| operation.id.clone())
                    .collect::<Vec<_>>())
            })
            .unwrap_or_default();
        for operation in unknown {
            if let Err(error) = self.reconcile(&operation).await {
                eprintln!("Setup reconciliation deferred: {}", error.message);
            }
        }
    }

    /// Looks at each step whose outcome is unknown and records what actually happened.
    pub(crate) async fn reconcile(&self, operation: &str) -> Result<dto::OperationProgress, Diagnostic> {
        {
            let mut running = lock(&self.running);
            if running.contains_key(operation) {
                return Err(Diagnostic::new("operation_running", "This operation is still running. Its outcome will be known when the current step finishes.")
                    .operation(operation)
                    .retryable());
            }
            running.insert(operation.to_owned(), CancellationToken::new());
        }
        let _guard = RunGuard { running: &self.running, operation: operation.to_owned() };
        let result = self.reconcile_steps(operation).await;
        self.forget_finished_secrets();
        result
    }

    async fn reconcile_steps(&self, operation: &str) -> Result<dto::OperationProgress, Diagnostic> {
        let contexts = self.read(|registry| {
            let found = registry.operations.get(operation).ok_or_else(|| operation_missing(operation))?;
            Ok(found
                .steps
                .iter()
                .filter(|step| matches!(step.state, StepState::Unknown | StepState::Applying))
                .map(|step| (step.attempts, context(registry, found, step, CancellationToken::new(), Default::default())))
                .collect::<Vec<_>>())
        })?;
        for (attempts, context) in contexts {
            let recovery = if matches!(context.action, Action::Attach | Action::Detach) {
                // These steps change only records, saved with their receipt in one commit: an
                // interrupted one simply did not happen.
                Recovery::NotApplied
            } else {
                match self.handlers.get(context.kind) {
                    Ok(handler) => handler
                        .recover(&context)
                        .await
                        .unwrap_or_else(|error| Recovery::Unknown { reason: error.message }),
                    Err(diagnostic) => Recovery::Unknown { reason: diagnostic.message },
                }
            };
            self.commit(|registry| {
                let found = operation_mut(registry, operation)?;
                if found.state != OperationState::Unknown {
                    return Ok(());
                }
                let step = found.step_mut(&context.step).ok_or_else(|| operation_missing(operation))?;
                if !matches!(step.state, StepState::Unknown | StepState::Applying) || step.attempts != attempts {
                    // Someone else settled this step while we looked; their record stands.
                    return Ok(());
                }
                match recovery {
                    Recovery::Applied(receipt) => {
                        let step = step.clone();
                        apply_receipt(registry, operation, &step, receipt.clone());
                        let found = operation_mut(registry, operation)?;
                        let step = found.step_mut(&context.step).expect("step exists");
                        step.state = StepState::Done;
                        step.receipt = Some(receipt);
                        step.finished_at = Some(now());
                        found.event(Some(&context.step), format!("Found that {} {} had finished. Recorded it without doing it again.", action_words(context.action), context.resource));
                    }
                    Recovery::NotApplied => {
                        step.state = StepState::Pending;
                        found.event(Some(&context.step), format!("Found that {} {} had not happened. It can run again safely.", action_words(context.action), context.resource));
                    }
                    Recovery::Unknown { reason } => {
                        step.state = StepState::Unknown;
                        found.event(Some(&context.step), format!("Still can't tell whether {} {} happened: {reason}", action_words(context.action), context.resource));
                    }
                }
                Ok(())
            })?;
        }
        self.commit(|registry| {
            let found = operation_mut(registry, operation)?;
            if found.state != OperationState::Unknown || found.has_unknown() {
                return Ok(());
            }
            if found.cancel_requested {
                finish(registry, operation, OperationState::Cancelled, None);
            } else if found.all_done() {
                finish(registry, operation, OperationState::Completed, None);
            } else {
                finish(
                    registry,
                    operation,
                    OperationState::Failed,
                    Some(
                        Diagnostic::new("engine_interrupted", "This change was interrupted. Retry continues only the steps that didn't finish.")
                            .retryable()
                            .operation(operation)
                            .next(&["retry"]),
                    ),
                );
            }
            Ok(())
        })?;
        self.read(|registry| {
            let found = registry.operations.get(operation).ok_or_else(|| operation_missing(operation))?;
            views::progress(found, found.next_seq)
        })
    }

    /// Runs a failed or cancelled operation again from the steps that did not finish. Steps that
    /// are done stay done; nothing they created is made twice.
    pub(crate) fn prepare_retry(&self, operation: &str) -> Result<(), Diagnostic> {
        self.commit(|registry| {
            let found = registry.operations.get(operation).ok_or_else(|| operation_missing(operation))?;
            if found.state == OperationState::AwaitingInput {
                // Continue with the answers already given; a step that still lacks one asks again.
                let found = operation_mut(registry, operation)?;
                found.set_state(OperationState::Planned);
                found.error = None;
                found.event(None, "Continuing.");
                return Ok(());
            }
            if found.state == OperationState::Unknown {
                // Nothing changes here: the runner looks at what the cut-off step left behind
                // first (`settle_before_continuing`), and claims the setup again only once it
                // knows. The setup is still held by this operation meanwhile.
                return Ok(());
            }
            if !matches!(found.state, OperationState::Failed | OperationState::Cancelled) {
                return Err(Diagnostic::new("not_retryable", "Only a failed, cancelled, waiting or unknown change can be continued.").operation(operation));
            }
            let setup = found.setup.clone();
            let claimed = found.claimed_revision;
            let instance = registry.instances.get(&setup).ok_or_else(|| not_found(&setup))?;
            if instance.current_operation.is_some() || instance.revision != claimed + 1 {
                return Err(Diagnostic::new(
                    "revision_conflict",
                    "This setup has changed since this operation stopped. Review the change again instead of retrying it.",
                )
                .operation(operation)
                .next(&["plan"]));
            }
            if registry.tombstones.contains_key(&setup) {
                return Err(removed(&setup));
            }
            // A stop or removal is ordered by what the setup's parts need. One stopped under an
            // earlier rule (a volume taken down before the sandbox that mounts it) would only
            // fail the same way again, so its waits are worked out again before it carries on.
            let teardown = matches!(found.kind, OperationKind::Stop | OperationKind::Remove).then(|| teardown_waits(&found.steps, instance));
            let instance = registry.instances.get_mut(&setup).expect("instance exists");
            instance.revision += 1;
            instance.current_operation = Some(operation.to_owned());
            let revision = instance.revision;
            let found = operation_mut(registry, operation)?;
            found.claimed_revision = revision;
            found.cancel_requested = false;
            found.error = None;
            found.completed_at = None;
            for step in &mut found.steps {
                if matches!(step.state, StepState::Failed | StepState::Cancelled) {
                    step.state = StepState::Pending;
                }
                if let Some(waits) = teardown.as_ref().and_then(|waits| waits.get(&step.id)) {
                    step.depends_on = waits.clone();
                }
            }
            found.set_state(OperationState::Planned);
            found.event(None, "Retrying the steps that didn't finish.");
            Ok(())
        })
    }

    /// Looks at every owned resource and records drift. Never recreates or changes anything;
    /// a missing resource is repaired only by a reviewed repair plan.
    pub(crate) async fn refresh(&self, setup: &str) -> Result<views::Detail, Diagnostic> {
        if adopt::is_adopted_id(setup) {
            return self.get(setup);
        }
        let contexts = self.read(|registry| {
            let instance = registry.instances.get(setup).ok_or_else(|| not_found(setup))?;
            if let Some(operation) = instance.current_operation.as_ref().and_then(|id| registry.operations.get(id)) {
                return Err(busy(operation));
            }
            Ok(instance
                .resources
                .values()
                .filter(|resource| resource.runtime_id.is_some() && resource.desired != Desired::Absent)
                .map(|resource| observe_context(instance, resource))
                .collect::<Vec<_>>())
        })?;
        let mut found = Vec::new();
        for context in contexts {
            let (observation, health) = match self.handlers.get(context.kind) {
                Ok(handler) => {
                    let observation = handler
                        .observe(&context)
                        .await
                        .unwrap_or_else(|error| Observation::Unknown { reason: error.message });
                    let health = match &observation {
                        Observation::Present { .. } => handler.health(&context).await.ok(),
                        _ => None,
                    };
                    (observation, health)
                }
                Err(diagnostic) => (Observation::Unknown { reason: diagnostic.message }, None),
            };
            found.push((context.resource.clone(), observation, health));
        }
        self.commit(|registry| {
            let instance = registry.instances.get_mut(setup).ok_or_else(|| not_found(setup))?;
            if instance.current_operation.is_some() {
                // A change started while looking; its own receipts are newer than these.
                return Ok(());
            }
            let at = now();
            let mut healths = Vec::new();
            for (id, observation, report) in &found {
                let health = report.as_ref().map(|report| report.health);
                let Some(resource) = instance.resources.get_mut(id) else { continue };
                match observation {
                    Observation::Present { observed, cost, retained_data, .. } => {
                        resource.observed = *observed;
                        resource.cost = *cost;
                        resource.retained_data = *retained_data;
                        resource.last_observed_at = Some(at.clone());
                        resource.drift = match (resource.desired, observed) {
                            (Desired::Running, Observed::Stopped) => Some("Stopped since this setup started it, for example when Yougori closed or by hand.".into()),
                            (Desired::Stopped, Observed::Running) => Some("Started since this setup stopped it, for example by hand.".into()),
                            _ => None,
                        };
                        healths.push(if resource.drift.is_some() { Health::Degraded } else { health.unwrap_or(Health::Unknown) });
                    }
                    Observation::Absent => {
                        resource.observed = Observed::Missing;
                        resource.last_observed_at = Some(at.clone());
                        resource.drift = Some("Removed outside Yougori. Repair the setup to create it again.".into());
                        healths.push(Health::Degraded);
                    }
                    Observation::Unknown { .. } => {
                        resource.observed = Observed::Unknown;
                        healths.push(Health::Unknown);
                    }
                }
            }
            instance.health = combined_health(&healths);
            instance.updated_at = at;
            Ok(())
        })?;
        let at = now();
        let said = found
            .iter()
            .filter_map(|(id, _, report)| report.as_ref().map(|report| (id.clone(), PartHealth { health: report.health, detail: report.detail.clone(), at: at.clone() })))
            .collect::<BTreeMap<_, _>>();
        lock(&self.health_reports).insert(setup.to_owned(), said);
        self.refresh_outputs(setup).await;
        self.get(setup)
    }

    /// What each part of the setup said about its health at its last check, by part. Empty
    /// before the first check since this engine started.
    pub(crate) fn health_reports(&self, setup: &str) -> BTreeMap<String, PartHealth> {
        lock(&self.health_reports).get(setup).cloned().unwrap_or_default()
    }

    // ----- New work and rented compute (plan 8.4) -----

    /// What pausing or resuming new work would do to this setup, said before anything changes:
    /// each of its own parts that take work in, what becomes of work already running, and that
    /// nothing is deleted. Its `planDigest` is what applies it (`admission`).
    pub(crate) fn admission_review(&self, setup: &str, change: Admission) -> Result<Value, Diagnostic> {
        let (parts, revision) = self.working_parts(setup)?;
        let names = parts.iter().map(|part| part.resource.clone()).collect::<Vec<_>>();
        let which = names.join(", ");
        let notes = match change {
            Admission::Pause { drain } => vec![
                format!("Jobs of {which} that are waiting don't start, and new ones aren't taken, until you resume new work."),
                if drain {
                    "Jobs already running finish, and what they hand back is kept.".to_owned()
                } else {
                    "Each job already running is asked to stop, as a cancel asks; its computer decides when that is safe. Nothing is killed.".to_owned()
                },
                "Nothing is deleted: the jobs, their queue and what they produced stay as they are.".to_owned(),
            ],
            Admission::Resume => vec![format!("Jobs of {which} that waited start as computers have room, in the order they came, and new ones are taken again.")],
        };
        Ok(json!({
            "reviewed": true,
            "applied": false,
            "setupId": setup,
            "action": admission_action(change),
            "drain": match change { Admission::Pause { drain } => json!(drain), Admission::Resume => Value::Null },
            "parts": names,
            "notes": notes,
            "planDigest": admission_digest(setup, change, revision, &names),
            "next": "Nothing has been changed. To go ahead, send this action again with planDigest set to the digest above.",
        }))
    }

    /// Pauses or resumes new work, exactly as the review with `digest` said. A digest from another
    /// review, or from before the setup changed, is refused and nothing changes.
    pub(crate) async fn admission(&self, setup: &str, change: Admission, digest: &str) -> Result<Value, Diagnostic> {
        let (parts, revision) = self.working_parts(setup)?;
        let names = parts.iter().map(|part| part.resource.clone()).collect::<Vec<_>>();
        if digest != admission_digest(setup, change, revision, &names) {
            return Err(review_changed(setup));
        }
        let mut said = BTreeSet::new();
        for part in &parts {
            let handler = self.handlers.get(part.kind).map_err(|diagnostic| diagnostic.resource(&part.resource))?;
            said.insert(handler.admission(part, change).await.map_err(|error| error.diagnostic().resource(&part.resource))?);
        }
        Ok(json!({ "applied": true, "setupId": setup, "action": admission_action(change), "said": said }))
    }

    /// The setup's own parts that take work in, ready to be asked, with its revision. Refused for
    /// an older grid, a setup another change holds, or one where nothing takes work in.
    fn working_parts(&self, setup: &str) -> Result<(Vec<StepContext>, u64), Diagnostic> {
        if adopt::is_adopted_id(setup) {
            return Err(legacy_managed(setup));
        }
        let (parts, revision) = self.read(|registry| {
            if registry.tombstones.contains_key(setup) {
                return Err(removed(setup));
            }
            let instance = registry.instances.get(setup).ok_or_else(|| not_found(setup))?;
            if let Some(operation) = instance.current_operation.as_ref().and_then(|id| registry.operations.get(id)) {
                return Err(busy(operation));
            }
            let parts = instance
                .resources
                .values()
                .filter(|part| !part.borrowed() && part.desired != Desired::Absent && self.handlers.get(part.kind).is_ok_and(|handler| handler.takes_work()))
                .map(|part| observe_context(instance, part))
                .collect::<Vec<_>>();
            Ok((parts, instance.revision))
        })?;
        if parts.is_empty() {
            return Err(Diagnostic::new(
                "unsupported_here",
                "Nothing in this setup takes work in, so there is no new work to pause. A grid has no pause for new work yet; stopping the setup stops what it runs. Nothing was changed.",
            )
            .resource(setup));
        }
        Ok((parts, revision))
    }

    /// What releasing this setup's rented compute would do, said before anything changes: each
    /// rented computer by name, what it is and costs, who stops it, and when its charges stop.
    /// `resource` narrows it to one part. With nothing rented, the review says so and gives nothing
    /// to apply.
    pub(crate) async fn release_review(&self, setup: &str, resource: Option<&str>) -> Result<Value, Diagnostic> {
        let (held, revision) = self.rented_parts(setup, resource).await?;
        if held.is_empty() {
            return Ok(json!({
                "reviewed": true,
                "applied": false,
                "setupId": setup,
                "action": "release_compute",
                "rented": [],
                "notes": ["Nothing in this setup holds rented compute that may be billing, so there is nothing to release. Nothing was changed."],
            }));
        }
        let rented = held
            .iter()
            .map(|(part, said)| json!({ "part": part.resource, "provider": said["provider"], "computers": said["computers"], "notes": said["notes"] }))
            .collect::<Vec<_>>();
        Ok(json!({
            "reviewed": true,
            "applied": false,
            "setupId": setup,
            "action": "release_compute",
            "rented": rented,
            "planDigest": release_digest(setup, resource, revision, &held),
            "next": "Nothing has been changed. To go ahead, send this action again with planDigest set to the digest above.",
        }))
    }

    /// Releases the rented compute the review with `digest` named, and nothing else: one whose
    /// rented computers changed since, or that rents nothing now, is refused and nothing changes.
    /// Says what came of each part, naming every computer whose provider hasn't yet confirmed it
    /// stopped; `chargesStopped` is true only when every one has.
    pub(crate) async fn release(&self, setup: &str, resource: Option<&str>, digest: &str) -> Result<Value, Diagnostic> {
        let (held, revision) = self.rented_parts(setup, resource).await?;
        if held.is_empty() || digest != release_digest(setup, resource, revision, &held) {
            return Err(review_changed(setup));
        }
        let mut released = Vec::new();
        for (part, _) in &held {
            let handler = self.handlers.get(part.kind).map_err(|diagnostic| diagnostic.resource(&part.resource))?;
            let outcome = handler.release(part).await.map_err(|error| error.diagnostic().resource(&part.resource))?;
            released.push(json!({ "part": part.resource, "outcome": outcome }));
        }
        let stopped = released.iter().all(|done| done["outcome"]["confirmed"] == true);
        Ok(json!({
            "applied": true,
            "setupId": setup,
            "action": "release_compute",
            "released": released,
            "chargesStopped": stopped,
            "next": if stopped {
                "Every stop was confirmed by its provider."
            } else {
                "Not every stop is confirmed yet, so the computers named may still be charging. Each is checked again; review the release again to see where it stands."
            },
        }))
    }

    /// The setup's own parts that hold rented compute that may be billing, each with what its
    /// handler says of it, and the setup's revision. `resource` narrows it to one part.
    async fn rented_parts(&self, setup: &str, resource: Option<&str>) -> Result<(Vec<(StepContext, Value)>, u64), Diagnostic> {
        if adopt::is_adopted_id(setup) {
            return Err(legacy_managed(setup));
        }
        let (parts, revision) = self.read(|registry| {
            if registry.tombstones.contains_key(setup) {
                return Err(removed(setup));
            }
            let instance = registry.instances.get(setup).ok_or_else(|| not_found(setup))?;
            if let Some(operation) = instance.current_operation.as_ref().and_then(|id| registry.operations.get(id)) {
                return Err(busy(operation));
            }
            if let Some(wanted) = resource {
                let part = instance
                    .resources
                    .get(wanted)
                    .ok_or_else(|| Diagnostic::new("resource_missing", "This setup has no part by that name. Nothing was changed.").resource(wanted))?;
                if part.borrowed() {
                    return Err(Diagnostic::new("resource_borrowed", format!("{wanted} belongs to another setup, which pays for it and releases it. Nothing was changed.")).resource(wanted));
                }
            }
            let parts = instance
                .resources
                .values()
                .filter(|part| !part.borrowed() && part.runtime_id.is_some() && part.desired != Desired::Absent)
                .filter(|part| resource.is_none_or(|wanted| part.id == wanted))
                .map(|part| observe_context(instance, part))
                .collect::<Vec<_>>();
            Ok((parts, instance.revision))
        })?;
        let mut held = Vec::new();
        for part in parts {
            let handler = self.handlers.get(part.kind).map_err(|diagnostic| diagnostic.resource(&part.resource))?;
            if let Some(said) = handler.rented(&part).await.map_err(|error| error.diagnostic().resource(&part.resource))? {
                held.push((part, said));
            }
        }
        Ok((held, revision))
    }

    // ----- Outputs -----

    /// The outputs this setup's template declares for its own answers (each whose `when` holds),
    /// public or private, with what rendering them needs: its answers, its name and the parts that
    /// exist to ask. A setup made without a template package declares none.
    fn declared_outputs(&self, setup: &str, private: bool) -> Result<Declared, Diagnostic> {
        if adopt::is_adopted_id(setup) {
            return Err(legacy_managed(setup));
        }
        let (parts, answers, name, revision) = self.read(|registry| {
            if registry.tombstones.contains_key(setup) {
                return Err(removed(setup));
            }
            let instance = registry.instances.get(setup).ok_or_else(|| not_found(setup))?;
            let parts = instance
                .resources
                .values()
                .filter(|resource| !resource.borrowed() && resource.runtime_id.is_some() && resource.desired != Desired::Absent)
                .map(|resource| observe_context(instance, resource))
                .collect::<Vec<_>>();
            Ok((parts, instance.answers.clone(), instance.name.clone(), instance.revision))
        })?;
        let checked = self.package_files(setup).and_then(|files| yougori_setup::format::template(&files).ok());
        let inputs = answers.into_iter().map(|(id, value)| (id, value.as_str().map(str::to_owned).unwrap_or_else(|| value.to_string()))).collect::<BTreeMap<_, _>>();
        let templated = checked.is_some();
        let outputs = checked
            .map(|checked| {
                checked
                    .outputs
                    .into_iter()
                    .filter(|output| output.private == private && output.when.as_ref().is_none_or(|when| when.holds(&inputs)))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let values = yougori_setup::placeholder::Values { instance: name, inputs, partial: true, ..Default::default() };
        Ok(Declared { revision, templated, outputs, values, parts })
    }

    /// Asks the setup's parts what they show of themselves now, into `declared`'s values: the ones
    /// `only` names, or every one. Answers the ones that didn't say.
    async fn ask_parts(&self, declared: &mut Declared, only: Option<&BTreeSet<String>>) -> BTreeSet<String> {
        let mut silent = BTreeSet::new();
        for part in declared.parts.iter().filter(|part| only.is_none_or(|named| named.contains(&part.resource))) {
            let reported = match self.handlers.get(part.kind) {
                Ok(handler) => handler.outputs(part).await.ok(),
                Err(_) => None,
            };
            match reported {
                Some(reported) => {
                    declared.values.outputs.insert(part.resource.clone(), reported);
                }
                None => {
                    silent.insert(part.resource.clone());
                }
            }
        }
        silent
    }

    /// Brings the setup's outputs and realm references up to date with what its parts show now.
    ///
    /// Outputs: every public output its template declares for its answers whose every part is
    /// known. A private one is never kept (`reveal`); one not known yet is left out, never filled
    /// with a stand-in, and one whose part has gone goes with it. They are rewritten only when
    /// every part they name answered.
    ///
    /// Realms: each Grid Core realm a part says it lives in (`realm_id`). One stays until the setup
    /// goes, since it still holds what the setup's jobs made after they are removed.
    ///
    /// Written only if nothing changed the setup meanwhile. Both are derived from what is there,
    /// so the setup's revision, and every plan reviewed against it, stays as it is.
    pub(crate) async fn refresh_outputs(&self, setup: &str) {
        let Ok(mut declared) = self.declared_outputs(setup, false) else { return };
        // Every part is asked: the outputs name some, and any may say which realm it lives in.
        let silent = self.ask_parts(&mut declared, None).await;
        let outputs = (declared.templated && parts_named(&declared.outputs).is_disjoint(&silent)).then(|| {
            declared
                .outputs
                .iter()
                .filter_map(|output| Some((output_key(output), output_value(&output.value, &declared.values)?)))
                .collect::<BTreeMap<_, _>>()
        });
        let realms = declared.values.outputs.values().filter_map(|reported| reported.get("realm_id").cloned()).collect::<BTreeSet<_>>();
        let revision = declared.revision;
        let _ = self.commit(|registry| {
            let Some(instance) = registry.instances.get_mut(setup).filter(|instance| instance.revision == revision) else {
                return Ok(());
            };
            if let Some(outputs) = outputs {
                instance.outputs = outputs;
            }
            if realms.iter().any(|realm| !instance.realms.contains(realm)) {
                let mut all = instance.realms.iter().cloned().collect::<BTreeSet<_>>();
                all.extend(realms);
                instance.realms = all.into_iter().collect();
            }
            Ok(())
        });
    }

    /// The private outputs this setup can show now, as key and label: never a value. One its parts
    /// can't give right now, or never give (an API key no template makes yet), isn't listed.
    pub(crate) async fn private_outputs(&self, setup: &str) -> Result<Vec<(String, String)>, Diagnostic> {
        let mut declared = self.declared_outputs(setup, true)?;
        let named = parts_named(&declared.outputs);
        self.ask_parts(&mut declared, Some(&named)).await;
        Ok(declared
            .outputs
            .iter()
            .filter(|output| output_value(&output.value, &declared.values).is_some())
            .map(|output| (output_key(output), output.label.clone()))
            .collect())
    }

    /// One private output's label and value, asked of the product now for the person who asked:
    /// never written to the registry, a log or the vault, and never cached, so it is always the
    /// grid's current one.
    pub(crate) async fn reveal(&self, setup: &str, key: &str) -> Result<(String, String), Diagnostic> {
        let mut declared = self.declared_outputs(setup, true)?;
        let output = declared
            .outputs
            .iter()
            .find(|output| output_key(output) == key)
            .cloned()
            .ok_or_else(|| Diagnostic::new("output_unknown", format!("This setup has no private output called {key}.")).resource(setup))?;
        let named = parts_named(std::slice::from_ref(&output));
        self.ask_parts(&mut declared, Some(&named)).await;
        let value = output_value(&output.value, &declared.values).ok_or_else(|| {
            Diagnostic::new(
                "output_not_ready",
                format!("{} isn't available right now: the part of this setup it comes from isn't running, or hasn't given it yet. Try again once the setup is running.", output.label),
            )
            .retryable()
            .resource(setup)
        })?;
        Ok((output.label, value))
    }

    /// Each declared output's key with its template's own label, for the setup page.
    fn output_labels(&self, setup: &str) -> BTreeMap<String, String> {
        self.package_files(setup)
            .and_then(|files| yougori_setup::format::template(&files).ok())
            .map(|checked| checked.outputs.iter().map(|output| (output_key(output), output.label.clone())).collect())
            .unwrap_or_default()
    }

    // ----- Scheduled backups (setups/schedules.rs, setups/backups.rs) -----

    /// The backup scheduler, once the engine has started it.
    pub(crate) fn scheduler(&self) -> Option<Arc<super::schedules::Scheduler>> {
        self.scheduler.get().cloned()
    }

    /// The drive this setup's own sandboxes are stored on, when one was chosen.
    pub(crate) fn sandbox_drive(&self, setup: &str) -> Result<Option<String>, Diagnostic> {
        self.read(|registry| {
            let instance = registry.instances.get(setup).ok_or_else(|| not_found(setup))?;
            Ok(instance.resources.values().filter(|resource| resource.kind == Kind::Environment && !resource.borrowed()).find_map(|resource| resource.spec["storage_drive"].as_str().map(str::to_owned)))
        })
    }

    /// Gives the service the backup worker and the scheduler, once the engine has started, and
    /// brings every setup's times up to date with what its template declares.
    /// Wires the jobs' event addresses, and opens every setup's that should be open.
    pub(crate) async fn wire_events(&self, events: Arc<dyn EventsSync>) {
        let _ = self.events.set(events.clone());
        let setups = self.read(|registry| Ok(registry.instances.keys().cloned().collect::<Vec<_>>())).unwrap_or_default();
        for setup in setups {
            events.sync(&setup).await;
            self.refresh_outputs(&setup).await;
        }
    }

    pub(crate) fn wire_backups(&self, backups: Arc<super::backups::Backups>, scheduler: Arc<super::schedules::Scheduler>) {
        let _ = self.backups.set(backups);
        let _ = self.scheduler.set(scheduler);
        let setups = self.read(|registry| Ok(registry.instances.keys().cloned().collect::<Vec<_>>())).unwrap_or_default();
        for setup in setups {
            if let Err(error) = self.sync_schedules(&setup) {
                eprintln!("Backup times could not be brought up to date: {}", error.message);
            }
        }
    }

    fn backups(&self) -> Result<Arc<super::backups::Backups>, Diagnostic> {
        self.backups
            .get()
            .cloned()
            .ok_or_else(|| Diagnostic::new("setups_starting", "Backups are still starting. Try again in a moment.").retryable())
    }

    /// Makes the registry's schedules match what a setup's template declares, and whether the
    /// setup is running. Called after every operation on it, so a setup that was created,
    /// changed, stopped, started or removed keeps exactly the times it should.
    ///
    /// A volume's backups are **not** deleted here: removing a setup drops its times, and the
    /// copies stay in Yougori's data folder until a person deletes them, as data always does.
    pub(crate) fn sync_schedules(&self, setup: &str) -> Result<(), Diagnostic> {
        use super::schedules::{next_due, now, Schedule, Work};
        use yougori_setup::resource::{parse_json, Spec};
        let changed = self.commit(|registry| {
            let instance = registry.instances.get(setup);
            let paused = instance.is_none_or(|instance| matches!(instance.lifecycle, Lifecycle::Stopped | Lifecycle::Removing | Lifecycle::Retained | Lifecycle::Removed));
            let mut wanted: BTreeMap<String, Schedule> = BTreeMap::new();
            for resource in instance.into_iter().flat_map(|instance| instance.resources.values()).filter(|resource| resource.kind == Kind::Volume && !resource.borrowed()) {
                let Ok(Spec::Volume(volume)) = parse_json(Kind::Volume, &resource.spec) else { continue };
                let Some(backup) = volume.backup() else { continue };
                // Where the sandbox it is read through mounts it. Without that the schedule
                // cannot run, so none is kept: the setup page shows the volume with no backups.
                let Some(path) = instance
                    .and_then(|instance| instance.resources.get(&backup.through))
                    .filter(|through| through.kind == Kind::Environment)
                    .and_then(|through| mount_target(&through.spec, &resource.id))
                else {
                    continue;
                };
                let id = Schedule::key(setup, &resource.id);
                wanted.insert(
                    id.clone(),
                    Schedule {
                        id,
                        setup: setup.to_owned(),
                        resource: resource.id.clone(),
                        work: Work::VolumeBackup,
                        schedule: backup.schedule.to_string(),
                        timezone: backup.timezone.to_string(),
                        keep: backup.keep,
                        consistency: backup.consistency,
                        missed: backup.missed,
                        overlap: backup.overlap,
                        retries: backup.retries,
                        through: backup.through.clone(),
                        path,
                        paused,
                        next_at: 0,
                        last_started_at: None,
                        last_finished_at: None,
                        last_outcome: Default::default(),
                        last_detail: String::new(),
                        failures: 0,
                        backups: Vec::new(),
                    },
                );
            }
            let before = registry.schedules.clone();
            registry.schedules.retain(|id, _| !id.starts_with(&format!("{setup}/")) || wanted.contains_key(id));
            for (id, mut schedule) in wanted {
                match before.get(&id) {
                    // Already known: what happened and what is kept stay, and the next time is
                    // worked out afresh only when the times themselves changed.
                    Some(saved) => {
                        let same = saved.schedule == schedule.schedule && saved.timezone == schedule.timezone;
                        schedule.last_started_at = saved.last_started_at;
                        schedule.last_finished_at = saved.last_finished_at;
                        schedule.last_outcome = saved.last_outcome;
                        schedule.last_detail = saved.last_detail.clone();
                        schedule.failures = saved.failures;
                        schedule.backups = saved.backups.clone();
                        schedule.next_at = if same { saved.next_at } else { 0 };
                    }
                    None => {}
                }
                if schedule.next_at == 0 {
                    schedule.next_at = next_due(&schedule, now()).unwrap_or(0);
                }
                registry.schedules.insert(schedule.id.clone(), schedule);
            }
            Ok(registry.schedules != before)
        })?;
        if changed {
            if let Some(scheduler) = self.scheduler.get() {
                scheduler.changed();
            }
        }
        Ok(())
    }

    /// Read-only access to the registry, for the operations reading (`setups/telemetry.rs`). It
    /// hands the records to a function that can only look at them: nothing here can write, and
    /// the reading it builds is redacted again on its way out.
    pub(crate) fn observe<T>(&self, view: impl FnOnce(&Registry) -> Result<T, Diagnostic>) -> Result<T, Diagnostic> {
        self.read(view)
    }

    /// One of a setup's recorded resources, by its id in the setup. Reads only.
    pub(crate) fn resource_of(&self, setup: &str, resource: &str) -> Result<Resource, Diagnostic> {
        self.read(|registry| {
            let instance = registry.instances.get(setup).ok_or_else(|| not_found(setup))?;
            instance.resources.get(resource).cloned().ok_or_else(|| Diagnostic::new("resource_unknown", format!("This setup has no part called {resource}.")).resource(resource))
        })
    }

    /// The setups that sent a job of their own and are not being removed: the ones whose queue may
    /// hold work for this computer's workers after Yougori starts again. Reads only; empty when the
    /// registry can't be read.
    pub(crate) fn with_jobs(&self) -> Vec<String> {
        self.read(|registry| {
            Ok(registry
                .instances
                .iter()
                .filter(|(_, instance)| !matches!(instance.lifecycle, Lifecycle::Removing | Lifecycle::Removed))
                .filter(|(_, instance)| instance.resources.values().any(|resource| resource.kind == Kind::Job && !resource.borrowed() && resource.runtime_id.is_some()))
                .map(|(id, _)| id.clone())
                .collect())
        })
        .unwrap_or_default()
    }

    /// The setup's resources of `kind` it owns, with their recorded IDs. Reads only.
    pub(crate) fn resources_of(&self, setup: &str, kind: Kind) -> Result<Vec<Resource>, Diagnostic> {
        self.read(|registry| {
            let instance = registry.instances.get(setup).ok_or_else(|| not_found(setup))?;
            Ok(instance.resources.values().filter(|resource| resource.kind == kind && !resource.borrowed()).cloned().collect())
        })
    }

    /// A setup's backup times, for the setup page and the CLI.
    pub(crate) fn schedules_of(&self, setup: &str) -> Result<Vec<super::schedules::Schedule>, Diagnostic> {
        self.read(|registry| Ok(registry.schedules.values().filter(|schedule| schedule.setup == setup).cloned().collect()))
    }

    /// One of a setup's volumes' backup times, by the volume's resource id.
    fn schedule_of(&self, setup: &str, resource: &str) -> Result<super::schedules::Schedule, Diagnostic> {
        self.read(|registry| {
            registry
                .schedules
                .get(&super::schedules::Schedule::key(setup, resource))
                .cloned()
                .ok_or_else(|| Diagnostic::new("no_backups", "This setup doesn't back this up. Nothing was changed.").resource(resource))
        })
    }

    /// What restoring a kept backup would do, before anything is changed.
    pub(crate) fn restore_review(&self, setup: &str, resource: &str, backup: &str, original: bool) -> Result<Vec<String>, Diagnostic> {
        let schedule = self.schedule_of(setup, resource)?;
        let found = schedule.backups.iter().find(|kept| kept.id == backup).ok_or_else(|| no_backup(backup))?;
        let target = if original { super::backups::Target::Original } else { super::backups::Target::Copy };
        Ok(self.backups()?.restore_review(&schedule, found, target))
    }

    /// Puts a kept backup back, into a disposable copy or, when the person has seen the review
    /// and asked for it by name, over the volume itself.
    pub(crate) async fn restore_backup(&self, setup: &str, resource: &str, backup: &str, original: bool) -> Result<Value, Diagnostic> {
        let schedule = self.schedule_of(setup, resource)?;
        if let Some(operation) = self.read(|registry| {
            Ok(registry
                .instances
                .get(setup)
                .and_then(|instance| instance.current_operation.clone())
                .and_then(|id| registry.operations.get(&id).cloned()))
        })? {
            return Err(busy(&operation));
        }
        let found = schedule.backups.iter().find(|kept| kept.id == backup).cloned().ok_or_else(|| no_backup(backup))?;
        let target = if original { super::backups::Target::Original } else { super::backups::Target::Copy };
        self.backups()?
            .restore(&schedule, &found, target)
            .await
            .map_err(|error| Diagnostic::new("restore_failed", error).resource(resource))
    }

    /// The second half of deleting a volume the person ticked on its removal: its backups.
    ///
    /// The volume's backup times go first, so no new copy starts. A copy already being taken is
    /// waited for: it finds its times gone when it finishes and discards itself. Then the
    /// volume's backups folder goes. Any of it failing fails the step, which says the volume
    /// itself is already gone, and trying again finishes it, so nothing the review named is left
    /// half-deleted without saying so.
    async fn forget_backups(&self, context: &StepContext) -> Result<(), HandlerError> {
        let volume = &context.resource;
        let failed = |why: String| HandlerError {
            retryable: true,
            ..HandlerError::new(
                Outcome::Failed,
                "backups_delete_failed",
                format!("{volume} was deleted, but its backups were not yet: {why} They are still in Yougori's data folder. Try again to finish deleting them."),
            )
        };
        let id = super::schedules::Schedule::key(&context.setup, volume);
        self.commit(|registry| {
            registry.schedules.remove(&id);
            Ok(())
        })
        .map_err(|error| failed(error.message))?;
        if let Some(scheduler) = self.scheduler.get() {
            scheduler.changed();
            let waited = Instant::now();
            while scheduler.running_now(&id) {
                if context.cancel.is_cancelled() || waited.elapsed() > BACKUP_WAIT {
                    return Err(failed(format!("a backup of {volume} was being taken right now.")));
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
        let backups = self.backups().map_err(|error| failed(error.message))?;
        backups
            .forget_volume(&context.setup, volume)
            .await
            .map_err(|error| failed(format!("{}.", crate::lifecycle::safe_diagnostic(&error).trim_end_matches('.'))))
    }

    /// Checks a kept backup against its own record, without changing anything.
    pub(crate) async fn verify_backup(&self, setup: &str, resource: &str, backup: &str) -> Result<Value, Diagnostic> {
        self.schedule_of(setup, resource)?;
        self.backups()?
            .verify(setup, resource, backup)
            .await
            .map_err(|error| Diagnostic::new("backup_unusable", error).resource(resource))
    }
}

fn no_backup(backup: &str) -> Diagnostic {
    Diagnostic::new("backup_not_found", "That backup is not one Yougori kept. Choose one from the list.").resource(backup)
}

/// Where a sandbox mounts a named volume of the same setup, such as `/data`.
fn mount_target(spec: &Value, volume: &str) -> Option<String> {
    spec["volumes"]
        .as_array()?
        .iter()
        .find(|mount| mount["bind"] != true && mount["source"].as_str() == Some(volume))
        .and_then(|mount| mount["target"].as_str())
        .map(str::to_owned)
}

impl super::schedules::Records for Service {
    fn schedules(&self) -> Vec<super::schedules::Schedule> {
        self.read(|registry| Ok(registry.schedules.values().cloned().collect())).unwrap_or_default()
    }

    /// Writes one schedule's progress. A failed save leaves the times as they were: the run that
    /// happened is then made again at its next time, which a backup can safely be.
    fn change(&self, id: &str, change: &mut dyn FnMut(&mut super::schedules::Schedule)) {
        let saved = self.commit(|registry| {
            if let Some(schedule) = registry.schedules.get_mut(id) {
                change(schedule);
            }
            Ok(())
        });
        if let Err(error) = saved {
            eprintln!("A backup's progress could not be saved: {}", error.message);
        }
    }
}

impl super::backups::Setups for Service {
    fn sandbox(&self, setup: &str, resource: &str) -> Option<String> {
        self.read(|registry| {
            Ok(registry
                .instances
                .get(setup)
                .and_then(|instance| instance.resources.get(resource))
                .filter(|found| found.kind == Kind::Environment && found.desired != Desired::Absent)
                .and_then(|found| found.runtime_id.clone()))
        })
        .ok()
        .flatten()
    }

    fn mounting(&self, setup: &str, volume: &str) -> Vec<String> {
        self.read(|registry| {
            Ok(registry
                .instances
                .get(setup)
                .into_iter()
                .flat_map(|instance| instance.resources.values())
                .filter(|resource| resource.kind == Kind::Environment && mount_target(&resource.spec, volume).is_some())
                .map(|resource| resource.id.clone())
                .collect())
        })
        .unwrap_or_default()
    }
}

// ----- Pure registry transitions -----

fn operation_missing(operation: &str) -> Diagnostic {
    Diagnostic::new("operation_not_found", "This operation is not on this computer.").operation(operation)
}

fn operation_mut<'a>(registry: &'a mut Registry, operation: &str) -> Result<&'a mut Operation, Diagnostic> {
    registry.operations.get_mut(operation).ok_or_else(|| operation_missing(operation))
}

fn action_words(action: Action) -> &'static str {
    match action {
        Action::Create => "creating",
        Action::Update => "updating",
        Action::Start => "starting",
        Action::Stop => "stopping",
        Action::Attach => "attaching",
        Action::Detach => "detaching",
        Action::Remove => "removing",
    }
}

fn combined_health(healths: &[Health]) -> Health {
    let rank = |health: &Health| match health {
        Health::Failed => 7,
        Health::Degraded => 6,
        Health::Unsupported => 5,
        Health::NeedsSignIn => 4,
        Health::WaitingForComputer => 3,
        Health::Starting => 2,
        Health::Unknown => 1,
        Health::Ready => 0,
    };
    healths.iter().copied().max_by_key(rank).unwrap_or(Health::Unknown)
}

/// What a previous engine left running: mid-call steps become unknown, other interrupted
/// operations fail with a retry that continues only the missing steps.
fn interrupted(registry: &mut Registry) {
    let open = registry
        .operations
        .values()
        .filter(|operation| matches!(operation.state, OperationState::Planned | OperationState::Applying | OperationState::Cancelling))
        .map(|operation| operation.id.clone())
        .collect::<Vec<_>>();
    for id in open {
        let operation = registry.operations.get_mut(&id).expect("listed above");
        let mut unknown = false;
        for step in &mut operation.steps {
            if step.state == StepState::Applying {
                step.state = StepState::Unknown;
                unknown = true;
            }
        }
        if unknown {
            operation.set_state(OperationState::Unknown);
            operation.error = Some(
                Diagnostic::new("engine_interrupted", "Yougori closed while a step was running. It will check what happened before doing anything else.")
                    .operation(&id)
                    .next(&["reconcile"]),
            );
            operation.event(None, "Yougori closed while a step was running. Checking what happened.");
        } else if operation.cancel_requested {
            finish(registry, &id, OperationState::Cancelled, None);
        } else {
            let started = operation.state != OperationState::Planned;
            finish(
                registry,
                &id,
                OperationState::Failed,
                Some(
                    Diagnostic::new(
                        "engine_interrupted",
                        if started {
                            "Yougori closed during this change. Retry continues only the steps that didn't finish."
                        } else {
                            "Yougori closed before this change started. Nothing was changed. Retry to start it."
                        },
                    )
                    .retryable()
                    .operation(&id)
                    .next(&["retry"]),
                ),
            );
        }
    }
}

/// Checks a reviewed plan against the setup as it is now, then saves the operation and claims
/// the setup. A repeat of the same request joins the operation it already made.
fn claim(
    registry: &mut Registry,
    handlers: &Handlers,
    adopted: &[adopt::Adopted],
    plan: &ReviewedPlan,
    operation_id: &str,
    consents: &BTreeSet<String>,
) -> Result<Submitted, Diagnostic> {
    let join = |operation: &Operation| Submitted {
        operation_id: operation.id.clone(),
        setup_id: operation.setup.clone(),
        joined: true,
    };
    if let Some(operation) = registry.operations.get(operation_id) {
        if operation.setup != plan.setup_id || operation.plan_digest != plan.digest {
            return Err(Diagnostic::new(
                "operation_id_reused",
                "This operation ID was already used for a different change. Send the new change with a new ID.",
            )
            .operation(operation_id));
        }
        return Ok(join(operation));
    }
    if registry.tombstones.contains_key(&plan.setup_id) {
        return Err(removed(&plan.setup_id));
    }
    let instance = registry.instances.get(&plan.setup_id);
    if let Some(active) = instance
        .and_then(|instance| instance.current_operation.as_ref())
        .and_then(|id| registry.operations.get(id))
    {
        if active.plan_digest == plan.digest && !active.state.is_terminal() {
            return Ok(join(active));
        }
        return Err(busy(active));
    }
    match (instance, plan.intent) {
        (None, OperationKind::Create) if plan.base_revision == 0 => {
            if registry.instances.values().filter(|instance| instance.lifecycle != Lifecycle::Removed).count() >= SETUP_LIMIT {
                return Err(Diagnostic::new("setup_limit", "This computer has reached its limit of saved setups. Remove setups you no longer need."));
            }
        }
        (None, _) => return Err(not_found(&plan.setup_id)),
        (Some(_), OperationKind::Create) => {
            return Err(Diagnostic::new("setup_exists", "This setup was already created from this plan.")
                .resource(&plan.setup_id)
                .next(&["plan"]));
        }
        (Some(instance), _) if instance.lifecycle == Lifecycle::Removed => return Err(removed(&plan.setup_id)),
        (Some(instance), _) if instance.revision != plan.base_revision => {
            return Err(Diagnostic::new(
                "revision_conflict",
                "This setup changed after the plan was reviewed. Review the change again so nothing newer is overwritten.",
            )
            .resource(&plan.setup_id)
            .retryable()
            .next(&["plan"]));
        }
        _ => {}
    }
    // Everything below is checked again here, not only at review: another setup may have
    // changed since (a new borrower, a new grid, an owner that is now busy).
    let mut grids = Vec::new();
    for step in &plan.steps {
        match step.action {
            Action::Attach => {
                owned_by_other(registry, &plan.setup_id, &step.resource, step.kind, step.owner.as_ref())?;
            }
            Action::Detach => {}
            action => {
                handlers.get(step.kind)?;
                if action == Action::Remove {
                    if let Some(resource) = registry.instances.get(&plan.setup_id).and_then(|instance| instance.resources.get(&step.resource)) {
                        if !resource.borrowers.is_empty() {
                            return Err(in_use(resource));
                        }
                    }
                }
                if step.kind == Kind::Grid && matches!(action, Action::Create | Action::Update) {
                    grids.push((step.resource.clone(), step.spec.clone()));
                }
            }
        }
        if let Some(tombstone) = registry.tombstones.get(&format!("{}/{}", plan.setup_id, step.resource)) {
            if !matches!(step.action, Action::Remove | Action::Detach) && step.generation <= tombstone.generation {
                return Err(Diagnostic::new(
                    "resource_removed",
                    "This plan would bring back a resource that was removed. Review the change again.",
                )
                .resource(&step.resource)
                .next(&["plan"]));
            }
        }
    }
    one_grid_per_profile(registry, adopted, &plan.setup_id, &grids)?;
    one_owner_per_instance(registry, &plan.setup_id, &grids)?;
    let at = now();
    let operation_id = operation_id.to_owned();
    let claimed = plan.base_revision + 1;
    match registry.instances.get_mut(&plan.setup_id) {
        None => {
            let change = plan.change.clone().ok_or_else(|| invalid("A new setup needs its name and source."))?;
            registry.instances.insert(
                plan.setup_id.clone(),
                Instance {
                    id: plan.setup_id.clone(),
                    name: change.name,
                    source: change.source,
                    format_version: change.format_version,
                    protocol_version: change.protocol_version,
                    lock_digest: change.lock_digest,
                    config_revision: 1,
                    revision: claimed,
                    answers: change.answers,
                    secret_bindings: change.secret_bindings,
                    lock: change.lock,
                    customizations: BTreeMap::new(),
                    capabilities: change.capabilities,
                    realms: Vec::new(),
                    storage: None,
                    outputs: BTreeMap::new(),
                    current_operation: Some(operation_id.clone()),
                    lifecycle: Lifecycle::Creating,
                    health: Health::Unknown,
                    history: Vec::new(),
                    resources: BTreeMap::new(),
                    created_at: at.clone(),
                    updated_at: at.clone(),
                },
            );
        }
        Some(instance) => {
            instance.revision = claimed;
            instance.current_operation = Some(operation_id.clone());
            instance.updated_at = at.clone();
            match plan.intent {
                OperationKind::Update | OperationKind::Repair => instance.lifecycle = Lifecycle::Updating,
                OperationKind::Remove => instance.lifecycle = Lifecycle::Removing,
                _ => {}
            }
        }
    }
    let steps = plan
        .steps
        .iter()
        .map(|planned| Step {
            id: planned.id.clone(),
            resource: planned.resource.clone(),
            kind: planned.kind,
            action: planned.action,
            depends_on: planned.depends_on.clone(),
            requires: planned.requires.clone(),
            spec: planned.spec.clone(),
            generation: planned.generation,
            owner: planned.owner.clone(),
            state: StepState::Pending,
            idempotency_key: step_key(&operation_id, &planned.resource, planned.action),
            attempts: 0,
            receipt: None,
            error: None,
            started_at: None,
            finished_at: None,
        })
        .collect();
    let mut operation = Operation {
        id: operation_id.clone(),
        setup: plan.setup_id.clone(),
        kind: plan.intent,
        plan_digest: plan.digest.clone(),
        source_digest: plan.source_digest.clone(),
        base_revision: plan.base_revision,
        claimed_revision: claimed,
        state: OperationState::Planned,
        steps,
        change: (plan.intent == OperationKind::Update).then(|| plan.change.clone()).flatten(),
        cancel_requested: false,
        error: None,
        created_at: at.clone(),
        updated_at: at,
        completed_at: None,
        events: Vec::new(),
        next_seq: 0,
        consents: consents.clone(),
    };
    operation.event(None, "Saved the reviewed plan. Nothing has changed yet.");
    registry.operations.insert(operation_id.clone(), operation);
    Ok(Submitted { operation_id, setup_id: plan.setup_id.clone(), joined: false })
}

fn context(
    registry: &Registry,
    operation: &Operation,
    step: &Step,
    cancel: CancellationToken,
    secrets: Arc<BTreeMap<String, String>>,
) -> StepContext {
    let resource = registry
        .instances
        .get(&operation.setup)
        .and_then(|instance| instance.resources.get(&step.resource));
    StepContext {
        setup: operation.setup.clone(),
        operation: operation.id.clone(),
        step: step.id.clone(),
        resource: step.resource.clone(),
        kind: step.kind,
        action: step.action,
        label: step.idempotency_key.clone(),
        created_label: (step.action == Action::Create).then(|| step.idempotency_key.clone()),
        generation: step.generation,
        spec: step.spec.clone(),
        runtime_id: if step.action == Action::Create { None } else { resource.and_then(|resource| resource.runtime_id.clone()) },
        owner: step.owner.clone(),
        peers: registry.instances.get(&operation.setup).map(|instance| peers(instance, &step.resource)).unwrap_or_default(),
        planned: operation
            .steps
            .iter()
            .filter(|other| other.id != step.id)
            .map(|other| (other.resource.clone(), Peer { kind: other.kind, spec: other.spec.clone(), runtime_id: None, owned: other.owner.is_none() }))
            .collect(),
        cancel,
        secrets,
        started_at: step.started_at.as_deref().and_then(|at| chrono::DateTime::parse_from_rfc3339(at).ok()).map(|at| at.timestamp()),
        recorded: resource.map(|resource| resource.spec.clone()),
        consents: Arc::new(operation.consents.clone()),
    }
}

/// The setup's other resources, for a step that refers to them.
fn peers(instance: &Instance, except: &str) -> BTreeMap<String, Peer> {
    instance
        .resources
        .values()
        .filter(|resource| resource.id != except && resource.desired != Desired::Absent)
        .map(|resource| {
            (
                resource.id.clone(),
                Peer { kind: resource.kind, spec: resource.spec.clone(), runtime_id: resource.runtime_id.clone(), owned: !resource.borrowed() },
            )
        })
        .collect()
}

fn observe_context(instance: &Instance, resource: &Resource) -> StepContext {
    StepContext {
        setup: instance.id.clone(),
        operation: String::new(),
        step: resource.id.clone(),
        resource: resource.id.clone(),
        kind: resource.kind,
        action: Action::Update,
        label: String::new(),
        created_label: None,
        generation: resource.generation,
        spec: resource.spec.clone(),
        runtime_id: resource.runtime_id.clone(),
        owner: resource.owner.clone(),
        peers: peers(instance, &resource.id),
        planned: BTreeMap::new(),
        cancel: CancellationToken::new(),
        secrets: Default::default(),
        started_at: None,
        recorded: Some(resource.spec.clone()),
        consents: Default::default(),
    }
}

/// The receipt of an attach or detach: the engine's own record change, no provider involved.
/// Attaching copies the owner's runtime ID, so this setup sees the very resource it borrows.
fn binding_receipt(registry: &Registry, context: &StepContext) -> Result<Receipt, HandlerError> {
    let at = now();
    if context.action != Action::Attach {
        return Ok(Receipt { runtime_id: None, observed: Observed::Missing, retained_data: false, cost: Cost::Unknown, at, adopted: false });
    }
    let refused = |code: &str, message: &str| Err(HandlerError::new(Outcome::NotStarted, code, message));
    let Some(owner) = context.owner.as_ref() else {
        return refused("borrowed_resource_missing", "This step does not say which resource it borrows.");
    };
    let Some(owner_setup) = registry.instances.get(&owner.setup) else {
        return refused("borrowed_resource_missing", "The setup this one borrows from is no longer there.");
    };
    if let Some(busy) = owner_setup.current_operation.as_ref().and_then(|id| registry.operations.get(id)) {
        if busy.kind == OperationKind::Remove {
            return refused("owner_busy", "The setup this one borrows from is being removed. Nothing was attached.");
        }
    }
    match owner_setup.resources.get(&owner.resource).filter(|owned| !owned.borrowed() && owned.desired != Desired::Absent) {
        Some(owned) => Ok(Receipt { runtime_id: owned.runtime_id.clone(), observed: owned.observed, retained_data: false, cost: owned.cost, at, adopted: false }),
        None => refused("borrowed_resource_missing", "The resource this setup borrows is no longer there. Nothing was attached."),
    }
}

/// Refuses to remove a resource that gained a borrower after the removal was planned.
fn still_unborrowed(registry: &Registry, context: &StepContext) -> Result<(), HandlerError> {
    match registry.instances.get(&context.setup).and_then(|instance| instance.resources.get(&context.resource)) {
        Some(resource) if !resource.borrowers.is_empty() => {
            let refusal = in_use(resource);
            Err(HandlerError::new(Outcome::NotStarted, &refusal.code, refusal.message))
        }
        _ => Ok(()),
    }
}

/// Picks the next runnable step and saves its intent, or finishes the operation.
fn next_step(
    registry: &mut Registry,
    operation: &str,
    cancel: &CancellationToken,
    secrets: &Arc<BTreeMap<String, String>>,
) -> Result<Option<StepContext>, Diagnostic> {
    let found = operation_mut(registry, operation)?;
    if !matches!(found.state, OperationState::Applying | OperationState::Cancelling) {
        return Ok(None);
    }
    if found.cancel_requested {
        finish(registry, operation, OperationState::Cancelled, None);
        return Ok(None);
    }
    let Some(step_id) = found.runnable().map(|step| step.id.clone()) else {
        if found.all_done() {
            finish(registry, operation, OperationState::Completed, None);
        } else {
            finish(
                registry,
                operation,
                OperationState::Failed,
                Some(Diagnostic::new("steps_blocked", "Some steps can't run because a step they need did not finish.").operation(operation).next(&["retry"])),
            );
        }
        return Ok(None);
    };
    let step = found.step_mut(&step_id).expect("runnable step exists");
    step.state = StepState::Applying;
    step.attempts += 1;
    step.error = None;
    step.started_at = Some(now());
    step.finished_at = None;
    let (action, resource) = (step.action, step.resource.clone());
    found.event(Some(&step_id), format!("{} {resource}.", capitalised(action_words(action))));
    let found = &registry.operations[operation];
    let step = found.steps.iter().find(|step| step.id == step_id).expect("runnable step exists");
    Ok(Some(context(registry, found, step, cancel.clone(), secrets.clone())))
}

fn capitalised(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map(|first| first.to_uppercase().chain(chars).collect()).unwrap_or_default()
}

async fn call(handler: &dyn ResourceHandler, context: &StepContext) -> Result<Receipt, HandlerError> {
    use futures_util::FutureExt;
    let future = match context.action {
        Action::Create | Action::Update | Action::Start => handler.apply(context),
        Action::Stop => handler.stop(context),
        Action::Remove => handler.remove(context),
        Action::Attach | Action::Detach => {
            return Err(HandlerError::new(Outcome::NotStarted, "engine_step", "This step is the engine's own and calls no handler."));
        }
    };
    // A handler that panics may have acted already, so its outcome is unknown.
    std::panic::AssertUnwindSafe(future).catch_unwind().await.unwrap_or_else(|_| {
        Err(HandlerError::new(Outcome::Unknown, "handler_stopped", "The step stopped unexpectedly while it was running."))
    })
}

/// Records a step's result: the receipt and ownership on success, or what the failure means.
fn record(
    registry: &mut Registry,
    operation: &str,
    context: &StepContext,
    result: Result<Receipt, HandlerError>,
) -> Result<(), Diagnostic> {
    let found = operation_mut(registry, operation)?;
    let cancel_requested = found.cancel_requested;
    let step = found.step_mut(&context.step).ok_or_else(|| operation_missing(operation))?;
    step.finished_at = Some(now());
    match result {
        Ok(receipt) => {
            step.state = StepState::Done;
            step.receipt = Some(receipt.clone());
            let step = step.clone();
            found.event(Some(&context.step), format!("Finished {} {}.", action_words(context.action), context.resource));
            apply_receipt(registry, operation, &step, receipt);
        }
        Err(error) => {
            let diagnostic = error.diagnostic().operation(operation).step(&context.step).resource(&context.resource);
            match error.outcome {
                Outcome::NotStarted if cancel_requested => {
                    step.state = StepState::Pending;
                    found.event(Some(&context.step), format!("Cancelled before {} {} began.", action_words(context.action), context.resource));
                }
                Outcome::Unknown => {
                    step.state = StepState::Unknown;
                    step.error = Some(diagnostic.clone());
                    found.set_state(OperationState::Unknown);
                    found.error = Some(diagnostic.clone().next(&["reconcile"]));
                    found.event(Some(&context.step), format!("Can't tell whether {} {} took effect. Checking before anything else runs.", action_words(context.action), context.resource));
                }
                Outcome::NeedsInput => {
                    step.state = StepState::Pending;
                    found.set_state(OperationState::AwaitingInput);
                    found.error = Some(diagnostic.clone().next(&["continue", "cancel"]));
                    found.event(Some(&context.step), diagnostic.message.clone());
                }
                Outcome::NotStarted | Outcome::Failed | Outcome::Unsupported => {
                    step.state = StepState::Failed;
                    step.error = Some(diagnostic.clone());
                    let next: &[&str] = if diagnostic.retryable { &["retry"] } else { &["plan"] };
                    finish(registry, operation, OperationState::Failed, Some(diagnostic.next(next)));
                }
            }
        }
    }
    Ok(())
}

/// Saves what a confirmed effect means for the setup's resource records. Called in the same
/// commit as the step's receipt, so ownership is never lost between the two.
fn apply_receipt(registry: &mut Registry, operation: &str, step: &Step, receipt: Receipt) {
    let setup = registry.operations[operation].setup.clone();
    let key = format!("{setup}/{}", step.resource);
    let Some(instance) = registry.instances.get_mut(&setup) else { return };
    match step.action {
        Action::Create | Action::Update | Action::Start => {
            let resource = instance.resources.entry(step.resource.clone()).or_insert_with(|| Resource {
                id: step.resource.clone(),
                kind: step.kind,
                depends_on: step.requires.clone(),
                runtime_id: None,
                owner: step.owner.clone(),
                borrowers: Vec::new(),
                generation: step.generation,
                desired: Desired::Running,
                observed: Observed::Unknown,
                retained_data: false,
                cost: receipt.cost,
                last_observed_at: None,
                drift: None,
                spec: step.spec.clone(),
                spec_digest: digest(&step.spec),
            });
            if step.action != Action::Start {
                resource.kind = step.kind;
                resource.depends_on = step.requires.clone();
                resource.spec = step.spec.clone();
                resource.spec_digest = digest(&step.spec);
                resource.owner = step.owner.clone();
            }
            if receipt.runtime_id.is_some() {
                resource.runtime_id = receipt.runtime_id.clone();
            }
            resource.generation = step.generation;
            resource.desired = Desired::Running;
            resource.observed = receipt.observed;
            resource.retained_data = receipt.retained_data;
            resource.cost = receipt.cost;
            resource.last_observed_at = Some(receipt.at.clone());
            resource.drift = None;
        }
        Action::Attach => {
            let resource = instance.resources.entry(step.resource.clone()).or_insert_with(|| Resource {
                id: step.resource.clone(),
                kind: step.kind,
                depends_on: step.requires.clone(),
                runtime_id: None,
                owner: step.owner.clone(),
                borrowers: Vec::new(),
                generation: step.generation,
                desired: Desired::Running,
                observed: Observed::Unknown,
                retained_data: false,
                cost: receipt.cost,
                last_observed_at: None,
                drift: None,
                spec: step.spec.clone(),
                spec_digest: digest(&step.spec),
            });
            resource.kind = step.kind;
            resource.depends_on = step.requires.clone();
            resource.owner = step.owner.clone();
            resource.runtime_id = receipt.runtime_id.clone();
            resource.generation = step.generation;
            resource.desired = Desired::Running;
            resource.observed = receipt.observed;
            resource.cost = receipt.cost;
            resource.last_observed_at = Some(receipt.at.clone());
            resource.drift = None;
            resource.spec = step.spec.clone();
            resource.spec_digest = digest(&step.spec);
            if let Some(owner) = step.owner.clone() {
                let borrower = Borrower { setup: setup.clone(), resource: step.resource.clone() };
                if let Some(owner_setup) = registry.instances.get_mut(&owner.setup) {
                    if let Some(owned) = owner_setup.resources.get_mut(&owner.resource) {
                        if !owned.borrowers.contains(&borrower) {
                            owned.borrowers.push(borrower);
                        }
                    }
                    // A plan for the owner reviewed before this borrower existed must be reviewed
                    // again. A claimed owner moves on when its own operation finishes.
                    if owner_setup.current_operation.is_none() {
                        owner_setup.revision += 1;
                    }
                }
            }
        }
        Action::Stop => {
            if let Some(resource) = instance.resources.get_mut(&step.resource) {
                resource.desired = Desired::Stopped;
                resource.observed = receipt.observed;
                resource.cost = receipt.cost;
                resource.last_observed_at = Some(receipt.at.clone());
                resource.drift = None;
            }
        }
        Action::Remove => {
            let keep = receipt.retained_data;
            if let Some(resource) = instance.resources.get_mut(&step.resource) {
                if keep {
                    resource.desired = Desired::Absent;
                    // What the step saw: a kept volume is still there with its data (and the
                    // setup is retained because of it); a removed sandbox is gone.
                    resource.observed = if receipt.observed == Observed::Present { Observed::Present } else { Observed::Missing };
                    resource.runtime_id = None;
                    resource.retained_data = true;
                    resource.cost = receipt.cost;
                    resource.last_observed_at = Some(receipt.at.clone());
                } else {
                    instance.resources.remove(&step.resource);
                }
            }
            registry.tombstones.insert(
                key,
                Tombstone { generation: step.generation, operation: operation.to_owned(), at: receipt.at },
            );
        }
        Action::Detach => {
            let owner = instance.resources.remove(&step.resource).and_then(|resource| resource.owner);
            if let Some(owner) = owner.or_else(|| step.owner.clone()) {
                if let Some(owned) = registry
                    .instances
                    .get_mut(&owner.setup)
                    .and_then(|instance| instance.resources.get_mut(&owner.resource))
                {
                    owned.borrowers.retain(|borrower| !(borrower.setup == setup && borrower.resource == step.resource));
                }
            }
        }
    }
}

/// Ends an operation, releases the setup and records what the setup now is.
fn finish(registry: &mut Registry, operation: &str, state: OperationState, error: Option<Diagnostic>) {
    let Some(found) = registry.operations.get_mut(operation) else { return };
    if state == OperationState::Cancelled {
        for step in &mut found.steps {
            if step.state == StepState::Pending {
                step.state = StepState::Cancelled;
            }
        }
    }
    found.set_state(state);
    found.error = error;
    found.event(
        None,
        match state {
            OperationState::Completed => "Finished.",
            OperationState::Cancelled => "Cancelled. Everything already created is still tracked.",
            _ => "Stopped before finishing. Everything already created is still tracked.",
        },
    );
    let (setup, kind, change) = (found.setup.clone(), found.kind, found.change.clone());
    // A removal with nothing left to do is of a setup whose resources were all removed before,
    // keeping their data where it is: the setup itself goes now.
    let only_kept = found.steps.is_empty();
    let at = now();
    let mut removed_setup = false;
    if let Some(instance) = registry.instances.get_mut(&setup) {
        if instance.current_operation.as_deref() == Some(operation) {
            instance.current_operation = None;
        }
        instance.revision += 1;
        instance.updated_at = at.clone();
        match (state, kind) {
            (OperationState::Completed, OperationKind::Create | OperationKind::Update | OperationKind::Repair | OperationKind::Start) => {
                instance.lifecycle = Lifecycle::Running;
                if let (OperationKind::Update, Some(change)) = (kind, change) {
                    instance.name = change.name;
                    instance.source = change.source;
                    instance.format_version = change.format_version;
                    instance.protocol_version = change.protocol_version;
                    instance.lock_digest = change.lock_digest;
                    instance.answers = change.answers;
                    instance.secret_bindings = change.secret_bindings;
                    instance.lock = change.lock;
                    instance.capabilities = change.capabilities;
                    instance.config_revision += 1;
                }
                // The change applied; earlier failure or drift is no longer evidence of anything.
                if matches!(instance.health, Health::Failed | Health::Degraded) {
                    instance.health = Health::Unknown;
                }
            }
            (OperationState::Completed, OperationKind::Stop) => instance.lifecycle = Lifecycle::Stopped,
            (OperationState::Completed, OperationKind::Remove) => {
                if instance.resources.is_empty() || only_kept {
                    instance.lifecycle = Lifecycle::Removed;
                    removed_setup = true;
                } else {
                    instance.lifecycle = Lifecycle::Retained;
                }
            }
            (_, OperationKind::Create) => instance.health = Health::Failed,
            (_, OperationKind::Update | OperationKind::Repair) => {
                instance.lifecycle = Lifecycle::Running;
                instance.health = Health::Degraded;
            }
            (_, OperationKind::Remove) => instance.health = Health::Degraded,
            _ => {}
        }
        if state == OperationState::Completed {
            instance.history.push(HistoryEntry {
                at: at.clone(),
                operation: operation.to_owned(),
                change: kind.as_str().into(),
                source_version: instance.source.version(),
            });
            let excess = instance.history.len().saturating_sub(HISTORY_LIMIT);
            instance.history.drain(..excess);
        }
    }
    if removed_setup {
        // The tombstone alone guards against resurrection; the record no longer counts.
        registry.instances.remove(&setup);
        registry.tombstones.insert(setup, Tombstone { generation: 0, operation: operation.to_owned(), at });
    }
    prune(registry);
}

/// Makes room when the registry reaches its size limit: finished operations keep only their
/// last events, then only the newest few finished operations of each setup remain. Tombstones
/// stay: they are small, and they are what stops a removed setup coming back.
fn shrink(registry: &mut Registry) {
    for operation in registry.operations.values_mut().filter(|operation| operation.state.is_terminal()) {
        let excess = operation.events.len().saturating_sub(10);
        operation.events.drain(..excess);
    }
    let mut finished = registry
        .operations
        .values()
        .filter(|operation| operation.state.is_terminal())
        .map(|operation| (operation.completed_at.clone().unwrap_or_default(), operation.setup.clone(), operation.id.clone()))
        .collect::<Vec<_>>();
    finished.sort();
    finished.reverse();
    let mut kept: HashMap<String, usize> = HashMap::new();
    for (_, setup, id) in finished {
        let count = kept.entry(setup).or_default();
        *count += 1;
        if *count > 4 {
            registry.operations.remove(&id);
        }
    }
}

/// Keeps the journal bounded: old finished operations go first. An operation that holds a setup
/// or whose outcome is unknown is never dropped.
fn prune(registry: &mut Registry) {
    let mut finished = registry
        .operations
        .values()
        .filter(|operation| operation.state.is_terminal())
        .map(|operation| (operation.completed_at.clone().unwrap_or_default(), operation.setup.clone(), operation.id.clone()))
        .collect::<Vec<_>>();
    finished.sort();
    let mut per_setup: HashMap<String, usize> = HashMap::new();
    for (_, setup, _) in &finished {
        *per_setup.entry(setup.clone()).or_default() += 1;
    }
    let mut total = finished.len();
    for (_, setup, id) in finished {
        let count = per_setup.get_mut(&setup).expect("counted above");
        if *count > FINISHED_PER_SETUP || total > FINISHED_TOTAL {
            registry.operations.remove(&id);
            *count -= 1;
            total -= 1;
        }
    }
}

// ----- Review -----

fn review(registry: &Registry, handlers: &Handlers, adopted: &[adopt::Adopted], intent: PlanIntent) -> Result<ReviewedPlan, Diagnostic> {
    let mut notes = Vec::new();
    let (setup_id, kind, base_revision, change, steps) = match intent {
        PlanIntent::Create(draft) => {
            let setup_id = new_id("setup-");
            check_change(&draft.change)?;
            let steps = declared_steps(registry, handlers, adopted, &setup_id, None, &draft.resources, &mut notes)?;
            (setup_id, OperationKind::Create, 0, Some(draft.change), steps)
        }
        PlanIntent::Update { setup, draft } => {
            let instance = live_instance(registry, &setup)?;
            check_change(&draft.change)?;
            let steps = declared_steps(registry, handlers, adopted, &setup, Some(instance), &draft.resources, &mut notes)?;
            // The update as a whole: what is made, changed, left as it is, and what the new
            // version no longer declares (kept with its data, never deleted by an update).
            let of = |action: Action| steps.iter().filter(|step| step.action == action).map(|step| step.resource.clone()).collect::<Vec<_>>();
            let declared = draft.resources.iter().map(|resource| resource.id.clone()).collect::<BTreeSet<_>>();
            let touched = steps.iter().map(|step| step.resource.clone()).collect::<BTreeSet<_>>();
            let same = declared.iter().filter(|id| !touched.contains(*id) && instance.resources.contains_key(*id)).cloned().collect::<Vec<_>>();
            let dropped = instance.resources.keys().filter(|id| !declared.contains(*id)).cloned().collect::<Vec<_>>();
            let mut summary = Vec::new();
            for (label, ids) in [("New", of(Action::Create)), ("Changed", of(Action::Update)), ("Unchanged", same), ("No longer in the template, kept", dropped)] {
                if !ids.is_empty() {
                    summary.push(format!("{label}: {}.", ids.join(", ")));
                }
            }
            if !summary.is_empty() {
                notes.insert(0, summary.join(" "));
            }
            if instance.source.reference != draft.change.source.reference {
                notes.insert(0, format!("The setup moves from {} to {}. Until this change finishes it stays on {}; if it fails, it stays there.", source_words(&instance.source.reference), source_words(&draft.change.source.reference), source_words(&instance.source.reference)));
            }
            (setup, OperationKind::Update, instance.revision, Some(draft.change), steps)
        }
        PlanIntent::Start { setup } => {
            let instance = live_instance(registry, &setup)?;
            let order = dependency_order(instance);
            notes.extend(order.iter().filter_map(|id| instance.resources.get(id)).filter_map(|resource| unmanaged(handlers, resource)));
            let steps = order
                .iter()
                .filter_map(|id| instance.resources.get(id))
                .filter(|resource| !resource.borrowed() && resource.runtime_id.is_some() && resource.desired != Desired::Absent)
                .filter(|resource| {
                    handlers.get(resource.kind).is_ok_and(|handler| {
                        handler.stops(&resource.spec) && (resource.observed != Observed::Running || handler.renews_when_running(&resource.spec))
                    })
                })
                .map(|resource| lifecycle_step(resource, Action::Start))
                .collect::<Vec<_>>();
            (setup, OperationKind::Start, instance.revision, None, forward(steps, instance))
        }
        PlanIntent::Stop { setup } => {
            let instance = live_instance(registry, &setup)?;
            let mut order = dependency_order(instance);
            order.reverse();
            let mut steps = Vec::new();
            for resource in order.iter().filter_map(|id| instance.resources.get(id)) {
                if resource.borrowed() {
                    notes.push(format!("{} is borrowed from another setup. It keeps running for its owner.", resource.id));
                } else if let Some(note) = unmanaged(handlers, resource) {
                    notes.push(note);
                } else if resource.runtime_id.is_some()
                    && resource.desired != Desired::Absent
                    && resource.observed != Observed::Stopped
                    && handlers.get(resource.kind).is_ok_and(|handler| handler.stops(&resource.spec))
                {
                    steps.push(lifecycle_step(resource, Action::Stop));
                }
                if matches!(resource.cost, Cost::Accruing | Cost::Unknown) && !resource.borrowed() {
                    notes.push(format!("{} may still cost money while stopped, for example for its storage.", resource.id));
                }
            }
            (setup, OperationKind::Stop, instance.revision, None, reverse(steps, instance))
        }
        PlanIntent::Remove { setup } => {
            let instance = live_instance(registry, &setup)?;
            let mut order = dependency_order(instance);
            order.reverse();
            let mut steps = Vec::new();
            // What may still be charging, part by part, said after what goes. A borrowed part
            // isn't this setup's to stop, so what it costs is left to its own setup.
            let mut charging = Vec::new();
            let mut left_alone = false;
            for resource in order.iter().filter_map(|id| instance.resources.get(id)) {
                if !resource.borrowers.is_empty() {
                    return Err(in_use(resource));
                }
                if resource.borrowed() {
                    notes.push(format!("{} belongs to another setup. Only this setup's access to it is removed.", resource.id));
                    steps.push(lifecycle_step(resource, Action::Detach));
                } else if let Some(note) = unmanaged(handlers, resource) {
                    // Made by a product this version no longer carries: nothing can be done to
                    // it from here, so it is left where it is and the review says so.
                    notes.push(note);
                    left_alone = true;
                    continue;
                } else if resource.desired != Desired::Absent || resource.runtime_id.is_some() {
                    steps.push(lifecycle_step(resource, Action::Remove));
                    charging.extend(charges_note(resource));
                    // A research worker's model and sandbox go with the worker, which says so.
                    let worker_part = super::grids::research::made_by_worker(resource.kind, &resource.id, instance.resources.values().map(|other| (other.kind, &other.spec)));
                    let said = handlers.get(resource.kind).ok().filter(|_| !worker_part).map(|handler| handler.notes(&setup, &resource.id, &resource.spec, Action::Remove)).unwrap_or_default();
                    if worker_part {
                        continue;
                    }
                    if !said.is_empty() {
                        // The handler says what removing this deletes, and when; nothing generic.
                        notes.extend(said);
                        continue;
                    }
                }
                if resource.retained_data {
                    notes.push(kept_note(&resource.id));
                }
            }
            notes.extend(charging);
            // A grid's removal note says what it deletes and when; data is not simply kept there.
            if steps.is_empty() && left_alone {
                notes.push("Nothing in this setup can be removed from here. This removes the setup from My setups only; everything it made stays where it is, with its data.".into());
            } else if steps.is_empty() && instance.lifecycle == Lifecycle::Retained {
                notes.push("Everything in this setup was already removed. This removes the setup from My setups; what it kept stays where it is.".into());
            } else if !steps.iter().any(|step| step.kind == Kind::Grid) {
                notes.push(DATA_KEPT.into());
            }
            if left_alone {
                notes.push(UNMANAGED_WAYS_OUT.into());
            }
            (setup, OperationKind::Remove, instance.revision, None, reverse(steps, instance))
        }
        PlanIntent::Repair { setup } => {
            let instance = live_instance(registry, &setup)?;
            let order = dependency_order(instance);
            notes.extend(order.iter().filter_map(|id| instance.resources.get(id)).filter_map(|resource| unmanaged(handlers, resource)));
            let steps = order
                .iter()
                .filter_map(|id| instance.resources.get(id))
                .filter(|resource| !resource.borrowed() && resource.observed == Observed::Missing && resource.desired != Desired::Absent)
                .filter(|resource| handlers.get(resource.kind).is_ok())
                .map(|resource| {
                    let mut step = lifecycle_step(resource, Action::Create);
                    step.generation = next_generation(registry, &setup, &resource.id, Some(resource));
                    step
                })
                .collect::<Vec<_>>();
            if steps.is_empty() {
                notes.push("Nothing is missing. Refresh the setup first if something changed outside Yougori.".into());
            }
            (setup, OperationKind::Repair, instance.revision, None, forward(steps, instance))
        }
        PlanIntent::Part { setup, resource, action } => {
            let instance = live_instance(registry, &setup)?;
            let part = instance
                .resources
                .get(&resource)
                .ok_or_else(|| Diagnostic::new("resource_missing", "This setup has no part by that name. Nothing was changed.").resource(&resource))?;
            if !part_actions(handlers, instance, part).contains(&action) {
                return Err(part_refused(handlers, instance, part, action));
            }
            match action {
                Action::Remove => {
                    let said = handlers.get(part.kind).map(|handler| handler.notes(&setup, &part.id, &part.spec, Action::Remove)).unwrap_or_default();
                    if !said.is_empty() {
                        notes.extend(said);
                    } else if part.retained_data {
                        notes.push(kept_note(&part.id));
                    }
                    notes.extend(charges_note(part));
                    notes.push(format!(
                        "Only {} is removed; the rest of the setup is left as it is. It comes back if the setup is updated while its template still includes it.",
                        part.id
                    ));
                }
                Action::Detach => {
                    notes.push(format!("{} belongs to another setup. Only this setup's use of it ends; it stays as it is, with its owner.", part.id));
                }
                _ => {}
            }
            (setup, OperationKind::Update, instance.revision, None, vec![lifecycle_step(part, action)])
        }
    };
    for step in &steps {
        handlers.get(step.kind)?;
    }
    Ok(ReviewedPlan {
        plan_id: String::new(),
        setup_id,
        intent: kind,
        base_revision,
        digest: String::new(),
        steps,
        change,
        notes,
        offered: Vec::new(),
        expires_at: String::new(),
        source_digest: None,
        package: None,
    })
}

/// The other parts of a setup that need `part`, by name: what stops it being removed or
/// detached on its own.
fn needing(instance: &Instance, part: &Resource) -> Vec<String> {
    instance
        .resources
        .values()
        .filter(|other| other.id != part.id && other.desired != Desired::Absent && needs(instance, other).contains(&part.id))
        .map(|other| other.id.clone())
        .collect()
}

/// What may be done to one part of a setup on its own, in the order a person reads them. The
/// setup page offers exactly these (`Service::get`), and a review refuses anything else, so a
/// button is never shown that the engine would turn down.
pub(crate) fn part_actions(handlers: &Handlers, instance: &Instance, part: &Resource) -> Vec<Action> {
    if instance.current_operation.is_some() || !matches!(instance.lifecycle, Lifecycle::Running | Lifecycle::Stopped) {
        return Vec::new();
    }
    let needed = !needing(instance, part).is_empty();
    if part.borrowed() {
        return if needed { Vec::new() } else { vec![Action::Detach] };
    }
    if part.desired == Desired::Absent || unmanaged(handlers, part).is_some() {
        return Vec::new();
    }
    let mut actions = Vec::new();
    if part.runtime_id.is_some() && handlers.get(part.kind).is_ok_and(|handler| handler.stops(&part.spec)) {
        let running = match part.observed {
            Observed::Running => true,
            Observed::Stopped => false,
            _ => part.desired != Desired::Stopped,
        };
        actions.push(if running { Action::Stop } else { Action::Start });
    }
    if !needed && part.borrowers.is_empty() {
        actions.push(Action::Remove);
    }
    actions
}

/// Why `action` can't be taken on `part` on its own, in words a person can act on.
fn part_refused(handlers: &Handlers, instance: &Instance, part: &Resource, action: Action) -> Diagnostic {
    let name = &part.id;
    if !matches!(instance.lifecycle, Lifecycle::Running | Lifecycle::Stopped) {
        return Diagnostic::new("setup_not_ready", format!("{} is not running or stopped right now, so its parts can't be changed one by one. Nothing was changed.", instance.name)).resource(name);
    }
    let needing = needing(instance, part);
    if let Some(note) = unmanaged(handlers, part) {
        return Diagnostic::new("unsupported_resource", format!("{note} {UNMANAGED_WAYS_OUT}")).resource(name);
    }
    match action {
        Action::Remove | Action::Detach if !needing.is_empty() => Diagnostic::new(
            "resource_in_use",
            format!("{} need{} {name}. {} first, or remove the whole setup. Nothing was changed.", needing.join(", "), if needing.len() == 1 { "s" } else { "" }, if action == Action::Remove { "Remove those" } else { "Remove or detach those" }),
        )
        .resource(name),
        Action::Remove if !part.borrowers.is_empty() => in_use(part),
        Action::Remove if part.borrowed() => Diagnostic::new("resource_borrowed", format!("{name} belongs to another setup, so this setup can only detach it, never remove it. Nothing was changed.")).resource(name),
        Action::Detach if !part.borrowed() => Diagnostic::new("invalid_request", format!("{name} is this setup's own; remove it instead of detaching it. Nothing was changed.")).resource(name),
        Action::Start | Action::Stop if part.borrowed() => Diagnostic::new("resource_borrowed", format!("{name} belongs to another setup, which starts and stops it. Nothing was changed.")).resource(name),
        Action::Start | Action::Stop if !handlers.get(part.kind).is_ok_and(|handler| handler.stops(&part.spec)) || part.runtime_id.is_none() => {
            Diagnostic::new("unsupported_here", format!("{name} doesn't run on its own, so it can't be started or stopped. Nothing was changed.")).resource(name)
        }
        Action::Start => Diagnostic::new("nothing_to_do", format!("{name} is already running. Nothing was changed.")).resource(name),
        Action::Stop => Diagnostic::new("nothing_to_do", format!("{name} is already stopped. Nothing was changed.")).resource(name),
        _ => Diagnostic::new("invalid_request", format!("That can't be done to {name} on its own. Nothing was changed.")).resource(name),
    }
}

/// A setup's own part of a kind this engine has no handler for: made by a product this version no
/// longer carries. Nothing of it is ever touched from here, and every review and the setup page
/// say so in this line rather than failing on it or passing over it in silence.
fn unmanaged(handlers: &Handlers, part: &Resource) -> Option<String> {
    if part.borrowed() || handlers.get(part.kind).is_ok() {
        return None;
    }
    Some(format!(
        "{} is a {} resource, which this version of Yougori can no longer manage. It is left exactly as it is, with its data: nothing of it is started, stopped or removed from here.",
        part.id,
        words(part.kind)
    ))
}

/// What a person can still do with a setup that has a part this version can't manage.
const UNMANAGED_WAYS_OUT: &str = "Export the setup's template with yougori template export to keep how it was made, or remove the setup from My setups; what it made stays where it is either way.";

/// A removal review's line for one resource whose data it keeps. `Service::removal_data` says
/// more for a volume, in place of this line.
fn kept_note(resource: &str) -> String {
    format!("The data of {resource} is kept. Deleting it is a separate step.")
}

/// The setup action a change to new work is.
fn admission_action(change: Admission) -> &'static str {
    match change {
        Admission::Pause { .. } => "pause_admission",
        Admission::Resume => "resume_admission",
    }
}

/// What a review of new work covered: the setup as it was, the change, and the parts it named.
fn admission_digest(setup: &str, change: Admission, revision: u64, parts: &[String]) -> String {
    let drain = match change {
        Admission::Pause { drain } => Some(drain),
        Admission::Resume => None,
    };
    digest(&json!({ "setup": setup, "action": admission_action(change), "drain": drain, "revision": revision, "parts": parts }))
}

/// What a release review covered: the setup as it was, the part asked for, and every rented
/// computer it named, so a computer added or gone since means reviewing again.
fn release_digest(setup: &str, resource: Option<&str>, revision: u64, held: &[(StepContext, Value)]) -> String {
    let rented = held
        .iter()
        .map(|(part, said)| json!({ "part": part.resource, "computers": said["computers"].as_array().into_iter().flatten().map(|computer| computer["id"].clone()).collect::<Vec<_>>() }))
        .collect::<Vec<_>>();
    digest(&json!({ "setup": setup, "action": "release_compute", "resource": resource, "revision": revision, "rented": rented }))
}

/// A digest that doesn't match what the review would say now.
fn review_changed(setup: &str) -> Diagnostic {
    Diagnostic::new("plan_changed", "That review is for something else, or this setup has changed since it was made. Review again; nothing was changed.").resource(setup).next(&["plan"])
}

/// A setup's declared outputs, with what rendering them needs.
struct Declared {
    /// The setup's revision when they were read: what is written back only if it still holds.
    revision: u64,
    /// Whether it came from a template package, which is what declares outputs.
    templated: bool,
    outputs: Vec<yougori_setup::format::CheckedOutput>,
    values: yougori_setup::placeholder::Values,
    /// The setup's own parts that exist, ready to be asked.
    parts: Vec<StepContext>,
}

/// An output's key as declared, or made from its label when it has none.
fn output_key(output: &yougori_setup::format::CheckedOutput) -> String {
    output.key.clone().unwrap_or_else(|| output.label.to_lowercase().split(|letter: char| !letter.is_alphanumeric()).filter(|word| !word.is_empty()).collect::<Vec<_>>().join("_"))
}

/// The parts the outputs' values name: each `{{outputs.RESOURCE.NAME}}`'s resource.
fn parts_named(outputs: &[yougori_setup::format::CheckedOutput]) -> BTreeSet<String> {
    use yougori_setup::placeholder::{pieces, Piece, Placeholder};
    outputs
        .iter()
        .filter_map(|output| pieces(&output.value).ok())
        .flatten()
        .filter_map(|piece| match piece {
            Piece::Placeholder(Placeholder::Output(resource, _), _) => Some(resource),
            _ => None,
        })
        .collect()
}

/// An output's value from what is known now, or `None` while any part of it isn't: an output a
/// part hasn't given, an address that isn't public yet, or a secret, which is never an output.
/// Never a stand-in such as "(not ready)".
fn output_value(text: &str, values: &yougori_setup::placeholder::Values) -> Option<String> {
    use yougori_setup::placeholder::{pieces, render, Piece, Placeholder};
    let known = pieces(text).ok()?.iter().all(|piece| match piece {
        Piece::Placeholder(Placeholder::Output(resource, output), _) => values.outputs.get(resource).is_some_and(|given| given.contains_key(output)),
        Piece::Placeholder(Placeholder::Env(name), _) => values.names.contains_key(name),
        Piece::Placeholder(Placeholder::Public(name), _) => values.public.contains_key(name),
        Piece::Placeholder(Placeholder::Secret(_), _) => false,
        _ => true,
    });
    if !known {
        return None;
    }
    render(text, values).ok().map(|value| value.trim().to_owned()).filter(|value| !value.is_empty())
}

/// A removal review's line for one part it takes that may still be charging, from what its
/// provider last said. Free, or stopped as its provider confirmed, needs no line; nothing is ever
/// said to cost nothing without that evidence.
fn charges_note(resource: &Resource) -> Option<String> {
    let id = &resource.id;
    match resource.cost {
        Cost::Free | Cost::Stopped => None,
        Cost::Accruing => Some(format!("{id} is costing money now; the charges stop once its provider confirms it is gone.")),
        Cost::ShutdownUnconfirmed => Some(format!("{id} was asked to stop charging, but its provider hasn't confirmed it; check with its provider after removing it.")),
        Cost::Unknown => Some(format!("Yougori can't tell whether {id} is still charging; check with its provider after removing it.")),
    }
}

/// A removal review's closing line when nothing is offered for deletion.
const DATA_KEPT: &str = "Data is kept by default. Deleting data is a separate step that shows exactly what goes.";

/// Every choice that deletes something starts with this (`delete_data:`, `delete_grid:` …). One
/// is accepted only from the review that offered it.
const DELETION: &str = "delete_";

/// How long deleting a volume's backups waits for a copy of it that is being taken right now,
/// before it fails the step to be tried again.
const BACKUP_WAIT: Duration = Duration::from_secs(30);

/// What a synced folder's last pass said, in the setup's readiness and not only in its notes: the
/// sync capability reads degraded with the folder's own line, and a setup that read ready reads
/// degraded too. A note alone is easy to miss, and readiness has to say what is true. A worse
/// state already shown (failed, waiting for a sign-in) is left as it is; only the line is added.
fn sync_readiness(detail: &mut views::Detail, said: &[String]) {
    if said.is_empty() {
        return;
    }
    let line = said.join(" ");
    for capability in detail.setup.capabilities.iter_mut().filter(|capability| capability.id == "data.sync") {
        if matches!(capability.health, dto::CapabilityHealth::Ready | dto::CapabilityHealth::Starting) {
            capability.health = dto::CapabilityHealth::Degraded;
            capability.detail = Some(line.clone());
        } else if capability.detail.is_none() {
            capability.detail = Some(line.clone());
        }
    }
    if detail.setup.summary.health == Some(dto::CapabilityHealth::Ready) {
        detail.setup.summary.health = Some(dto::CapabilityHealth::Degraded);
    }
}

/// Where a setup's template came from, in words.
fn source_words(source: &dto::SourceRef) -> String {
    match source {
        dto::SourceRef::Hub { publisher, name, version } => format!("{publisher}/{name} {version}"),
        dto::SourceRef::LocalFolder { .. } => "its template folder".to_owned(),
        dto::SourceRef::InstalledSetup { .. } => "its kept template".to_owned(),
    }
}

fn live_instance<'a>(registry: &'a Registry, setup: &str) -> Result<&'a Instance, Diagnostic> {
    if adopt::is_adopted_id(setup) {
        return Err(legacy_managed(setup));
    }
    if !valid_id(setup, "setup-") {
        return Err(not_found(setup));
    }
    if registry.tombstones.contains_key(setup) {
        return Err(removed(setup));
    }
    let instance = registry.instances.get(setup).ok_or_else(|| not_found(setup))?;
    if instance.lifecycle == Lifecycle::Removed {
        return Err(removed(setup));
    }
    if let Some(operation) = instance.current_operation.as_ref().and_then(|id| registry.operations.get(id)) {
        return Err(busy(operation));
    }
    Ok(instance)
}

fn check_change(change: &InstanceChange) -> Result<(), Diagnostic> {
    let name = change.name.trim();
    if name.is_empty() || name.chars().count() > 64 || name.chars().any(char::is_control) {
        return Err(invalid("Give the setup a name of 1 to 64 characters."));
    }
    for (label, value) in [("answers", json!(change.answers))] {
        if let Some(field) = credential_field(&value) {
            return Err(Diagnostic::new(
                "secret_in_plan",
                format!("The {label} include a secret value at {field}. Secrets are given when applying, never saved with the setup."),
            ));
        }
    }
    Ok(())
}

fn next_generation(registry: &Registry, setup: &str, resource: &str, current: Option<&Resource>) -> u64 {
    let removed = registry
        .tombstones
        .get(&format!("{setup}/{resource}"))
        .map(|tombstone| tombstone.generation)
        .unwrap_or(0);
    removed.max(current.map(|resource| resource.generation).unwrap_or(0)) + 1
}

fn declared_steps(
    registry: &Registry,
    handlers: &Handlers,
    adopted: &[adopt::Adopted],
    setup: &str,
    instance: Option<&Instance>,
    declared: &[DeclaredResource],
    notes: &mut Vec<String>,
) -> Result<Vec<PlannedStep>, Diagnostic> {
    if declared.len() > STEP_LIMIT {
        return Err(invalid("This setup declares more resources than Yougori allows in one plan."));
    }
    let mut seen = BTreeSet::new();
    let mut steps = Vec::new();
    let mut grids = Vec::new();
    for resource in declared {
        if !valid_resource_id(&resource.id) {
            return Err(invalid("A resource ID must start with a letter and use only lowercase letters, digits, - and _.").resource(&resource.id));
        }
        if !seen.insert(resource.id.clone()) {
            return Err(invalid("Two resources have the same ID.").resource(&resource.id));
        }
        if let Some(missing) = resource.requires.iter().find(|required| !seen.contains(*required)) {
            return Err(invalid(&format!("{} needs {missing}, which is not declared before it.", resource.id)).resource(&resource.id));
        }
        if serde_json::to_vec(&resource.spec).map(|bytes| bytes.len()).unwrap_or(usize::MAX) > SPEC_LIMIT {
            return Err(invalid("A resource's settings are larger than Yougori allows.").resource(&resource.id));
        }
        if let Some(field) = credential_field(&resource.spec) {
            return Err(Diagnostic::new(
                "secret_in_plan",
                format!("The settings of {} include a secret value at {field}. Use a secret reference instead.", resource.id),
            )
            .resource(&resource.id));
        }
        let current = instance.and_then(|instance| instance.resources.get(&resource.id));
        let action = if resource.owner.is_some() {
            // A binding to another setup's resource: no handler acts and nothing is created.
            owned_by_other(registry, setup, &resource.id, resource.kind, resource.owner.as_ref())?;
            match current {
                Some(existing) if existing.owner == resource.owner => continue,
                Some(existing) if !existing.borrowed() => {
                    return Err(invalid(&format!("{} already exists in this setup; it can't become borrowed. Remove it first.", resource.id)).resource(&resource.id));
                }
                _ => Action::Attach,
            }
        } else {
            let handler = handlers.get(resource.kind).map_err(|diagnostic| diagnostic.resource(&resource.id))?;
            handler
                .validate(&resource.spec)
                .map_err(|error| error.diagnostic().resource(&resource.id))?;
            let others = declared
                .iter()
                .filter(|other| other.id != resource.id && other.owner.is_none())
                .map(|other| (other.id.clone(), (other.kind, other.spec.clone())))
                .collect::<BTreeMap<_, _>>();
            handler
                .review(&resource.id, &resource.spec, &others)
                .map_err(|error| error.diagnostic().resource(&resource.id))?;
            if resource.kind == Kind::Grid {
                grids.push((resource.id.clone(), resource.spec.clone()));
            }
            if current.is_some_and(Resource::borrowed) {
                return Err(invalid(&format!("{} is borrowed in this setup; detach it before creating one of its own.", resource.id)).resource(&resource.id));
            }
            let spec_digest = digest(&resource.spec);
            match handler.plan(current, &resource.spec, &spec_digest).map_err(|error| error.diagnostic().resource(&resource.id))? {
                Planned::Unchanged => continue,
                Planned::Step(action) => {
                    if !super::grids::research::made_by_worker(resource.kind, &resource.id, others.values().map(|(kind, spec)| (*kind, spec))) {
                        notes.extend(handler.notes(setup, &resource.id, &resource.spec, action));
                    }
                    if let (Action::Update, Some(current)) = (action, current) {
                        // The reviewed difference: which settings change, never their secret values.
                        let changed = changed_settings(&current.spec, &resource.spec);
                        if !changed.is_empty() {
                            notes.push(format!("{} changes in place: {}.", resource.id, changed.join(", ")));
                        }
                        notes.extend(handler.change_notes(setup, &resource.id, &current.spec, &resource.spec));
                    }
                    action
                }
            }
        };
        let generation = match (action, current) {
            (Action::Create, _) | (Action::Attach, None) => next_generation(registry, setup, &resource.id, current),
            (_, Some(existing)) => existing.generation,
            (_, None) => 1,
        };
        steps.push(PlannedStep {
            id: resource.id.clone(),
            resource: resource.id.clone(),
            kind: resource.kind,
            action,
            depends_on: Vec::new(),
            requires: resource.requires.clone(),
            spec: resource.spec.clone(),
            generation,
            owner: resource.owner.clone(),
        });
    }
    one_grid_per_profile(registry, adopted, setup, &grids)?;
    one_owner_per_instance(registry, setup, &grids)?;
    if let Some(instance) = instance {
        for kept in instance.resources.keys().filter(|id| !seen.contains(*id)) {
            notes.push(format!("{kept} is no longer in the template. It is kept, with its data; remove it separately if you no longer need it."));
        }
    }
    let planned = steps.iter().map(|step| step.id.clone()).collect::<BTreeSet<_>>();
    for step in &mut steps {
        step.depends_on = step.requires.iter().filter(|id| planned.contains(*id)).cloned().collect();
    }
    Ok(steps)
}

/// The top-level settings that differ between two specifications, in words.
fn changed_settings(before: &Value, after: &Value) -> Vec<String> {
    let empty = serde_json::Map::new();
    let (before, after) = (before.as_object().unwrap_or(&empty), after.as_object().unwrap_or(&empty));
    let mut keys = before.keys().chain(after.keys()).collect::<Vec<_>>();
    keys.sort();
    keys.dedup();
    keys.into_iter().filter(|key| before.get(*key) != after.get(*key)).map(|key| key.replace('_', " ")).collect()
}

/// What a grid resource holds on this computer, each of which exists once per computer in this
/// version: the profile's hub, this computer's membership (`member`), and a person's sign-in
/// (`person`). A grid made here holds its hub and the membership the product gives the hub's
/// own computer; an Access Grid's is the sign-in of its first administrator.
fn grid_slots(spec: &Value) -> Vec<(String, &'static str)> {
    let Some(profile) = spec.get("profile").and_then(Value::as_str) else { return Vec::new() };
    let joins = spec.get("mode").and_then(Value::as_str) == Some("join");
    let person = spec.get("member").and_then(Value::as_str) == Some("person");
    let slots: &[&'static str] = match (profile, joins, person) {
        (_, false, _) => &["hub", "member"],
        ("access_grid", true, _) | (_, true, false) => &["member"],
        (_, true, true) => &["person"],
    };
    slots.iter().map(|slot| (profile.to_owned(), *slot)).collect()
}

/// One hub, one membership and one sign-in per computer for a grid profile whose product keeps a
/// single grid of its kind (Swarm Mining). Counts what setups hold, what an operation that hasn't
/// finished (or whose outcome is unknown) is making, a second one in the same plan, and the legacy
/// product's own records. `declared` is the plan's own grids by resource ID; a grid is never
/// compared with itself. A Neo, Sandbox or Access Grid gets an instance of its own instead
/// (`one_owner_per_instance`).
fn one_grid_per_profile(registry: &Registry, adopted: &[adopt::Adopted], setup: &str, declared: &[(String, Value)]) -> Result<(), Diagnostic> {
    let owned = owned_grids(registry);
    let mut planned = BTreeSet::new();
    for (resource, spec) in declared {
        if spec.get("profile").and_then(Value::as_str).is_some_and(instanced) {
            continue;
        }
        for slot in grid_slots(spec) {
            let other = |owner: &str, id: &str| !(owner == setup && id == resource);
            let twice = !planned.insert(slot.clone());
            let existing = registry.instances.values().filter(|instance| instance.lifecycle != Lifecycle::Removed).any(|instance| {
                instance.resources.values().any(|found| {
                    found.kind == Kind::Grid && !found.borrowed() && found.desired != Desired::Absent && grid_slots(&found.spec).contains(&slot) && other(&instance.id, &found.id)
                })
            });
            let in_flight = registry.operations.values().filter(|operation| !operation.state.is_terminal()).any(|operation| {
                operation.steps.iter().any(|step| {
                    step.kind == Kind::Grid
                        && step.owner.is_none()
                        && matches!(step.action, Action::Create | Action::Update)
                        && grid_slots(&step.spec).contains(&slot)
                        && other(&operation.setup, &step.resource)
                })
            });
            // What a setup made leaves the product's own record behind; that record is the setup's.
            // A grid being adopted is that record.
            let adopting = spec.get("adopted").and_then(Value::as_bool) == Some(true);
            let legacy = !adopting && !owned.iter().any(|(profile, role, _)| *profile == slot.0 && *role == slot.1) && adopted.iter().any(|record| record.profile.id() == slot.0 && record.role == slot.1);
            if twice || existing || in_flight || legacy {
                let name = match slot.0.as_str() {
                    "neo_grid" => "Neo Grid",
                    "sandbox_grid" => "Sandbox Grid",
                    "access_grid" => "Access Grid",
                    "swarm_mining_grid" => "Swarm Mining Grid",
                    _ => "grid of this kind",
                };
                // Each grid's hub keys, listener and saved membership still have fixed names on
                // this computer (plan 19.1, docs/template-platform/singleton-ledger.md), so a
                // second one would overwrite the first.
                let message = match (slot.1, slot.0.as_str()) {
                    ("hub", _) => format!("Unsupported here: one {name} per computer in this version. Manage or adopt the existing one instead. Nothing was changed."),
                    ("member", "access_grid") | ("person", _) => format!("Unsupported here: someone is already signed in to a {name} on this computer, or a setup is signing in. This setup won't replace that sign-in; sign out from the grid in My setups first. Nothing was changed."),
                    _ => format!("Unsupported here: this computer is already in a {name}, or a setup is joining one. This setup won't take over that membership; leave it from its own tab in My setups first, or adopt it. Nothing was changed."),
                };
                return Err(Diagnostic::new("unsupported_here", message).resource(resource));
            }
        }
    }
    Ok(())
}

/// The grid records this computer's setups hold, as the products lay them out: profile, role
/// (`hub`, `member`, `person`, and `desks` for the desks a Sandbox Grid computer hosts) and the
/// product instance they are in. A grid whose instance isn't known yet (made by an operation that
/// hasn't recorded it) holds none: its product gives it a free one.
fn owned_grids(registry: &Registry) -> BTreeSet<(String, &'static str, String)> {
    let mut owned = BTreeSet::new();
    let held = registry
        .instances
        .values()
        .filter(|instance| instance.lifecycle != Lifecycle::Removed)
        .flat_map(|instance| instance.resources.values())
        .filter(|resource| resource.kind == Kind::Grid && !resource.borrowed() && resource.desired != Desired::Absent);
    for resource in held {
        let Some(key) = grid_instance(&resource.spec, resource.runtime_id.as_deref()) else { continue };
        for (profile, role) in grid_slots(&resource.spec) {
            if profile == "sandbox_grid" && role == "member" {
                owned.insert((profile.clone(), "desks", key.clone()));
            }
            owned.insert((profile, role, key.clone()));
        }
    }
    owned
}

/// Grid profiles whose products keep each grid in an instance of its own, so several grids of a
/// kind can share a computer.
fn instanced(profile: &str) -> bool {
    matches!(profile, "neo_grid" | "sandbox_grid" | "access_grid")
}

/// The product instance a grid resource holds, once known: for a hub adopted into a setup, the one
/// its review named (`instance`, the first when it names none); for any other grid, the one its
/// record names (`ID@KEY`, the first when it names none). `None` for a grid not made yet.
fn grid_instance(spec: &Value, runtime_id: Option<&str>) -> Option<String> {
    if spec.get("adopted").and_then(Value::as_bool) == Some(true) {
        return Some(spec.get("instance").and_then(Value::as_str).unwrap_or(super::grids::FIRST).to_owned());
    }
    runtime_id.map(|record| super::grids::located(record).1.to_owned())
}

/// A Neo, Sandbox or Access Grid's instance is held by one setup at a time. A grid made, joined or
/// signed in to gets a free instance from its product when it is applied, so it never collides
/// here; one that names its instance, a hub being adopted, must not already be held: by another
/// setup's grid, by an operation that hasn't finished adopting it, or twice in one plan.
fn one_owner_per_instance(registry: &Registry, setup: &str, declared: &[(String, Value)]) -> Result<(), Diagnostic> {
    let mut planned = BTreeSet::new();
    for (resource, spec) in declared {
        let Some(profile) = spec.get("profile").and_then(Value::as_str).filter(|profile| instanced(profile)) else { continue };
        let Some(key) = grid_instance(spec, None) else { continue };
        let other = |owner: &str, id: &str| !(owner == setup && id == resource);
        let same = |found: &Value, runtime_id: Option<&str>| found.get("profile").and_then(Value::as_str) == Some(profile) && grid_instance(found, runtime_id).as_deref() == Some(key.as_str());
        let twice = !planned.insert((profile, key.clone()));
        let held = registry.instances.values().filter(|instance| instance.lifecycle != Lifecycle::Removed).any(|instance| {
            instance.resources.values().any(|found| {
                found.kind == Kind::Grid && !found.borrowed() && found.desired != Desired::Absent && other(&instance.id, &found.id) && same(&found.spec, found.runtime_id.as_deref())
            })
        });
        let in_flight = registry.operations.values().filter(|operation| !operation.state.is_terminal()).any(|operation| {
            operation.steps.iter().any(|step| {
                step.kind == Kind::Grid && step.owner.is_none() && matches!(step.action, Action::Create | Action::Update) && other(&operation.setup, &step.resource) && same(&step.spec, None)
            })
        });
        if twice || held || in_flight {
            let name = match profile {
                "neo_grid" => "Neo Grid",
                "sandbox_grid" => "Sandbox Grid",
                _ => "Access Grid",
            };
            return Err(Diagnostic::new(
                "unsupported_here",
                format!("Unsupported here: that {name} already belongs to a setup on this computer. A grid is held by one setup at a time; manage it from that setup in My setups. Nothing was changed."),
            )
            .resource(resource));
        }
    }
    Ok(())
}

/// The resource another setup owns that `resource` would borrow: it must exist, be that setup's
/// own, be of the same kind, and its setup must not be in the middle of a change.
fn owned_by_other<'a>(registry: &'a Registry, setup: &str, resource: &str, kind: Kind, owner: Option<&OwnerRef>) -> Result<&'a Resource, Diagnostic> {
    let missing = || {
        Diagnostic::new("borrowed_resource_missing", format!("{resource} points at a resource of another setup that is not there."))
            .resource(resource)
    };
    let owner = owner.ok_or_else(missing)?;
    if owner.setup == setup || registry.tombstones.contains_key(&owner.setup) {
        return Err(missing());
    }
    let owner_setup = registry
        .instances
        .get(&owner.setup)
        .filter(|instance| !matches!(instance.lifecycle, Lifecycle::Removed | Lifecycle::Removing))
        .ok_or_else(missing)?;
    if owner_setup.current_operation.is_some() {
        return Err(Diagnostic::new(
            "owner_busy",
            format!("The setup that owns what {resource} borrows is in the middle of a change. Try again when it has finished."),
        )
        .resource(resource)
        .retryable());
    }
    let owned = owner_setup
        .resources
        .get(&owner.resource)
        .filter(|owned| !owned.borrowed() && owned.desired != Desired::Absent)
        .ok_or_else(missing)?;
    if owned.kind != kind {
        return Err(invalid(&format!("{resource} borrows a resource of a different kind.")).resource(resource));
    }
    Ok(owned)
}

fn in_use(resource: &Resource) -> Diagnostic {
    Diagnostic::new(
        "resource_in_use",
        format!(
            "{} is used by {} other setup{}. Remove those setups, or detach them from it, before removing this one.",
            resource.id,
            resource.borrowers.len(),
            if resource.borrowers.len() == 1 { "" } else { "s" }
        ),
    )
    .resource(&resource.id)
}

fn lifecycle_step(resource: &Resource, action: Action) -> PlannedStep {
    PlannedStep {
        id: resource.id.clone(),
        resource: resource.id.clone(),
        kind: resource.kind,
        action,
        depends_on: Vec::new(),
        requires: resource.depends_on.clone(),
        spec: resource.spec.clone(),
        generation: resource.generation,
        owner: resource.owner.clone(),
    }
}

/// Resource IDs with each one after everything it needs.
/// What `resource` needs in its setup: its recorded dependencies, and the setup's own volumes it
/// mounts by name. A setup recorded before the planner counted mounts as dependencies has no edge
/// from a sandbox to its volume; reading the mount here keeps such a setup removing the sandbox
/// before the volume it holds, rather than failing to delete a volume still in use.
fn needs(instance: &Instance, resource: &Resource) -> BTreeSet<String> {
    let mut needed: BTreeSet<String> = resource.depends_on.iter().cloned().collect();
    match resource.kind {
        Kind::Environment => needed.extend(mounted(resource).filter(|source| *source != resource.id && instance.resources.get(*source).is_some_and(|other| other.kind == Kind::Volume)).map(str::to_owned).collect::<Vec<_>>()),
        // The sandbox a volume is backed up through mounts it, so the volume does not wait for it
        // (an earlier planner recorded that edge from `backup_through`).
        Kind::Volume => needed.retain(|id| !instance.resources.get(id).is_some_and(|other| other.kind == Kind::Environment && mounted(other).any(|source| source == resource.id))),
        _ => {}
    }
    needed
}

/// The volumes an environment's recorded spec mounts by name; a `bind` mount names a folder.
fn mounted(resource: &Resource) -> impl Iterator<Item = &str> {
    resource.spec["volumes"].as_array().into_iter().flatten().filter(|mount| mount["bind"] != true).filter_map(|mount| mount["source"].as_str())
}

fn dependency_order(instance: &Instance) -> Vec<String> {
    let mut order = Vec::new();
    let mut placed = BTreeSet::new();
    let mut remaining = instance.resources.keys().cloned().collect::<Vec<_>>();
    while !remaining.is_empty() {
        let before = remaining.len();
        remaining.retain(|id| {
            let ready = needs(instance, &instance.resources[id])
                .iter()
                .all(|dependency| placed.contains(dependency) || !instance.resources.contains_key(dependency));
            if ready {
                placed.insert(id.clone());
                order.push(id.clone());
            }
            !ready
        });
        if remaining.len() == before {
            // A cycle cannot come from a reviewed plan; keep the rest in ID order.
            order.append(&mut remaining);
        }
    }
    order
}

/// Start-type steps wait for the planned steps of what they need.
fn forward(mut steps: Vec<PlannedStep>, instance: &Instance) -> Vec<PlannedStep> {
    let planned = steps.iter().map(|step| step.id.clone()).collect::<BTreeSet<_>>();
    for step in &mut steps {
        step.depends_on = instance
            .resources
            .get(&step.resource)
            .map(|resource| needs(instance, resource).into_iter().filter(|id| planned.contains(id)).collect())
            .unwrap_or_default();
    }
    steps
}

/// The waits of a stop or removal's steps by the rule [`reverse`] plans them with: each step
/// waits for the steps of this operation whose parts need its part.
fn teardown_waits(steps: &[super::journal::Step], instance: &Instance) -> BTreeMap<String, Vec<String>> {
    steps
        .iter()
        .map(|step| {
            let waits = steps
                .iter()
                .filter(|other| other.id != step.id && instance.resources.get(&other.resource).is_some_and(|part| needs(instance, part).contains(&step.resource)))
                .map(|other| other.id.clone())
                .collect();
            (step.id.clone(), waits)
        })
        .collect()
}

/// Stop-type steps wait for the planned steps of everything that needs them.
fn reverse(mut steps: Vec<PlannedStep>, instance: &Instance) -> Vec<PlannedStep> {
    let planned = steps.iter().map(|step| step.id.clone()).collect::<BTreeSet<_>>();
    for step in &mut steps {
        step.depends_on = instance
            .resources
            .values()
            .filter(|other| planned.contains(&other.id) && needs(instance, other).contains(&step.resource))
            .map(|other| other.id.clone())
            .collect();
    }
    steps
}

#[cfg(test)]
#[path = "lifecycle_tests.rs"]
mod lifecycle_tests;
