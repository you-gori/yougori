//! Grid Core: what every grid is made of, whatever it is for.
//!
//! One realm is one trust boundary. Inside it there are people and services, the computers they
//! act from, the computers that offer resources, the work that runs, and a record of everything
//! that was decided. A company's realm may serve models, host workspaces and broker credentials;
//! authorised research runs in a realm of its own, built from this same code but holding its own
//! keys, its own data and its own permissions.
//!
//! The realm lives in a database of its own, one change per transaction. Permissions handed to
//! work are checked against what is true at the moment they are used, not only when they were
//! issued, so withdrawing trust from an account or a computer takes effect at once.
//!
//! One realm is one database on one computer, and that is not a high-availability design. There is
//! no replication, no leader election, no failover and no second copy of a realm serving at the
//! same time: one connection, one writer, and a history that is a single sealed sequence which two
//! writers cannot both be at the end of. `docs/grid-core/operations.md` says what each of the ways
//! out would cost. Nothing here should ever be worded as though a realm were more available than
//! that.
//!
//! The products keep their own hubs while this is built; nothing here replaces them yet. See
//! `docs/grid-core/0001-architecture.md`.
pub mod approval;
pub mod audit;
/// Making a request with a credential the workload never sees (see docs/grid-core/plan.md).
pub mod broker;
pub mod capability;
pub mod compat;
/// The one way a grid reaches a system somebody else runs (see docs/grid-core/adapters.md).
pub mod connector;
pub mod credential;
/// Getting a realm's sealed history off this computer (see docs/grid-core/adapters.md).
pub mod export;
/// What a computer can report about itself, and what that is worth (see docs/grid-core/adapters.md).
pub mod hardware;
pub mod health;
pub mod identity;
/// How large a grid is supported to get, and what sets each number.
pub mod limits;
/// What a realm can say about itself, taken from its own database.
pub mod metrics;
/// The short-lived credentials the broker makes from a long-lived value, and where it keeps them.
pub mod mint;
pub mod model;
/// Names a person can read aloud, for the things a person has to refer to.
pub mod name;
pub mod realm;
/// Authorised research in a realm of its own (see docs/grid-core/plan.md).
pub mod research;
pub mod store;
/// The slow work, kept off everybody's request path (see docs/grid-core/operations.md).
pub mod upkeep;
/// Where a secret actually is, and the one way the broker reads it.
pub mod vault;
pub mod work;
pub mod workspace;

use approval::{Allowance, Approval, Verdict};
use audit::{Decision, Entry};
use capability::{Attempt, Authority, Claims};
use credential::{Credential, Grant};
use identity::{Action, Device, Principal, PrincipalKind, Role};
use model::{ModelAssignment, ModelPlan, Target};
use realm::{Capability, Lifecycle, Realm, RealmKind};
use std::path::{Path, PathBuf};
use store::{KeyReference, Permission, Record, Store};
use work::{Commitment, Host, Lease, Resources, Stage, Workload};
use workspace::{Access, Artifact, ArtifactStore, Assignment, Claim, Condition, Data, Image, Pledge, Quota, Report, Reported, Session, Workspace, WorkspaceState};

/// What a computer is told when it tries to report a packed copy through the ordinary door. What
/// it has to tell the realm is a key, a size and a checksum, so parking has a door of its own.
const PARKING: &str = "A computer that packed a workspace's data records it with its key and its checksum";

/// A realm, open, with everything it holds. One of these per realm; a research realm is another
/// instance with its own key and its own database, never a part of this one.
pub struct Core {
    store: Store,
    /// The realm as it was last read. Everything else is read from the database as it is needed.
    realm: Realm,
    authority: Authority,
    /// The realm's key: it signs permissions and seals the history. Held here only while the
    /// realm is open; it belongs in the operating system's vault.
    key: String,
    /// The typed command being run, by its readable name. Every event written while this is set
    /// carries it, so one command and everything it caused read as one thing.
    command: Option<String>,
}

impl std::fmt::Debug for Core {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the key, and never what the realm holds.
        formatter.debug_struct("Core").field("realm", &self.realm.id).field("kind", &self.realm.kind).finish()
    }
}

impl Core {
    /// Starts a new realm. The key is the caller's to store in the operating system's vault; only
    /// a check value derived from it is written to the database.
    pub fn create(path: &Path, name: &str, kind: RealmKind, capabilities: &[Capability], key: &str, now: i64) -> Result<Core, String> {
        if !crate::is_token(key) {
            return Err("A grid's key is 64 hexadecimal characters".into());
        }
        let realm = Realm::new(name, kind, capabilities, key, now)?;
        let reference = KeyReference::for_realm(&realm.id);
        let store = Store::create(path, &realm, &reference, now)?;
        let authority = Authority::new(&realm.id, key);
        let core = Core { store, realm, authority, key: key.to_owned(), command: None };
        let opened = Entry::new(&core.realm.id, "owner", "realm.created", Decision::Allowed).because(&format!(
            "{} realm: {}",
            if kind == RealmKind::Primary { "company" } else { "research" },
            core.realm.capabilities.iter().map(|capability| capability.name()).collect::<Vec<_>>().join(", ")
        ));
        core.note(opened, now)?;
        Ok(core)
    }

    /// Opens a realm already on this computer, with its key. A realm written by an earlier build,
    /// as one record in a file, is brought into a database first and the record kept beside it.
    pub fn open(path: &Path, key: &str) -> Result<Core, String> {
        let database = Core::database_for(path, key)?;
        let store = Store::open(&database)?;
        let realm = store.realm()?;
        if !realm.keyed_by(key) {
            return Err("That is not this grid's key".into());
        }
        let authority = Authority::new(&realm.id, key);
        Ok(Core { store, realm, authority, key: key.to_owned(), command: None })
    }

    /// Which file actually holds this realm, bringing an older record across if that is what the
    /// caller named. The original is kept beside the database, under the version it was written
    /// in, so a migration can be undone by hand.
    /// Where a realm's database is, for a path that may name either it or an older record.
    fn database_path(path: &Path) -> PathBuf {
        if path.extension().is_some_and(|extension| extension == "db") {
            path.to_owned()
        } else {
            path.with_extension("db")
        }
    }

    /// What opening an older record would bring across, without writing anything at all. The key
    /// and the history are checked here exactly as they would be, so a rehearsal that passes is
    /// a migration that will run.
    pub fn rehearse(path: &Path, key: &str) -> Result<store::legacy::Rehearsal, String> {
        store::legacy::rehearse(path, key, &Core::database_path(path))
    }

    fn database_for(path: &Path, key: &str) -> Result<PathBuf, String> {
        let database = Core::database_path(path);
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(_) if database.exists() => return Ok(database),
            Err(error) => return Err(format!("Cannot read the grid: {error}")),
        };
        if store::legacy::is_database(&bytes) {
            return Ok(path.to_owned());
        }
        if database.exists() {
            // The database was built from this record already; the record is what it was built
            // from, and the database is what the realm is now.
            return Ok(database);
        }
        let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| "The grid's record is damaged".to_owned())?;
        let found = store::legacy::found_version(&value);
        let record = store::legacy::read(&bytes)?;
        if !record.realm.keyed_by(key) {
            return Err("That is not this grid's key".into());
        }
        record.audit.verify(key).map_err(|error| format!("This record's history does not verify: {error}"))?;
        let reference = KeyReference::for_realm(&record.realm.id);
        Store::import(&database, &record, &reference, crate::now())?;
        // Only once the database holds it all is the record moved aside.
        let kept = path.with_extension(format!("v{found}.backup"));
        std::fs::rename(path, &kept).map_err(|error| format!("Cannot keep the record that was migrated: {error}"))?;
        Ok(database)
    }

    pub fn realm(&self) -> &Realm {
        &self.realm
    }

    pub fn path(&self) -> &Path {
        self.store.path()
    }

    /// The realm's database, for the tests that have to look at a row no door returns.
    ///
    /// A property test asks things like whether a generation ever fell and whether a permission
    /// is still unspent, and neither has a reason to be a public method. This is `cfg(test)` so
    /// it cannot become one by accident.
    #[cfg(test)]
    pub(crate) fn store_for_tests(&self) -> &Store {
        &self.store
    }

    /// Which vault entry holds this realm's key, and which version of it.
    pub fn key_reference(&self) -> Result<KeyReference, String> {
        self.store.key_reference()
    }

    /// Everything the realm holds, in the portable shape. This is what a backup carries and what
    /// an admin view reads.
    ///
    /// It is a whole-realm read, and it is named so that it reads like one. There used to be a
    /// `record()` beside it that did the same thing behind a getter's name and panicked when the
    /// database would not answer, and both halves of that were wrong: a scan behind a name like a
    /// getter is how a scan ends up on somebody's request path, and a getter that panics is how a
    /// realm whose disk has gone takes the process with it. Ask for the thing wanted, or
    /// `counts()` where the answer is a number.
    pub fn snapshot(&self) -> Result<Record, String> {
        self.store.snapshot()
    }

    /// Writes one event, sealed with the realm's key.
    ///
    /// Every event in a realm goes through here, so this is where the redaction gate sits: a
    /// reason that looks like a value is replaced with a fixed phrase. It is here rather than in
    /// the broker because an audit reason anywhere in the realm must not be able to carry one,
    /// not only the broker's.
    fn note(&self, entry: Entry, now: i64) -> Result<(), String> {
        let version = self.store.policy_version()?;
        let mut entry = entry.safe().under(version);
        if entry.command.is_none() {
            entry.command = self.command.clone();
        }
        self.store.append_event(entry, now, &self.key)?;
        Ok(())
    }

    /// Runs `work` as one named command, so every event it causes carries that name.
    ///
    /// Threading the name through the fifty signatures between here and the thing that writes
    /// the event would be worse than holding it for the length of the call, and this reads the
    /// way it behaves: inside `during`, the realm is doing that one command.
    pub fn during<T>(&mut self, command: &str, work: impl FnOnce(&mut Core) -> T) -> T {
        let previous = self.command.replace(command.to_owned());
        let result = work(self);
        self.command = previous;
        result
    }

    /// Which command the realm is in the middle of, if any.
    pub fn command(&self) -> Option<&str> {
        self.command.as_deref()
    }

    /// Which events one typed command caused, by sequence, in the order they were written.
    pub fn recorded_for(&self, command: &str) -> Result<Vec<u64>, String> {
        self.store.events_for_command(command)
    }

    /// Everything one typed command caused, in full.
    pub fn history_for(&self, command: &str) -> Result<Vec<audit::Event>, String> {
        Ok(self.store.chain()?.under(command).into_iter().cloned().collect())
    }

    // ---- People and computers ----

    /// Adds a person or a service to this realm.
    pub fn add_principal(&mut self, by: &str, kind: PrincipalKind, name: &str, roles: &[Role], now: i64) -> Result<Principal, String> {
        self.allowed(by, Action::ManagePeople)?;
        if self.store.people_count()? >= limits::MAX_PEOPLE {
            return Err(limits::reached("people", limits::MAX_PEOPLE));
        }
        let principal = Principal::new(&self.realm.id, kind, name, roles, now)?;
        self.store.add_principal(&principal, by, now)?;
        self.note(Entry::new(&self.realm.id, by, "principal.added", Decision::Allowed).because(&principal.name), now)?;
        self.store.principal(&principal.id)?.ok_or_else(|| "The person was not written".to_owned())
    }

    /// One person or service, as they are now.
    pub fn principal(&self, id: &str) -> Result<Option<Principal>, String> {
        self.store.principal(id)
    }

    /// Everything someone holds, and which role each of it came with.
    pub fn permissions(&self, principal_id: &str) -> Result<Vec<Permission>, String> {
        self.store.permissions(principal_id)
    }

    /// Gives someone another permission, and whatever that one brings with it.
    pub fn grant(&mut self, by: &str, principal_id: &str, role: Role, now: i64) -> Result<(), String> {
        self.allowed(by, Action::ManagePeople)?;
        self.person(principal_id)?;
        self.store.grant(principal_id, role, by, now)?;
        self.note(Entry::new(&self.realm.id, by, "principal.granted", Decision::Allowed).because(role.name()), now)
    }

    /// Takes a permission away, with anything that only came with it.
    ///
    /// Taking away the permission to be in a workspace has to reach the sign-ins somebody is
    /// already holding, not only the next one they ask for. Nothing re-reads a person's roles at
    /// the moment a permission is used, so their workspaces move on a generation and their
    /// sign-ins close, which is the push a suspension gives. A withdrawal that leaves them able
    /// to use a workspace, such as taking back the auditor's role, throws nobody out of a desk.
    pub fn withdraw(&mut self, by: &str, principal_id: &str, role: Role, now: i64) -> Result<(), String> {
        self.allowed(by, Action::ManagePeople)?;
        self.store.withdraw(principal_id, role)?;
        if !self.store.principal(principal_id)?.is_some_and(|person| person.may(Action::UseWorkspace)) {
            for workspace in self.store.workspaces_owned_by(principal_id)?.into_iter().filter(|workspace| !workspace.state.finished()) {
                self.store.end_sessions(&workspace.id, "the permission to use a workspace was taken away", now)?;
                self.store.raise_workspace_generation(&workspace.id, now)?;
            }
        }
        self.note(Entry::new(&self.realm.id, by, "principal.withdrawn", Decision::Allowed).because(role.name()), now)
    }

    /// Suspends an account. Everything it holds stops at once, because its generation moves on
    /// and a permission issued under the older one is refused when it is next used.
    pub fn suspend_principal(&mut self, by: &str, principal_id: &str, reason: &str, now: i64) -> Result<(), String> {
        self.allowed(by, Action::ManagePeople)?;
        self.store.suspend_principal(principal_id, by, reason, now)?;
        for work in self.store.unfinished_of(principal_id)? {
            // A workspace is not work this person placed; it is the grid hosting their desk, and
            // the desk stays on its computer with its data. Suspending somebody stops them, and
            // what stops them is that their sign-ins close and nothing they hold is accepted.
            if work.note.as_deref().is_some_and(|note| note.starts_with("workspace:")) {
                continue;
            }
            // Work that is finishing up finishes; everything else stops through the one cancel.
            if work.stage.may_become(Stage::Cancelled) {
                self.stop_work(by, work, "the account was suspended", now)?;
            }
        }
        // Their workspaces move on a generation and their sign-ins close, so being refused does
        // not wait for them to present a permission. The workspaces themselves keep running, and
        // keep their owner: suspending somebody is not deleting their desk.
        for workspace in self.store.workspaces_owned_by(principal_id)?.into_iter().filter(|workspace| !workspace.state.finished()) {
            self.store.end_sessions(&workspace.id, "the account was suspended", now)?;
            self.store.raise_workspace_generation(&workspace.id, now)?;
        }
        self.note(Entry::new(&self.realm.id, by, "principal.suspended", Decision::Allowed).because(reason), now)
    }

    /// Enrols a computer for a person, and returns the secret it must keep.
    pub fn enrol_device(&mut self, principal_id: &str, name: &str, platform: &str, now: i64) -> Result<(Device, String), String> {
        let person = self.person(principal_id)?;
        if !person.active() {
            return Err("This account is suspended".into());
        }
        if self.store.device_count()? >= limits::MAX_DEVICES {
            return Err(limits::reached("computers", limits::MAX_DEVICES));
        }
        let (device, secret) = Device::enrol(&self.realm.id, principal_id, name, platform, now)?;
        self.store.enrol_device(&device)?;
        self.note(Entry::new(&self.realm.id, principal_id, "device.enrolled", Decision::Allowed).from(&device.id).because(&device.name), now)?;
        Ok((device, secret))
    }

    /// Takes a computer out of the realm. Anything it holds stops working at once.
    pub fn revoke_device(&mut self, by: &str, device_id: &str, now: i64) -> Result<(), String> {
        self.allowed(by, Action::RevokeDevice)?;
        self.store.revoke_device(device_id, by, "taken out of the grid", now)?;
        // Whatever it was offering to the realm stops taking work.
        let offered: Vec<String> = self.store.hosts_of_device(device_id)?;
        for host in &offered {
            self.store.set_draining(host, true)?;
            // A workspace on a computer that has left keeps its owner and its trail, and waits
            // for another computer where its data can still be found.
            self.workspaces_off(by, host, "the computer was taken out of the grid", now)?;
        }
        // Its reservations go back, and its unfinished work is cancelled rather than left running.
        for work in self.store.unfinished_on(device_id)? {
            if work.stage.may_become(Stage::Cancelled) {
                self.stop_work(by, work, "the computer was taken out of the grid", now)?;
            }
        }
        // Work that was running on this computer for somebody else goes back the same way any
        // other failed attempt does, so a model request moves to another computer in its plan
        // instead of waiting out a reservation on a computer that has gone.
        for host in &offered {
            for lease in self.store.leases_on(host)? {
                if let Some(work) = self.store.workload(&lease.workload_id)?.filter(|work| !work.stage.finished()) {
                    self.after_trouble(work, work::Setback::LeftTheGrid, now)?;
                }
            }
        }
        // A computer that has left belongs to no plan that picked it, and a plan left with no
        // computers goes rather than sitting there able to place nothing.
        let mut plans = self.store.model_plans()?;
        for host in &offered {
            model::forget_host(&mut plans, host);
        }
        let assignments = model::reconcile(&plans, &self.store.hosts()?, &self.store.devices()?, &self.store.model_assignments()?, now);
        self.store.replace_model_state(&plans, &assignments)?;
        self.note(Entry::new(&self.realm.id, by, "device.revoked", Decision::Allowed).from(device_id), now)
    }

    /// Who is presenting this computer's secret, if it still belongs here. A revoked computer, or
    /// one whose person is suspended, is refused however valid its secret.
    pub fn authenticate(&self, device_id: &str, secret: &str, now: i64) -> Result<(Principal, Device), String> {
        let device = self.store.device(device_id)?.ok_or("This computer is not in this grid")?;
        if !device.holds(secret) {
            return Err("This computer is not in this grid".into());
        }
        if !device.active() {
            return Err("This computer was removed from the grid".into());
        }
        let person = self.store.principal(&device.principal_id)?.ok_or("This account is no longer in this grid")?;
        if !person.active() {
            return Err("This account is suspended".into());
        }
        self.store.seen(device_id, now)?;
        Ok((person, device))
    }

    fn person(&self, id: &str) -> Result<Principal, String> {
        self.store.principal(id)?.ok_or_else(|| "No such account is in this grid".to_owned())
    }

    /// Whether `by` may do `action` here, as an error when they may not.
    pub fn allowed(&self, by: &str, action: Action) -> Result<(), String> {
        if by == "owner" {
            return Ok(());
        }
        let person = self.person(by)?;
        if person.may(action) {
            Ok(())
        } else {
            Err(format!("{} may not {}", person.name, action.name()))
        }
    }

    // ---- Computers that offer resources ----

    /// Records what a computer gives to the realm. A computer that offers again keeps the same
    /// place in the realm, so what is already reserved on it is not left pointing at nothing.
    pub fn offer_host(&mut self, device_id: &str, name: &str, capacity: Resources, offered: Resources, commitment: Commitment, now: i64) -> Result<Host, String> {
        let device = self.store.device(device_id)?.filter(|device| device.active()).ok_or("This computer is not in this grid")?;
        let mut host = Host::new(&self.realm.id, &device.id, name, capacity, offered, commitment, now)?;
        if self.store.host_of_device(device_id)?.is_none() && self.store.host_count()? >= limits::MAX_HOSTS {
            return Err(limits::reached("computers offering resources at once", limits::MAX_HOSTS));
        }
        if let Some(before) = self.store.host_of_device(device_id)? {
            host.id = before.id;
            host.joined_at = before.joined_at;
            host.gpu_isolation = before.gpu_isolation;
            host.draining = before.draining;
        }
        // What a computer is committed to is a decision somebody made in words, not something the
        // computer announces each time it checks in. While a commitment stands, an offer says how
        // large the computer is and nothing else; changing the commitment goes through
        // `commit_host`, which records the new wording beside the old.
        let commitment = match self.store.standing_pledge(&host.id)? {
            Some(pledge) => pledge.commitment,
            None => commitment,
        };
        host.commitment = commitment;
        self.store.put_host(&host)?;
        self.reconcile_model_plans(now)?;
        self.note(
            Entry::new(&self.realm.id, &device.principal_id, "host.offered", Decision::Allowed).from(device_id).because(match commitment {
                Commitment::Share => "a bounded share of this computer",
                Commitment::Dedicated => "this computer is dedicated to the grid",
                Commitment::None => "this computer contributes nothing",
            }),
            now,
        )?;
        Ok(host)
    }

    /// Stops a computer taking new work; what runs on it is left to finish.
    pub fn drain_host(&mut self, by: &str, host_id: &str, now: i64) -> Result<(), String> {
        self.allowed(by, Action::DrainHost)?;
        self.store.set_draining(host_id, true)?;
        self.reconcile_model_plans(now)?;
        self.note(Entry::new(&self.realm.id, by, "host.draining", Decision::Allowed).because(host_id), now)
    }

    /// Brings a computer back to taking work after it was emptied, and lets the plans place on it
    /// again. Leaving a computer out is a decision an administrator makes, so it has to be one
    /// they can unmake; the legacy grid's admin can put a computer back whenever they like.
    pub fn bring_host_back(&mut self, by: &str, host_id: &str, now: i64) -> Result<(), String> {
        self.allowed(by, Action::DrainHost)?;
        self.store.set_draining(host_id, false)?;
        self.reconcile_model_plans(now)?;
        self.note(Entry::new(&self.realm.id, by, "host.brought back", Decision::Allowed).because(host_id), now)
    }

    /// What a computer still has free, after what is reserved on it.
    ///
    /// One question about one computer, asked as one query. It used to read every reservation in
    /// the grid, and it is called once per computer inside placement, which made placement cost
    /// the number of computers times the number of reservations ever granted.
    pub fn free_on(&self, host_id: &str, now: i64) -> Option<Resources> {
        let host = self.store.host(host_id).ok()??;
        let mut free = host.offered;
        for taken in self.store.reserved_on(host_id, now).ok()? {
            free = free.less(&taken);
        }
        Some(free)
    }

    /// What every computer still has free, in one pass rather than one pass per computer.
    ///
    /// This returns free room and nothing else. The rules that decide whether a computer may take
    /// a particular piece of work stay where they are: whether its card can be shared, what its
    /// owner committed it to, and what it last said about itself are the computer owner's
    /// protection, and a helper that quietly absorbed one of them would place work on a computer
    /// whose owner said no. Callers also keep iterating `hosts()` rather than this map, because
    /// `hosts()` returns computers in the order they joined and ties in placement go to the one
    /// that joined first.
    fn free_everywhere(&self, now: i64) -> Result<std::collections::HashMap<String, Resources>, String> {
        let mut free: std::collections::HashMap<String, Resources> = self.store.hosts()?.into_iter().map(|host| (host.id, host.offered)).collect();
        for lease in self.store.live_leases(now)? {
            if let Some(room) = free.get_mut(&lease.host_id) {
                *room = room.less(&lease.resources);
            }
        }
        Ok(free)
    }

    // ---- Model serving profile ----

    /// Model plans are part of the core realm, while the model runner remains a profile adapter.
    /// This keeps administration, placement and audit in one database without putting prompts or
    /// answers in it.
    pub fn model_plans(&self) -> Result<Vec<ModelPlan>, String> {
        self.store.model_plans()
    }

    pub fn model_plan(&self, id: &str) -> Result<Option<ModelPlan>, String> {
        self.store.model_plan(id)
    }

    /// The hosts currently assigned to a model plan, in stable assignment order.
    pub fn model_assignments(&self) -> Result<Vec<ModelAssignment>, String> {
        self.store.model_assignments()
    }

    /// Adds a model plan and reconciles its sticky host assignments in one database update.
    pub fn add_model_plan(
        &mut self,
        by: &str,
        model: &str,
        quant: Option<&str>,
        percent: u8,
        policy: crate::policy::IdlePolicy,
        target: Target,
        now: i64,
    ) -> Result<ModelPlan, String> {
        self.allowed(by, Action::ManageModels)?;
        if !self.realm.can(Capability::Models) {
            return Err("This grid does not serve models".into());
        }
        let hosts = self.store.hosts()?;
        let mut plans = self.store.model_plans()?;
        // Picking computers resolves against the plans already here: they leave whatever picked
        // them before, an emptied pick plan goes, and picking more computers for the same model
        // joins its plan. A computer runs the model it was given last.
        let plan = model::place(&self.realm.id, &mut plans, model, quant, percent, policy, target, &hosts, now)?;
        let assignments = model::reconcile(&plans, &hosts, &self.store.devices()?, &self.store.model_assignments()?, now);
        self.store.replace_model_state(&plans, &assignments)?;
        self.note(
            Entry::new(&self.realm.id, by, "model.plan.added", Decision::Allowed)
                .about(Capability::Models, &plan.id)
                .because(&plan.model),
            now,
        )?;
        Ok(plan)
    }

    /// Replaces the editable fields of a model plan, then reconciles sticky assignments.
    pub fn update_model_plan(
        &mut self,
        by: &str,
        plan_id: &str,
        model: Option<&str>,
        quant: Option<Option<&str>>,
        percent: Option<u8>,
        policy: Option<crate::policy::IdlePolicy>,
        target: Option<Target>,
        now: i64,
    ) -> Result<ModelPlan, String> {
        self.allowed(by, Action::ManageModels)?;
        let hosts = self.store.hosts()?;
        let mut plan = self.store.model_plan(plan_id)?.ok_or("No such model plan")?;
        if let Some(model) = model {
            plan.model = model::validate_model(model)?;
        }
        if let Some(quant) = quant {
            plan.quant = model::validate_quant(quant)?;
        }
        if let Some(percent) = percent {
            plan.percent = model::validate_percent(percent)?;
        }
        if let Some(policy) = policy {
            plan.policy = policy;
        }
        if let Some(target) = target {
            plan.target = ModelPlan::validate_target(target, &hosts)?;
            if matches!(plan.target, Target::Computers { .. }) {
                plan.percent = 100;
            }
        }
        if !matches!(plan.target, Target::Computers { .. }) {
            model::validate_percent(plan.percent)?;
        }
        let mut plans = self.store.model_plans()?;
        let slot = plans.iter_mut().find(|entry| entry.id == plan_id).ok_or("No such model plan")?;
        *slot = plan.clone();
        // A computer this plan now picks leaves the plan that picked it before, and a plan left
        // with no computers goes, exactly as it does when a plan is added. Otherwise two plans
        // would name one computer, the earlier one would keep it, and this edit would be the
        // decision that never happened.
        let picked = plan.target.hosts().to_vec();
        if !picked.is_empty() {
            for other in plans.iter_mut().filter(|other| other.id != plan_id) {
                if let Target::Computers { hosts } = &mut other.target {
                    hosts.retain(|host| !picked.contains(host));
                }
            }
            plans.retain(|other| other.id == plan_id || !matches!(&other.target, Target::Computers { hosts } if hosts.is_empty()));
        }
        let assignments = model::reconcile(&plans, &hosts, &self.store.devices()?, &self.store.model_assignments()?, now);
        self.store.replace_model_state(&plans, &assignments)?;
        self.note(
            Entry::new(&self.realm.id, by, "model.plan.updated", Decision::Allowed)
                .about(Capability::Models, plan_id)
                .because(&plan.model),
            now,
        )?;
        Ok(plan)
    }

    /// Removes a plan and releases its model assignments. Hosts remain enrolled and available to
    /// other plans.
    pub fn remove_model_plan(&mut self, by: &str, plan_id: &str, now: i64) -> Result<(), String> {
        self.allowed(by, Action::ManageModels)?;
        let mut plans = self.store.model_plans()?;
        let before = plans.len();
        plans.retain(|plan| plan.id != plan_id);
        if plans.len() == before {
            return Err("No such model plan".into());
        }
        let hosts = self.store.hosts()?;
        let assignments = model::reconcile(&plans, &hosts, &self.store.devices()?, &self.store.model_assignments()?, now);
        self.store.replace_model_state(&plans, &assignments)?;
        self.note(Entry::new(&self.realm.id, by, "model.plan.removed", Decision::Allowed).about(Capability::Models, plan_id), now)
    }

    /// Re-runs placement after a computer offer, revocation or drain changed eligibility.
    ///
    /// The write is skipped when nothing moved. `replace_model_state` deletes every plan and every
    /// assignment and writes them all again, and this runs inline whenever a computer offers,
    /// drains or comes back, so a grid where computers check in regularly was rewriting its whole
    /// model profile for each of them and flushing it to the disk each time. Placement itself is
    /// unchanged and still happens on the request path: coalescing it into the background would
    /// delay where a model lands by however long the pass waits, and the parity tests that say
    /// this core places models where the shipped hub places them compare computer by computer.
    pub fn reconcile_model_plans(&mut self, now: i64) -> Result<Vec<ModelAssignment>, String> {
        let plans = self.store.model_plans()?;
        let hosts = self.store.hosts()?;
        let before = self.store.model_assignments()?;
        let assignments = model::reconcile(&plans, &hosts, &self.store.devices()?, &before, now);
        if assignments != before {
            self.store.replace_model_state(&plans, &assignments)?;
        }
        Ok(assignments)
    }

    // ---- Work ----

    /// Whether this work may be admitted, and the stamp it is admitted under. Nothing is written
    /// here, so a caller that has to write several things at once can admit the work and then
    /// commit the lot in one change of its own.
    fn admit(&self, work: &mut Workload, now: i64) -> Result<(), String> {
        if !self.realm.lifecycle.serves() {
            return Err("This grid is not serving work at the moment".into());
        }
        if !self.realm.can(work.capability) {
            return Err(format!("This grid does not {}", work.capability.doing()));
        }
        let person = self.person(&work.principal_id)?;
        if !person.active() {
            return Err("This account is suspended".into());
        }
        let may_place = person.may(Action::PlaceWork)
            || (work.capability == Capability::Models && work.kind == work::Kind::Inference && person.may(Action::CallModel))
            || (work.capability == Capability::Workspaces && person.may(Action::UseWorkspace))
            // A researcher places research work and nothing else: they hold no permission to
            // place work in general, which is the point of the role being its own.
            || (work.capability == Capability::Research && person.may(Action::DoResearch));
        if !may_place {
            return Err(format!("{} may not place work here", person.name));
        }
        // The one free text a workload carries is cut down here, because a realm is a record that
        // something happened and not a place to park what somebody typed. Every other free text in
        // the core is bounded where it comes in: `Entry::because` strips and cuts to five hundred,
        // `Workspace::advance` to three hundred, a connector's note to five hundred. This column
        // was bounded only by the convention that `submit_model` writes a disciplined string into
        // it, and a convention is not a check: `submit` is public and takes a `Workload` the
        // caller filled in. This is the single door work goes through.
        if let Some(note) = work.note.as_mut() {
            *note = note.chars().filter(|letter| !letter.is_control()).take(300).collect();
        }
        work.policy_version = self.store.policy_version()?;
        work.advance(Stage::Validating, now)?;
        work.advance(Stage::Queued, now)?;
        Ok(())
    }

    /// Puts a piece of work in the queue, under the policy in force now.
    pub fn submit(&mut self, mut work: Workload, now: i64) -> Result<Workload, String> {
        if self.store.unfinished_count()? >= limits::MAX_UNFINISHED_WORK {
            return Err(limits::reached("pieces of work in flight at once", limits::MAX_UNFINISHED_WORK));
        }
        self.admit(&mut work, now)?;
        self.store.put_workload(&work)?;
        self.note(
            Entry::new(&self.realm.id, &work.principal_id, "work.queued", Decision::Allowed).about(work.capability, &work.id).from(&work.device_id).for_work(&work.id),
            now,
        )?;
        Ok(work)
    }

    /// Admits an inference request against a named model plan. The request body is intentionally
    /// not an argument and is never written by Core; the runner streams it directly to the
    /// assigned member and returns the answer to the caller.
    pub fn submit_model(
        &mut self,
        principal_id: &str,
        device_id: &str,
        plan_id: &str,
        needs: Resources,
        expires_at: Option<i64>,
        now: i64,
    ) -> Result<Workload, String> {
        let plan = self.store.model_plan(plan_id)?.ok_or("No such model plan")?;
        let device = self.store.device(device_id)?.filter(|device| device.active()).ok_or("This computer is not in this grid")?;
        if device.principal_id != principal_id {
            return Err("That computer belongs to someone else".into());
        }
        let mut work = Workload::new(
            &self.realm.id,
            Capability::Models,
            work::Kind::Inference,
            principal_id,
            device_id,
            needs,
            self.store.policy_version()?,
            now,
        );
        work.note = Some(format!("model-plan:{}:{}", plan.id, plan.model));
        // The caller's deadline for the whole request, retries included, and it is set once here.
        // A request with no deadline of its own is not a request that waits for ever: it gets the
        // same half hour the legacy hub gives an answer, and nobody may ask for longer than a day.
        work.expires_at = Some(expires_at.map_or(now + work::ANSWER_WITHIN, |deadline| deadline.min(now + work::LONGEST_WAIT)));
        self.submit(work, now)
    }

    /// The model plan a request belongs to, read back from the one note a model workload carries.
    fn plan_of(work: &Workload) -> Option<&str> {
        work.note.as_deref().and_then(|note| note.strip_prefix("model-plan:")).and_then(|note| note.split(':').next())
    }

    /// The computers that have already held a reservation for this work, whether or not they
    /// still do. Reservations are kept after they are given back, so what has been tried needs no
    /// new column and no clock, and it survives a restart.
    fn tried(&self, workload_id: &str) -> Result<Vec<String>, String> {
        self.store.leases_tried(workload_id)
    }

    /// Which computer in a model request's plan should have it next, if any.
    ///
    /// The same question is asked when a request is first placed and when one computer's attempt
    /// has ended, so that re-queueing work and finding it a computer can never disagree about who
    /// is eligible. A computer that has already had this request is skipped: the reservations say
    /// who tried, so a second try goes somewhere else or the request ends honestly.
    ///
    /// This is stricter than the legacy hub, which lets the same computer have a job again after
    /// five seconds. The record already says who tried, so no clock is involved and the rule
    /// survives a restart; the cost is that a plan with one computer gets one try, and saying so
    /// is better than making the caller wait out the same failure twice.
    fn model_host_for(&self, work: &Workload, now: i64) -> Result<Option<String>, String> {
        let Some(plan_id) = Core::plan_of(work) else { return Ok(None) };
        let tried = self.tried(&work.id)?;
        let leases = self.store.live_leases(now)?;
        let free_room = self.free_everywhere(now)?;
        let still_here = self.store.active_devices()?;
        let hosts: std::collections::HashMap<String, work::Host> = self.store.hosts()?.into_iter().map(|host| (host.id.clone(), host)).collect();
        let mut best: Option<(String, f64)> = None;
        for assignment in self.store.model_assignments()?.iter().filter(|assignment| assignment.plan_id == plan_id) {
            if tried.contains(&assignment.host_id) {
                continue;
            }
            let Some(host) = hosts.get(&assignment.host_id) else { continue };
            if !host.takes_work() || !still_here.contains(&host.device_id) {
                continue;
            }
            let Some(free) = free_room.get(&host.id).copied() else { continue };
            if !free.covers(&work.needs) {
                continue;
            }
            if work.needs.gpu && !host.gpu_isolation.shareable() && leases.iter().any(|lease| lease.host_id == host.id && lease.resources.gpu) {
                continue;
            }
            if best.as_ref().is_none_or(|(_, room)| free.memory_gb > *room) {
                best = Some((host.id.clone(), free.memory_gb));
            }
        }
        Ok(best.map(|(host_id, _)| host_id))
    }

    /// Gives a model request a reservation on one of the plan's assigned hosts. Generic work can
    /// use `grant_lease`; model work uses this method so a runner never receives a different
    /// model's host merely because it had more free memory.
    ///
    /// Called again after an attempt ended, it is the retry: the computers that already had this
    /// request are skipped, the reservation never outlives the caller's deadline, and the
    /// reservation's generation is the attempt number, so a computer waking up late cannot act on
    /// a reservation the work has moved on from.
    pub fn grant_model_lease(&mut self, workload_id: &str, seconds: i64, now: i64) -> Result<Lease, String> {
        let work = self.store.workload(workload_id)?.ok_or("No such work")?;
        if work.capability != Capability::Models || work.kind != work::Kind::Inference || work.stage != Stage::Queued {
            return Err("Only a queued model request is given one of its plan's computers".into());
        }
        if Core::plan_of(&work).is_none() {
            return Err("This model request has no model plan".into());
        }
        let deadline = work.expires_at.unwrap_or(i64::MAX);
        if now >= deadline {
            return Err("This request's deadline has passed".into());
        }
        let tried = self.tried(workload_id)?;
        if tried.len() as u64 >= work::TRIES {
            return Err(format!("This request has already been tried on {} computers", work::TRIES));
        }
        let host_id = match self.model_host_for(&work, now)? {
            Some(host_id) => host_id,
            None => {
                // Two different things to say, and the caller can do something about only one of
                // them: there is nowhere left to try, or there is somewhere and it has no room.
                let plan_id = Core::plan_of(&work).unwrap_or_default().to_owned();
                let assigned: Vec<String> = self.store.model_assignments()?.into_iter().filter(|entry| entry.plan_id == plan_id).map(|entry| entry.host_id).collect();
                return Err(if !assigned.is_empty() && assigned.iter().all(|host| tried.contains(host)) {
                    "Every computer in this model plan has already tried this request".to_owned()
                } else {
                    "No assigned computer in this model plan has room for this work".to_owned()
                });
            }
        };
        let lease = Lease {
            id: format!("lease-{}", &crate::token()[..16]),
            realm_id: self.realm.id.clone(),
            host_id,
            workload_id: workload_id.to_owned(),
            resources: work.needs,
            generation: tried.len() as u64 + 1,
            granted_at: now,
            // A computer never holds a reservation past the moment the caller stopped waiting.
            expires_at: (now + seconds.clamp(30, work::LONGEST_WAIT)).min(deadline),
            released_at: None,
        };
        let mut work = work;
        work.lease_id = Some(lease.id.clone());
        work.advance(Stage::Leased, now)?;
        self.store.put_workload(&work)?;
        self.store.put_lease(&lease)?;
        self.note(Entry::new(&self.realm.id, &work.principal_id, "model.work.leased", Decision::Allowed).about(Capability::Models, &lease.host_id).for_work(workload_id), now)?;
        Ok(lease)
    }

    /// Reserves room on a computer for queued work and moves it on. Chooses the computer with the
    /// most room that can take it; a draining or uncommitted computer takes nothing.
    pub fn grant_lease(&mut self, workload_id: &str, seconds: i64, now: i64) -> Result<Lease, String> {
        let work = self.store.workload(workload_id)?.ok_or("No such work")?;
        if work.stage != Stage::Queued {
            return Err("Only queued work is given a computer".into());
        }
        // Work that belongs to a model plan is placed only on that plan's computers, whichever
        // way the caller asks for a reservation. Otherwise the plan would hold for a runner that
        // called one method and not for one that called the other.
        if work.note.as_deref().is_some_and(|note| note.starts_with("model-plan:")) {
            return self.grant_model_lease(workload_id, seconds, now);
        }
        // Work that names a workspace is placed by the workspace rule whichever way the
        // reservation is asked for, for the same reason: otherwise a runner that called this
        // method would get a computer that has never been committed to hosting workspaces, or one
        // whose person is using it and whose admin lent the grid only its idle time. What makes
        // a piece of work a placement is that it names a workspace, exactly as what makes one a
        // model request is that it names a plan.
        if work.note.as_deref().is_some_and(|note| note.starts_with("workspace:")) {
            return self.grant_workspace_lease(workload_id, seconds, now);
        }
        // And work that names a research scope is held to that scope's limits whichever way the
        // reservation is asked for, for the third time and the same reason: otherwise a runner
        // taking the generic path would be given a card nobody has recorded the isolation of, and
        // a reservation longer than the scope allows. The scope says how long, not the caller.
        if work.note.as_deref().is_some_and(|note| note.starts_with("research:")) {
            return self.grant_research_lease(workload_id, now);
        }
        let leases = self.store.live_leases(now)?;
        let free_room = self.free_everywhere(now)?;
        let still_here = self.store.active_devices()?;
        let mut best: Option<(String, f64)> = None;
        for host in self.store.hosts()?.iter().filter(|host| host.takes_work()) {
            // A computer that is no longer in the grid offers nothing, whatever it last said.
            if !still_here.contains(&host.device_id) {
                continue;
            }
            let Some(free) = free_room.get(&host.id).copied() else { continue };
            if !free.covers(&work.needs) {
                continue;
            }
            if work.needs.gpu && !host.gpu_isolation.shareable() && leases.iter().any(|lease| lease.host_id == host.id && lease.resources.gpu) {
                // The card cannot be shared safely, and someone else has it.
                continue;
            }
            let room = free.memory_gb;
            if best.as_ref().is_none_or(|(_, most)| room > *most) {
                best = Some((host.id.clone(), room));
            }
        }
        let (host_id, _) = best.ok_or("No computer in this grid has room for this work")?;
        let lease = Lease {
            id: format!("lease-{}", &crate::token()[..16]),
            realm_id: self.realm.id.clone(),
            host_id,
            workload_id: workload_id.to_owned(),
            resources: work.needs,
            generation: 1,
            granted_at: now,
            expires_at: now + seconds.clamp(30, 24 * 60 * 60),
            released_at: None,
        };
        let mut work = work;
        work.lease_id = Some(lease.id.clone());
        work.advance(Stage::Leased, now)?;
        self.store.put_workload(&work)?;
        self.store.put_lease(&lease)?;
        self.note(Entry::new(&self.realm.id, &work.principal_id, "work.leased", Decision::Allowed).about(work.capability, &lease.host_id).for_work(workload_id), now)?;
        Ok(lease)
    }

    /// Moves work on, on the reservation the computer doing it holds.
    ///
    /// Keyed on the reservation and not on the work, for the same reason `give_back` is: a
    /// computer that went quiet and woke up later is still holding a reservation the realm has
    /// since taken back, and the work may already be on another computer. Keyed on the work, that
    /// computer could walk work it no longer has all the way to finished, and the person waiting
    /// would be sent the wrong answer or none. Keyed on the reservation, it is refused at the
    /// first step, and what the refusal says is that the reservation is not the one this work
    /// holds now, so a runner knows to ask for one again rather than to retry.
    ///
    /// The reservation also has to be one the computer still holds: not given back, and not run
    /// out. That is now asked of every step rather than only of starting and running, because a
    /// computer whose reservation has ended has no more claim to finish work than to start it.
    pub fn advance(&mut self, lease_id: &str, next: Stage, now: i64) -> Result<Stage, String> {
        let lease = self.store.lease(lease_id)?.ok_or("No such reservation is in this grid")?;
        let mut work = self.store.workload(&lease.workload_id)?.ok_or("No such work")?;
        // The work moved on to another computer. Nothing is recorded for this: a realm should not
        // write a row every time a computer that was left behind knocks, and what the realm
        // decided about this work is already in the history where the reservation went back.
        if work.lease_id.as_deref() != Some(lease_id) {
            return Err("That reservation is not the one this work holds now; ask for a reservation again".into());
        }
        let workload_id = work.id.clone();
        // A reservation that was given back and one that simply ran out are the same thing to the
        // computer holding it: the realm is no longer waiting on it. The two are told apart only
        // in what the record says, because an operator reading the history wants to know which.
        if lease.released_at.is_some() || !lease.holds(now) {
            let why = if lease.released_at.is_some() { "its reservation on the computer was given back" } else { "its reservation on the computer has expired" };
            // Say so in the record, then refuse.
            self.note(
                Entry::new(&self.realm.id, &work.principal_id, "work.refused", Decision::Refused)
                    .about(work.capability, &workload_id)
                    .for_work(&workload_id)
                    .because(why),
                now,
            )?;
            return Err("This work no longer holds a computer; it must be queued again".into());
        }
        // Queued means the work has no computer, and nothing here gives one back. Allowing it left
        // the room subtracted from a computer doing nothing, and the work free to be given a
        // second reservation while the first was still live. `give_back` is the door for this: it
        // puts the room back, decides whether another computer may try, and records why.
        if next == Stage::Queued {
            return Err("Work is not queued again by moving it on; give the reservation back instead, and say what went wrong".into());
        }
        work.advance(next, now)?;
        self.store.put_workload(&work)?;
        if work.stage.finished() {
            self.store.release_for(&workload_id, now)?;
        }
        self.note(
            Entry::new(&self.realm.id, &work.principal_id, &format!("work.{}", format!("{:?}", work.stage).to_lowercase()), Decision::Allowed)
                .about(work.capability, &workload_id)
                .for_work(&workload_id),
            now,
        )?;
        Ok(work.stage)
    }

    /// Hands work back when one computer's attempt at it ended without an answer.
    ///
    /// This is the one door a runner uses: the computer went quiet, was busy, did not have the
    /// model ready, or sent nothing usable. It is keyed on the reservation and not on the work,
    /// so a computer that wakes up late cannot pull back work that has since moved on. What comes
    /// back is where the work now stands: queued when another computer in the plan may try it,
    /// failed when the answer had already begun or nothing is left to try, expired when the
    /// caller's deadline has passed. A runner that is given `Queued` asks for a reservation again.
    pub fn give_back(&mut self, lease_id: &str, setback: work::Setback, now: i64) -> Result<Stage, String> {
        let lease = self.store.lease(lease_id)?.ok_or("No such reservation is in this grid")?;
        if lease.released_at.is_some() {
            return Err("That reservation was already given back".into());
        }
        let work = self.store.workload(&lease.workload_id)?.ok_or("No such work")?;
        if work.lease_id.as_deref() != Some(lease_id) {
            return Err("That reservation is not the one this work holds now".into());
        }
        if work.stage.finished() {
            return Err("This work has already finished".into());
        }
        self.after_trouble(work, setback, now)
    }

    /// Stops work the caller no longer wants, or that an operator is stopping for them.
    ///
    /// Core does not reach the computer that was running it. The reservation goes back, so that
    /// computer's next step is refused and its runner drops the connection, which is what makes
    /// the model there stop generating. Nothing of the request or the answer is recorded, and the
    /// words in the history are chosen here rather than supplied by whoever asked.
    pub fn cancel_work(&mut self, by: &str, workload_id: &str, now: i64) -> Result<Stage, String> {
        let work = self.store.workload(workload_id)?.ok_or("No such work")?;
        // The person who placed it, or anyone who may place work here, which is what an operator
        // is for. Everybody else is refused in the same voice as any other permission.
        if by != work.principal_id {
            self.allowed(by, Action::PlaceWork)?;
        }
        if work.stage.finished() {
            return Err("This work has already finished".into());
        }
        if !work.stage.may_become(Stage::Cancelled) {
            return Err("This work is finishing up and will not be stopped now".into());
        }
        let why = if by == work.principal_id {
            "the caller stopped waiting for this request".to_owned()
        } else {
            format!("stopped by {}", self.person(by).map(|person| person.name).unwrap_or_else(|_| "the grid's owner".to_owned()))
        };
        self.stop_work(by, work, &why, now)
    }

    /// The one cancel in the realm: the reservations go back, the work is cancelled, and one
    /// event names whoever decided it and why.
    ///
    /// `cancel_work` is this with the permission check in front of it. Suspending an account and
    /// taking a computer out of the grid come straight here instead, because someone who may
    /// remove a computer is not thereby someone who may place work, and the removal must not fail
    /// on a permission its owner never needed.
    fn stop_work(&mut self, by: &str, work: Workload, why: &str, now: i64) -> Result<Stage, String> {
        let mut work = work;
        self.store.release_for(&work.id, now)?;
        work.advance(Stage::Cancelled, now)?;
        self.store.put_workload(&work)?;
        self.placement_ended(&work, why, now)?;
        self.note(
            Entry::new(&self.realm.id, by, "work.cancelled", Decision::Allowed).about(work.capability, &work.id).for_work(&work.id).because(why),
            now,
        )?;
        Ok(work.stage)
    }

    /// A piece of work that was holding a workspace on a computer has ended.
    ///
    /// The placement ends with it. A workspace left pointing at a reservation that has gone is a
    /// workspace no computer is actually holding, and the record would be saying otherwise. The
    /// workspace itself keeps its owner, its image and its trail, and waits for a computer.
    fn placement_ended(&mut self, work: &Workload, why: &str, now: i64) -> Result<(), String> {
        let Some(workspace_id) = work.note.as_deref().and_then(|note| note.strip_prefix("workspace:")).map(str::to_owned) else { return Ok(()) };
        let Some(placement) = self.store.live_assignment(&workspace_id)?.filter(|placement| placement.workload_id == work.id) else { return Ok(()) };
        self.store.release_assignment(&placement.id, why, now)?;
        let Some(mut workspace) = self.store.workspace(&workspace_id)?.filter(|workspace| !workspace.state.finished()) else { return Ok(()) };
        self.ask_for_a_computer_again(&mut workspace, "Waiting for a computer with room", now)?;
        self.store.put_workspace(&workspace)?;
        self.note(
            Entry::new(&self.realm.id, &work.principal_id, "workspace.placement.ended", Decision::Allowed)
                .about(Capability::Workspaces, &workspace_id)
                .for_work(&work.id)
                .because(why),
            now,
        )
    }

    /// The single decision behind every way one computer's attempt can end, so that giving work
    /// back, a reservation running out and a computer leaving the grid cannot drift apart.
    ///
    /// The room goes back first, whatever is decided next. Work that was running or finishing up
    /// has failed, because part of the answer may already be with the caller and nobody is ever
    /// sent two. Work that had a computer but had not begun the answer waits for another computer
    /// when the plan still has one and the caller is still waiting. Everything else ends here.
    fn after_trouble(&mut self, work: Workload, setback: work::Setback, now: i64) -> Result<Stage, String> {
        let mut work = work;
        self.store.release_for(&work.id, now)?;
        let next = if matches!(work.stage, Stage::Running | Stage::Draining) {
            Stage::Failed
        } else if work.expires_at.is_some_and(|deadline| now >= deadline) {
            Stage::Expired
        } else if self.another_computer_for(&work, now)? {
            Stage::Queued
        } else {
            Stage::Failed
        };
        // Work already waiting for a computer stays where it is. An attempt that ended on a
        // reservation the work had already given back moves nothing, and that is not a failure.
        if work.stage != next {
            work.advance(next, now)?;
            self.store.put_workload(&work)?;
        }
        if next.finished() {
            self.placement_ended(&work, setback.say(), now)?;
        }
        self.note(
            Entry::new(&self.realm.id, &work.principal_id, &format!("work.{}", format!("{next:?}").to_lowercase()), Decision::Allowed)
                .about(work.capability, &work.id)
                .for_work(&work.id)
                .because(setback.say()),
            now,
        )?;
        Ok(next)
    }

    /// Whether this work can honestly be offered to another computer: it belongs to a model plan,
    /// it has tries left, and some computer in that plan that has not had it can take it.
    ///
    /// Only model work is placed again here. A model plan says which computers may have the work,
    /// so Core knows where it should go; other work ends, and whoever placed it decides whether
    /// to place it again.
    fn another_computer_for(&self, work: &Workload, now: i64) -> Result<bool, String> {
        if Core::plan_of(work).is_none() {
            return Ok(false);
        }
        if self.tried(&work.id)?.len() as u64 >= work::TRIES {
            return Ok(false);
        }
        Ok(self.model_host_for(work, now)?.is_some())
    }

    /// Ends every reservation that has run out, and every piece of work whose own deadline has
    /// passed. Returns how many of each it acted on.
    ///
    /// A reservation that lapses goes through the same decision as any other failed attempt, so
    /// work that had not begun its answer waits for another computer instead of ending. A
    /// deadline is the only thing that can end a request no computer ever picked up, because
    /// queued work holds no reservation to lapse.
    ///
    /// Core has no clock of its own and this is the one thing in it driven by one: whoever opens
    /// the realm calls it on a timer, as the legacy hub's sweep does every second.
    pub fn expire(&mut self, now: i64) -> usize {
        let Ok(lapsed) = self.store.lapsed_leases(now) else { return 0 };
        for (lease_id, workload_id) in &lapsed {
            let _ = self.store.release_lease(lease_id, now);
            if let Ok(Some(work)) = self.store.workload(workload_id) {
                // Only the attempt that was made on this reservation. Giving one back is keyed on
                // the reservation for the same reason, so that a computer waking up late cannot
                // pull back work that has moved on; a reservation lapsing is that computer going
                // quiet instead of knocking, and it must not end an attempt somewhere else. Ending
                // the work here would take back the reservation it is actually running on.
                if work.lease_id.as_deref() != Some(lease_id.as_str()) {
                    continue;
                }
                if !work.stage.finished() {
                    let _ = self.after_trouble(work, work::Setback::WentQuiet, now);
                }
            }
        }
        let Ok(workloads) = self.store.unfinished_before(now) else { return lapsed.len() };
        let mut ended = 0;
        for work in workloads {
            // Work that was running has failed rather than expired: it was given a computer and a
            // computer did not finish it. Running work never becomes expired, and it should not.
            let next = if matches!(work.stage, Stage::Running | Stage::Draining) { Stage::Failed } else { Stage::Expired };
            let _ = self.store.release_for(&work.id, now);
            let mut work = work;
            if work.advance(next, now).is_ok() {
                let _ = self.store.put_workload(&work);
                let _ = self.note(
                    Entry::new(&self.realm.id, &work.principal_id, &format!("work.{}", format!("{next:?}").to_lowercase()), Decision::Allowed)
                        .about(work.capability, &work.id)
                        .for_work(&work.id)
                        .because("the computer did not finish in time"),
                    now,
                );
                ended += 1;
            }
        }
        lapsed.len() + ended
    }

    // ---- Permissions handed to work ----

    /// Mints a narrow, short-lived permission for a piece of work, and remembers the generations
    /// it was issued under so its use can be judged against what is true then.
    pub fn mint(&self, claims: &Claims) -> Result<String, String> {
        let token = self.authority.mint(claims)?;
        self.store.remember_capability(claims)?;
        Ok(token)
    }

    /// Accepts a permission for what is being attempted, and records the decision.
    ///
    /// The signature and the claims are only half of it. The realm, the account, the computer,
    /// the policy and whether it has been used already are all looked at again here, at the
    /// moment of use. A permission minted a minute ago is refused if the computer has since been
    /// taken out of the grid or the account suspended, and a restart does not forget any of it.
    pub fn accept(&mut self, token: &str, attempt: &Attempt<'_>, now: i64) -> Result<Claims, String> {
        // A grid that is not serving serves nothing, and a permission is served at the moment it
        // is used. `use_workspace` and the broker's `clear_to_send` each ask this before they get
        // here; asking it here as well is what makes it true of every path, including one a later
        // profile writes and forgets to guard. Read from the database rather than the copy this
        // handle opened with, because another handle may have paused the grid since.
        //
        // Nothing is recorded for a refusal at this point, exactly as `use_workspace` records
        // nothing: a paused grid is not a grid that should be writing a row per knock.
        if !self.store.realm()?.lifecycle.serves() {
            return Err("This grid is not serving work at the moment".into());
        }
        // The signature next, before a single field of the token is written anywhere. What a
        // token says is a stranger's text until it has been checked, and the identifier fields of
        // an event are not filtered the way a free-text reason is, so looking the claims up on an
        // unchecked token would let anybody seal whatever they liked into this realm's history.
        match self.authority.verified(token) {
            Ok(claims) => {
                // The generations, the policy and whether it has been spent, and then the one
                // thing only the research profile knows: a permission bound to a destination is
                // judged against the realm's policy and its admissions as they are at this
                // instant, because an admission can simply lapse without anything being raised.
                let stale = self.store.check_capability(&claims, now)?.or_else(|| {
                    if claims.capability == Capability::Research && claims.destination.is_some() {
                        self.research_destination_still_allowed(&claims, now)
                    } else {
                        None
                    }
                });
                if let Some(stale) = stale {
                    let entry = Entry::new(&self.realm.id, &claims.principal_id, "capability.refused", Decision::Refused)
                        .from(&claims.device_id)
                        .for_work(&claims.workload_id)
                        .because(&stale.describe());
                    self.note(entry, now)?;
                    return Err(stale.describe());
                }
            }
            Err(refused) => {
                let entry = Entry::new(&self.realm.id, "unknown", "capability.refused", Decision::Refused).because(&format!("{refused:?}"));
                self.note(entry, now)?;
                return Err(refused.describe());
            }
        }
        match self.authority.accept(token, attempt, now) {
            Ok(claims) => {
                // The spend is what settles a race, not the check above it. Two handles on one
                // realm can both read a permission as unspent; only one of them can be the UPDATE
                // that writes `spent_at`, so its answer is what decides which. Discarding that
                // answer would let anybody who can open the realm twice use a one-use permission
                // twice.
                if claims.single_use && self.store.spend_capability(&claims.id, now)? == 0 {
                    let stale = store::Stale::AlreadyUsed;
                    let entry = Entry::new(&self.realm.id, &claims.principal_id, "capability.refused", Decision::Refused)
                        .from(&claims.device_id)
                        .for_work(&claims.workload_id)
                        .because(&stale.describe());
                    self.note(entry, now)?;
                    return Err(stale.describe());
                }
                let entry = Entry::new(&self.realm.id, &claims.principal_id, "capability.used", Decision::Allowed)
                    .about(claims.capability, &claims.resource_id)
                    .from(&claims.device_id)
                    .for_work(&claims.workload_id);
                self.note(entry, now)?;
                Ok(claims)
            }
            Err(refused) => {
                let entry = Entry::new(&self.realm.id, "unknown", "capability.refused", Decision::Refused).because(&format!("{refused:?}"));
                self.note(entry, now)?;
                Err(refused.describe())
            }
        }
    }

    // ---- Agreement from someone else ----

    /// Asks for agreement to something that is not one person's to decide. `about` narrows the
    /// request to one way of reaching one thing. A request waits for `approval::WAIT` unless the
    /// caller asks for longer, and lapses if nobody answers.
    ///
    /// Anybody in the realm may ask for anything, and the action they name here decides nothing on
    /// its own. It cannot: a request may name something that does not exist yet, so this is not
    /// the moment at which the action and the thing it is about can be held to each other. What
    /// holds is read later, at both ends. `approval::decide` makes an approver hold the permission
    /// this request names rather than one they choose, and every place an agreement is spent asks
    /// `Approval::asked_to` whether it was asked for as that kind of thing at all.
    pub fn ask(&mut self, by: &str, action: Action, resource_id: &str, about: Option<(&str, &str)>, every_time: bool, seconds: i64, now: i64) -> Result<Approval, String> {
        if !action.needs_another() {
            return Err("That does not need anyone else's agreement".into());
        }
        self.person(by)?;
        let mut request = Approval::request(&self.realm.id, action, resource_id, by, every_time, now, seconds);
        if let Some((method, path)) = about {
            request = request.about(method, path);
        }
        if self.store.open_request_count(now)? >= limits::MAX_OPEN_REQUESTS {
            return Err(limits::reached("requests open at once", limits::MAX_OPEN_REQUESTS));
        }
        self.store.put_request(&request)?;
        self.note(Entry::new(&self.realm.id, by, "approval.requested", Decision::Allowed).because(action.name()), now)?;
        Ok(request)
    }

    /// Records someone's decision, and the standing allowance it creates when there is one. The
    /// decision is written once and never changed.
    pub fn decide(&mut self, approval_id: &str, action: Action, approver_id: &str, verdict: Verdict, now: i64) -> Result<(Approval, Option<Allowance>), String> {
        let approver = self.person(approver_id)?;
        // Whether anybody else could have decided this, asked of the database instead of of every
        // account in the grid. `principals()` reads one more query per person to fill in what each
        // of them holds, so this one question used to cost the realm's whole population twice.
        self.store.lapse_requests(now)?;
        let mut request = self.store.request(approval_id)?.ok_or("No such request")?;
        if request.state == approval::State::Expired {
            return Err("This request expired before it was decided".into());
        }
        let granted = !matches!(verdict, Verdict::Denied(_));
        let (word, until) = match &verdict {
            Verdict::Once => ("approve_once", None),
            Verdict::Hours(hours) => ("approve_until", Some(now + i64::from(*hours) * 3_600)),
            Verdict::Denied(_) => ("deny", None),
        };
        let alone = !self.store.another_holder_of(&approval::approving_roles(action), &request.requested_by)?;
        let allowance = approval::decide_knowing(&mut request, action, &approver, alone, verdict, now)?;
        self.store.record_decision(&request, word, until, allowance.as_ref())?;
        let reason = if request.self_issued {
            "decided by the requester; nobody else in this grid can decide".to_owned()
        } else if let Some(allowance) = &allowance {
            allowance.describe()
        } else {
            action.name().to_owned()
        };
        self.note(
            Entry::new(&self.realm.id, approver_id, "approval.decided", if granted { Decision::Allowed } else { Decision::Refused }).because(&reason),
            now,
        )?;
        Ok((request, allowance))
    }

    /// A standing allowance that already covers this, if one does. Requests that need an approver
    /// every time are never covered, so the caller does not consult this for them.
    pub fn standing(&self, principal_id: &str, resource_id: &str, method: Option<&str>, path: Option<&str>, now: i64) -> Option<Allowance> {
        self.store.allowance_for(principal_id, resource_id, method, path, now).ok()?
    }

    /// Lapses requests nobody answered, drops allowances that have run out, and withdraws research
    /// admissions that simply reached their end.
    ///
    /// The admissions are swept here rather than in a call of their own, because an admission that
    /// lapsed without being withdrawn would leave its destination in the realm's stated network
    /// policy, and the policy and what was actually let in would then disagree about what may be
    /// reached. The count returned is still the requests that lapsed, which is what it has always
    /// been; `expire_admissions` says how many admissions went.
    pub fn expire_approvals(&mut self, now: i64) -> usize {
        let lapsed = self.store.lapse_requests(now).unwrap_or(0);
        let _ = self.store.drop_lapsed_allowances(now);
        if self.realm.kind == RealmKind::Research {
            self.expire_admissions(now);
        }
        lapsed
    }

    // ---- Credentials ----
    //
    // What a credential is, where its value is kept and who may use it. Nothing here reads a
    // secret, and nothing here can store one: a workload is handed a permission naming the
    // credential, never the credential. The broker that makes the request with the value, the
    // places a credential may be sent and the record of every brokered request are in
    // `core::broker`, which adds methods to this same type.

    /// Records a credential the realm will hold on someone's behalf.
    ///
    /// `Credential::new` is where the rules about what a credential may hold are written, and this
    /// asks them again rather than trusting that the caller went through it: the type's fields are
    /// public and it deserialises, so one can arrive here having never met them.
    pub fn add_credential(&mut self, by: &str, credential: Credential, now: i64) -> Result<Credential, String> {
        self.allowed(by, Action::ManageCredentials)?;
        if !self.realm.can(realm::Capability::Credentials) {
            return Err("This grid does not broker credentials".into());
        }
        if credential.realm_id != self.realm.id {
            return Err("That credential belongs to another grid".into());
        }
        credential.is_a_reference()?;
        if self.store.credential_count()? >= limits::MAX_CREDENTIALS {
            return Err(limits::reached("credentials", limits::MAX_CREDENTIALS));
        }
        self.person(&credential.owner_id)?;
        self.store.put_credential(&credential)?;
        self.note(
            Entry::new(&self.realm.id, by, "credential.added", Decision::Allowed)
                .about(realm::Capability::Credentials, &credential.id)
                .because(&format!("{} for {}", credential.kind.name(), credential.destination)),
            now,
        )?;
        Ok(credential)
    }

    pub fn credential(&self, id: &str) -> Result<Option<Credential>, String> {
        self.store.credential(id)
    }

    pub fn credentials(&self) -> Result<Vec<Credential>, String> {
        self.store.credentials()
    }

    /// Says who may use a credential, and for what. Holding one is not permission on its own: a
    /// use still needs someone's agreement, or a standing allowance that already covers it.
    pub fn allow_credential(&mut self, by: &str, credential_id: &str, principal_id: &str, methods: &[&str], paths: &[&str], expires_at: Option<i64>, now: i64) -> Result<Grant, String> {
        self.allowed(by, Action::ManageCredentials)?;
        let credential = self.store.credential(credential_id)?.ok_or("No such credential is in this grid")?;
        if !credential.live(now) {
            return Err("This credential has been retired".into());
        }
        self.person(principal_id)?;
        if self.store.grant_for(credential_id, principal_id)?.is_none() && self.store.grant_count()? >= limits::MAX_GRANTS {
            return Err(limits::reached("people allowed to use a credential", limits::MAX_GRANTS));
        }
        let grant = Grant::new(&credential, principal_id, methods, paths, by, expires_at, now);
        self.store.put_grant(&grant)?;
        self.note(
            Entry::new(&self.realm.id, by, "credential.allowed", Decision::Allowed).about(realm::Capability::Credentials, credential_id).because(principal_id),
            now,
        )?;
        Ok(grant)
    }

    /// Takes a credential back from someone.
    pub fn take_credential_back(&mut self, by: &str, credential_id: &str, principal_id: &str, now: i64) -> Result<(), String> {
        self.allowed(by, Action::ManageCredentials)?;
        self.store.take_grant(credential_id, principal_id)?;
        self.note(
            Entry::new(&self.realm.id, by, "credential.taken back", Decision::Allowed).about(realm::Capability::Credentials, credential_id).because(principal_id),
            now,
        )
    }

    /// Records that a credential's value has been replaced in the vault. The new value is put
    /// there by the caller; what changes here is which version is current and its fingerprint.
    pub fn rotate_credential(&mut self, by: &str, credential_id: &str, fingerprint: &str, now: i64) -> Result<u32, String> {
        self.allowed(by, Action::ManageCredentials)?;
        if fingerprint.len() != 64 || !fingerprint.chars().all(|letter| letter.is_ascii_hexdigit()) {
            return Err("A credential's fingerprint comes from fingerprint_of; the value is never stored".into());
        }
        let version = self.store.rotate_credential(credential_id, fingerprint, now)?;
        self.note(
            Entry::new(&self.realm.id, by, "credential.rotated", Decision::Allowed).about(realm::Capability::Credentials, credential_id).because(&format!("version {version}")),
            now,
        )?;
        Ok(version)
    }

    /// Takes a credential out of use. Nothing about it is deleted.
    pub fn retire_credential(&mut self, by: &str, credential_id: &str, now: i64) -> Result<(), String> {
        self.allowed(by, Action::ManageCredentials)?;
        self.store.retire_credential(credential_id, now)?;
        self.note(Entry::new(&self.realm.id, by, "credential.retired", Decision::Allowed).about(realm::Capability::Credentials, credential_id), now)
    }

    /// Asks for agreement to use a credential one way. A credential that needs an approver every
    /// time makes the request one that no standing allowance can cover.
    pub fn ask_for_credential(&mut self, by: &str, credential_id: &str, method: &str, path: &str, seconds: i64, now: i64) -> Result<Approval, String> {
        let credential = self.store.credential(credential_id)?.ok_or("No such credential is in this grid")?;
        self.ask(by, Action::ApproveCredential, credential_id, Some((method, path)), credential.every_time, seconds, now)
    }

    /// Hands a piece of work a permission to use a credential once, in one way, to one place.
    ///
    /// Nothing about the value is returned or looked at. What comes back is a short-lived,
    /// single-use permission naming the credential, the destination, the method and the path, so
    /// the broker can make that one request and nothing else.
    pub fn use_credential(&mut self, principal_id: &str, device_id: &str, workload_id: &str, credential_id: &str, method: &str, path: &str, seconds: i64, now: i64) -> Result<String, String> {
        self.use_credential_to(principal_id, device_id, workload_id, credential_id, None, method, path, seconds, now)
    }

    /// Which agreement allows this use: a standing allowance that covers it, or a decision made
    /// for it that has not already been turned into a permission. A credential that needs an
    /// approver every time is never covered by a standing allowance.
    ///
    /// Only a request asked to approve a credential counts, whatever it names. Anyone may ask for
    /// anything, and a request naming this credential under some other action would have been put
    /// to some other population of approvers, so honouring it here would be spending an agreement
    /// that was never about sending a company secret.
    fn agreement_for(&self, credential: &Credential, principal_id: &str, method: &str, path: &str, now: i64) -> Result<String, String> {
        if !credential.every_time {
            if let Some(allowance) = self.standing(principal_id, &credential.id, Some(method), Some(path), now) {
                if self.asked_to_use_a_credential(&allowance.approval_id)? {
                    return Ok(allowance.approval_id);
                }
            }
        }
        let wanted = method.to_ascii_uppercase();
        // One person and one credential, rather than every request the realm has ever held. The
        // rules below are unchanged and stay in Rust, because what a request was asked to approve
        // is the difference between an agreement to send a company secret and an agreement to
        // approve research, and the order decides which of several agreements is spent.
        for request in self.store.standing_requests_about(&credential.id, principal_id, now)? {
            if !request.asked_to(Action::ApproveCredential) {
                continue;
            }
            if request.method.as_deref().is_some_and(|allowed| allowed != wanted) {
                continue;
            }
            if request.path.as_deref().is_some_and(|allowed| allowed != path) {
                continue;
            }
            if self.store.approval_spent(&request.id)? {
                continue;
            }
            return Ok(request.id);
        }
        Err("Someone has to agree to this use first".into())
    }

    /// Whether the request behind an agreement was asked to approve a credential. A standing
    /// allowance carries the request it came from rather than the action, so the action is read
    /// back from the request itself.
    fn asked_to_use_a_credential(&self, approval_id: &str) -> Result<bool, String> {
        Ok(self.store.request(approval_id)?.is_some_and(|request| request.asked_to(Action::ApproveCredential)))
    }

    // ---- What a connector was asked to do ----
    //
    // The seam guarantees a connector cannot write to a realm, which is why a connector that fails
    // part way cannot corrupt one. These three are the other half of that: the realm writes down
    // what it is about to ask for before it asks, so a provider that moved while the hub was being
    // restarted leaves a row saying "we do not know" rather than nothing at all.

    /// Several events in one transaction, each through the same redaction gate one event goes
    /// through.
    ///
    /// `note` is the one place a reason in a realm is scrubbed, and this does exactly what it
    /// does for each entry rather than writing a second rule: a connector's own sentences are the
    /// reasons most likely to carry something a provider echoed back, so they are the last place
    /// that gate should be skipped.
    fn notes(&self, entries: Vec<Entry>) -> Result<Vec<Entry>, String> {
        let version = self.store.policy_version()?;
        Ok(entries
            .into_iter()
            .map(|entry| {
                let mut entry = entry.safe().under(version);
                if entry.command.is_none() {
                    entry.command = self.command.clone();
                }
                entry
            })
            .collect())
    }

    /// Writes down what a connector is about to be asked to do, and mints the permission it will
    /// be given.
    ///
    /// The row is written first, on purpose. If the mint fails the row is settled as refused in
    /// the next breath, and if this process dies between the two the row says "opened" with
    /// nothing ever sent, which the sweeper settles. The other order would be a permission in
    /// somebody's hand with no record that the realm ever decided anything, and that is the one
    /// state there is no way back from.
    ///
    /// What the permission is pinned to is worth stating plainly, because it is looser than the
    /// broker's. `use_credential` binds a permission to one method and one path, and a connector
    /// makes several requests for one operation: a token, a lookup, a change. The connector seam
    /// checks the credential, the destination and the expiry and does not check the method or the
    /// path, so `method` and `path` here are what the realm's grant and agreement were checked
    /// against rather than a limit on the connector. A caller that needs a per-request limit uses
    /// `core::broker`, which is one request at a time and checks all five.
    #[allow(clippy::too_many_arguments)]
    pub fn open_connector_task(
        &mut self,
        by: &str,
        principal_id: &str,
        device_id: &str,
        workload_id: &str,
        credential_id: &str,
        connector: &str,
        plan: &connector::Plan,
        method: &str,
        path: &str,
        seconds: i64,
        now: i64,
    ) -> Result<(connector::intent::Intent, String), String> {
        use connector::intent::{Intent, IntentState};
        self.allowed(by, Action::ManageCredentials)?;
        if !self.realm.can(Capability::Credentials) {
            return Err("This grid does not broker credentials".into());
        }
        if plan.connector() != connector {
            return Err(format!("This plan is for {}, and the connector being asked is {connector}", plan.connector()));
        }
        if plan.credential_id() != credential_id {
            return Err("This plan was made for another credential".into());
        }
        let credential = self.store.credential(credential_id)?.ok_or("No such credential is in this grid")?;
        if !credential.live(now) {
            return Err("This credential has been retired".into());
        }
        let destination = credential.places().first().cloned().ok_or("This credential has nowhere it may be sent; give it a destination first")?;
        let intent = Intent {
            id: format!("intent-{}", &crate::token()[..16]),
            realm_id: self.realm.id.clone(),
            connector: connector.to_owned(),
            credential_id: credential_id.to_owned(),
            destination,
            change: plan.change(),
            subject_email: plan.about().email().to_owned(),
            subject_name: plan.about().name().to_owned(),
            target: plan.target().to_owned(),
            fingerprint: plan.fingerprint(),
            principal_id: principal_id.to_owned(),
            device_id: device_id.to_owned(),
            workload_id: workload_id.to_owned(),
            state: IntentState::Opened,
            attempts: 0,
            policy_version: self.store.policy_version()?,
            opened_at: now,
            settled_at: None,
            note: String::new(),
        };
        self.store.open_intent(&intent)?;
        self.note(
            Entry::new(&self.realm.id, by, "connector.task.opened", Decision::Allowed)
                .about(Capability::Credentials, credential_id)
                .from(device_id)
                .for_work(workload_id)
                .because(&format!("{connector}: {} {} at {}", plan.change().word(), intent.subject_email, intent.target)),
            now,
        )?;
        match self.use_credential(principal_id, device_id, workload_id, credential_id, method, path, seconds, now) {
            Ok(token) => Ok((intent, token)),
            Err(said) => {
                // Nothing was sent and nothing can be: the task is settled refused in the same
                // breath, so no row is left open for a change nobody was ever allowed to make.
                self.settle_connector_task(by, &intent.id, connector::intent::Ending::Refused(said.clone()), &[], now)?;
                Err(said)
            }
        }
    }

    /// Records how a connector task ended, together with every note the connector kept.
    ///
    /// One transaction for one account of what happened: the state change and the notes land
    /// together or not at all. A history that says a task ended without saying what the connector
    /// saw is worse than one that says nothing, because somebody would believe it.
    pub fn settle_connector_task(&mut self, by: &str, intent_id: &str, ending: connector::intent::Ending, notes: &[connector::Note], now: i64) -> Result<connector::intent::Intent, String> {
        self.allowed(by, Action::ManageCredentials)?;
        let intent = self.store.intent(intent_id)?.ok_or("No connector task with that name is in this grid")?;
        let mut entries: Vec<Entry> = notes.iter().map(|note| note.entry(&self.realm.id, &intent.principal_id, &intent.credential_id).from(&intent.device_id).for_work(&intent.workload_id)).collect();
        entries.push(
            Entry::new(&self.realm.id, by, ending.action(), ending.decision())
                .about(Capability::Credentials, &intent.credential_id)
                .from(&intent.device_id)
                .for_work(&intent.workload_id)
                .because(&format!("{}: {}", intent.connector, ending.say())),
        );
        let entries = self.notes(entries)?;
        let (settled, _) = self.store.settle_intent(intent_id, ending.state(), ending.say(), entries, now, &self.key)?;
        Ok(settled)
    }

    /// Every task that may have left a provider out of step with this realm, oldest first.
    pub fn unsettled_connector_tasks(&self, by: &str) -> Result<Vec<connector::intent::Intent>, String> {
        self.allowed(by, Action::ReadAudit)?;
        self.store.unsettled_intents()
    }

    /// Every connector task this realm has recorded, newest first.
    pub fn connector_tasks(&self, by: &str) -> Result<Vec<connector::intent::Intent>, String> {
        self.allowed(by, Action::ReadAudit)?;
        self.store.intents()
    }

    /// One connector task, for the sweeper and for anybody looking at a stuck one.
    pub fn connector_task(&self, by: &str, intent_id: &str) -> Result<Option<connector::intent::Intent>, String> {
        self.allowed(by, Action::ReadAudit)?;
        self.store.intent(intent_id)
    }

    // ---- What a computer shows about itself ----

    /// Records what a computer measured about itself.
    ///
    /// Nothing here checks any of it, and the words say so: this is a computer's own report, and
    /// `hardware::trust` is where what that is worth is decided. What the realm gains by keeping
    /// it is that a computer which could not measure something says so in a sentence, so an
    /// administrator looking at an unverified computer can see whether it is unprotected or
    /// unmeasured.
    pub fn report_hardware(&mut self, device_id: &str, machine: &hardware::Machine, agent_version: &str, now: i64) -> Result<identity::Attestation, String> {
        let device = self.store.device(device_id)?.filter(|device| device.active()).ok_or("This computer is not in this grid")?;
        let attestation = hardware::attestation(machine, agent_version);
        self.store.set_attestation(device_id, &attestation)?;
        let shown = attestation.trust(now);
        self.note(
            Entry::new(&self.realm.id, &device.principal_id, "device.reported itself", Decision::Allowed)
                .from(device_id)
                .because(&format!("{}, from what this computer says about itself and nothing else", shown.word())),
            now,
        )?;
        Ok(attestation)
    }

    /// What this realm demands a computer shows before work is placed on it.
    pub fn demands_trust(&self) -> Result<hardware::Trust, String> {
        self.store.demands_trust()
    }

    /// Sets it. A security administrator's decision, and one that can lock every computer out of
    /// the realm, so the refusal sentence says that plainly when what is demanded cannot be shown
    /// by anything in this version.
    pub fn demand_trust(&mut self, by: &str, wanted: hardware::Trust, now: i64) -> Result<(), String> {
        self.allowed(by, Action::ManageSecurity)?;
        self.store.set_demands_trust(wanted)?;
        self.note(
            Entry::new(&self.realm.id, by, "realm.demands of a computer", Decision::Allowed).because(&format!(
                "{}{}",
                wanted.word(),
                if wanted > hardware::CEILING { ", which nothing in this version can show, so no computer will take work until that changes" } else { "" }
            )),
            now,
        )
    }

    /// Why this computer may not take work for this realm, in words, or nothing when it may.
    ///
    /// This comes after the rules in `workspace::may_take`, not before them, and the order is the
    /// point: those rules protect the person whose computer it is, and this one protects the
    /// realm. A computer on battery is refused because its owner would lose work; a computer that
    /// has shown nothing is refused because the realm asked for evidence.
    pub fn may_host(&self, host_id: &str, now: i64) -> Result<Option<String>, String> {
        let wanted = self.store.demands_trust()?;
        if wanted == hardware::Trust::Unverified {
            return Ok(None);
        }
        let host = self.store.host(host_id)?.ok_or("No such computer is in this grid")?;
        let device = self.store.device(&host.device_id)?.ok_or("The computer behind this one is not in this grid")?;
        Ok(hardware::why_refused(wanted, device.attestation.trust(now)))
    }

    // ---- Getting the history off this computer ----

    /// Sends the part of this realm's history that has not been sent, and marks exactly what the
    /// far end accepted.
    ///
    /// The chain is verified first, so a history somebody edited is never laundered into a
    /// customer's collector, and `exported` is called only on what the sink confirmed. That is
    /// what makes the trim rule mean anything: `Store::trim` drops events only as far as the
    /// marker, so a batch nobody confirmed is a batch still on this computer.
    ///
    /// `by` is the person this grid is acting for, and it is asked for the same permission as
    /// every other way of reading the history. The ticket is not that person and cannot stand in
    /// for one: `Ticket::read` is `Authority::peek`, which checks no signature, so everything a
    /// ticket says about who is asking is text whoever built it chose, and the identifier fields
    /// of an event are not filtered the way a free-text reason is. The ticket keeps its one honest
    /// job, which is telling a sink where it may send and until when.
    ///
    /// What it does not prove, whichever sink is used, is that the far end stored what it
    /// acknowledged. No sink in this repository has been pointed at a real collector.
    pub async fn export_history(&mut self, by: &str, sink: &dyn export::Sink, ticket: &connector::Ticket, now: i64) -> Result<u64, String> {
        self.allowed(by, Action::ReadAudit)?;
        self.verify_audit()?;
        let exported: u64 = self.store.exported_to()?;
        let waiting = self.store.events_since(exported)?;
        if waiting.is_empty() {
            return Ok(exported);
        }
        let mut reached = exported;
        for batch in waiting.chunks(export::BATCH) {
            match sink.deliver(ticket, batch, now).await {
                Ok(0) => break,
                Ok(sequence) => {
                    // Never further than the batch actually held. A sink answers with what the far
                    // end took, and a far end claiming more than it was sent must not be able to
                    // let this grid drop events nobody has a copy of.
                    let sent = batch.last().map(|event| event.sequence).unwrap_or(reached);
                    let sequence = sequence.min(sent);
                    if sequence <= reached {
                        break;
                    }
                    reached = sequence;
                    self.store.exported(sequence)?;
                }
                Err(trouble) => {
                    self.note(
                        Entry::new(&self.realm.id, by, "audit.export refused", Decision::Refused).because(&format!("{}: {}", sink.name(), trouble.say())),
                        now,
                    )?;
                    return Err(trouble.say().to_owned());
                }
            }
        }
        if reached > exported {
            self.note(
                Entry::new(&self.realm.id, by, "audit.exported", Decision::Allowed)
                    .because(&format!("{} events to {}, which confirmed up to {reached}. This grid knows they were sent and not that they were stored.", reached - exported, sink.name())),
                now,
            )?;
        }
        Ok(reached)
    }

    // ---- Workspace profile ----
    //
    // Everything about a workspace is here: what it is built from, who owns it, which computer
    // has it, where its packed-up data waits while it moves, and who is in it. What is inside one
    // is not, and cannot be: nothing below takes a file, a path or a byte of anybody's work.

    /// Records a prepared image under the realm's own catalogue.
    pub fn publish_image(&mut self, by: &str, image: Image, now: i64) -> Result<Image, String> {
        self.allowed(by, Action::ManageWorkspaces)?;
        if !self.realm.can(Capability::Workspaces) {
            return Err("This grid does not host workspaces".into());
        }
        if image.realm_id != self.realm.id {
            return Err("That image belongs to another grid".into());
        }
        self.store.put_image(&image)?;
        self.note(
            Entry::new(&self.realm.id, by, "workspace.image.published", Decision::Allowed)
                .about(Capability::Workspaces, &image.id)
                .because(&format!("{} from {}", image.describe(), image.source.word())),
            now,
        )?;
        Ok(image)
    }

    pub fn image(&self, id: &str) -> Result<Option<Image>, String> {
        self.store.image(id)
    }

    pub fn images(&self) -> Result<Vec<Image>, String> {
        self.store.images()
    }

    /// Records what a computer actually hashed, on an administrator's say-so.
    ///
    /// The computers themselves do this through `report_workspace`, which is the ordinary path;
    /// this is the door for an administrator checking the catalogue by hand.
    pub fn verify_image(&mut self, by: &str, image_id: &str, seen: &str, now: i64) -> Result<(), String> {
        self.allowed(by, Action::ManageWorkspaces)?;
        self.pin_image(by, image_id, seen, now)
    }

    /// What an image's bytes are, written down the first time anybody hashes them.
    ///
    /// The first computer to fetch an image says what it got, which is how an image named only by
    /// a tag comes to have an identity. That computer may say it because it is holding a
    /// placement of a workspace built from this image, not because of any permission it holds.
    /// Every computer after it is checked against what was written down: bytes that hash to
    /// something else are refused, said so in the history with both digests, and nothing is built
    /// from them.
    fn pin_image(&mut self, by: &str, image_id: &str, seen: &str, now: i64) -> Result<(), String> {
        let image = self.store.image(image_id)?.ok_or("No such image is in this grid")?;
        let seen = workspace::checked_digest(seen)?;
        if image.pinned() && !image.is(&seen) {
            self.note(
                Entry::new(&self.realm.id, by, "workspace.image.refused", Decision::Refused)
                    .about(Capability::Workspaces, image_id)
                    .because(&format!("this image is {} and these bytes are {seen}", image.digest.clone().unwrap_or_default())),
                now,
            )?;
            return Err("These are not that image's bytes; nothing is built from them".into());
        }
        let first = !image.pinned();
        self.store.pin_image(image_id, &seen, now)?;
        self.note(
            Entry::new(&self.realm.id, by, if first { "workspace.image.pinned" } else { "workspace.image.verified" }, Decision::Allowed)
                .about(Capability::Workspaces, image_id)
                .because(&seen),
            now,
        )
    }

    /// Takes an image out of use. Nothing is deleted, and a workspace already built from it keeps
    /// the digest it was built from, so the record still names what is running.
    pub fn retire_image(&mut self, by: &str, image_id: &str, now: i64) -> Result<(), String> {
        self.allowed(by, Action::ManageWorkspaces)?;
        self.store.retire_image(image_id, now)?;
        self.note(Entry::new(&self.realm.id, by, "workspace.image.retired", Decision::Allowed).about(Capability::Workspaces, image_id), now)
    }

    /// Orders a workspace for somebody, or for nobody yet.
    pub fn order_workspace(&mut self, by: &str, name: &str, image_id: &str, access: Access, quota: Quota, owner: Option<&str>, now: i64) -> Result<Workspace, String> {
        self.allowed(by, Action::ManageWorkspaces)?;
        if !self.realm.can(Capability::Workspaces) {
            return Err("This grid does not host workspaces".into());
        }
        if self.store.workspace_count()? >= workspace::MAX_WORKSPACES {
            return Err(format!("A grid can have at most {} workspaces", workspace::MAX_WORKSPACES));
        }
        let image = self.store.image(image_id)?.ok_or("No such image is in this grid")?;
        if !image.live() {
            return Err("That image has been retired; choose another".into());
        }
        if let Some(owner) = owner {
            let person = self.person(owner)?;
            if !person.active() {
                return Err("This account is suspended".into());
            }
        }
        let workspace = Workspace::new(&self.realm.id, name, &image, access, quota, owner, by, now)?;
        self.store.put_workspace(&workspace)?;
        self.note(
            Entry::new(&self.realm.id, by, "workspace.ordered", Decision::Allowed)
                .about(Capability::Workspaces, &workspace.id)
                .because(&format!("{} from {}", workspace.name, image.describe())),
            now,
        )?;
        Ok(workspace)
    }

    pub fn workspace(&self, id: &str) -> Result<Option<Workspace>, String> {
        self.store.workspace(id)
    }

    pub fn workspaces(&self) -> Result<Vec<Workspace>, String> {
        self.store.workspaces()
    }

    /// One person's own workspaces, which is what their portal reads.
    pub fn workspaces_of(&self, principal_id: &str) -> Result<Vec<Workspace>, String> {
        self.store.workspaces_owned_by(principal_id)
    }

    /// Where a workspace has been, newest computer first.
    pub fn workspace_trail(&self, workspace_id: &str) -> Result<Vec<String>, String> {
        self.store.trail_of(workspace_id)
    }

    pub fn workspace_placements(&self, workspace_id: &str) -> Result<Vec<Assignment>, String> {
        self.store.assignments_of(workspace_id)
    }

    pub fn workspace_sessions(&self, workspace_id: &str) -> Result<Vec<Session>, String> {
        self.store.sessions_of(workspace_id)
    }

    /// Hands a workspace to somebody, or to nobody.
    ///
    /// `from` is who the caller believes owns it now. It is compared rather than ignored, so a
    /// page left open while somebody else reassigned the workspace cannot hand the wrong
    /// person's files on. Both names go into the history, with whether the data was kept.
    pub fn assign_workspace(&mut self, by: &str, workspace_id: &str, from: Option<&str>, to: Option<&str>, data: Data, now: i64) -> Result<Workspace, String> {
        self.allowed(by, Action::ManageWorkspaces)?;
        let mut workspace = self.store.workspace(workspace_id)?.ok_or("No such workspace is in this grid")?;
        if workspace.state.finished() {
            return Err("This workspace has been archived".into());
        }
        if workspace.owner_id.as_deref() != from {
            return Err(format!(
                "This workspace belongs to {} now; read it again before handing it on",
                workspace.owner_id.as_deref().unwrap_or("nobody")
            ));
        }
        if let Some(to) = to {
            let person = self.person(to)?;
            if !person.active() {
                return Err("This account is suspended".into());
            }
        }
        // Everything handed out under the old entitlement stops here, before the owner changes.
        workspace.generation = self.store.raise_workspace_generation(workspace_id, now)?;
        self.store.end_sessions(workspace_id, "this workspace changed hands", now)?;
        workspace.owner_id = to.map(str::to_owned);
        match (to, workspace.state) {
            (None, WorkspaceState::Assigned | WorkspaceState::Running) => workspace.advance(WorkspaceState::Ready, "Unassigned; nobody may open it", now)?,
            (Some(_), WorkspaceState::Ready) => workspace.advance(WorkspaceState::Assigned, "Assigned", now)?,
            _ => workspace.updated_at = now,
        }
        if data == Data::Reset {
            self.empty_and_rebuild(&mut workspace, "Emptied and waiting to be built again", now)?;
        }
        self.store.put_workspace(&workspace)?;
        self.note(
            Entry::new(&self.realm.id, by, if to.is_some() { "workspace.assigned" } else { "workspace.access.revoked" }, Decision::Allowed)
                .about(Capability::Workspaces, workspace_id)
                .because(&format!("from {} to {}, and {}", from.unwrap_or("nobody"), to.unwrap_or("nobody"), data.say())),
            now,
        )?;
        Ok(workspace)
    }

    /// Releases a workspace's placement and its packed copies and asks for it to be built again.
    /// Nothing about the history goes; what goes is the data, which is the point.
    fn empty_and_rebuild(&mut self, workspace: &mut Workspace, note: &str, now: i64) -> Result<(), String> {
        if let Some(live) = self.store.live_assignment(&workspace.id)? {
            self.store.release_assignment(&live.id, note, now)?;
            self.store.release_for(&live.workload_id, now)?;
        }
        self.store.remove_artifacts(&workspace.id, now)?;
        if workspace.state != WorkspaceState::Requested {
            if !workspace.state.may_become(WorkspaceState::Requested) {
                workspace.advance(WorkspaceState::Draining, note, now)?;
            }
            workspace.advance(WorkspaceState::Requested, note, now)?;
        }
        workspace.attempts = 0;
        Ok(())
    }

    /// Which computer should take this workspace, and why no computer may when none can.
    ///
    /// A computer that has held this workspace's data and still fits is preferred, so a workspace
    /// goes back where its disk already is. Otherwise the fitting computer with the most room
    /// left. Four of these rules are the computer owner's protection rather than an
    /// optimisation, and they are the shipped grid's own: a computer that is going away, one on
    /// battery, one nearly out of disk and one whose person is using it when the grid was only
    /// ever lent its idle time all take nothing.
    fn workspace_host_for(&self, workspace: &Workspace, tried: &[String], now: i64) -> Result<Option<String>, String> {
        let mut fitting: Vec<(String, f64)> = Vec::new();
        let free_room = self.free_everywhere(now)?;
        let still_here = self.store.active_devices()?;
        let pledges = self.store.standing_pledges()?;
        let conditions = self.store.conditions()?;
        for host in self.store.hosts()?.iter().filter(|host| host.takes_work()) {
            if tried.contains(&host.id) {
                continue;
            }
            if !still_here.contains(&host.device_id) {
                continue;
            }
            if workspace::may_take(pledges.get(&host.id), conditions.get(&host.id)).is_some() {
                continue;
            }
            let Some(free) = free_room.get(&host.id).copied() else { continue };
            if !free.covers(&workspace.shape) {
                continue;
            }
            fitting.push((host.id.clone(), free.memory_gb));
        }
        let candidates: Vec<String> = fitting.iter().map(|(host, _)| host.clone()).collect();
        if let Some(known) = workspace::prefer(&self.store.trail_of(&workspace.id)?, &candidates) {
            return Ok(Some(known));
        }
        // Ties go to the computer that joined first, because `hosts()` returns them in that
        // order and placement that moves for no reason is worse than placement that is dull.
        fitting.sort_by(|left, right| right.1.partial_cmp(&left.1).unwrap_or(std::cmp::Ordering::Equal));
        Ok(fitting.first().map(|(host, _)| host.clone()))
    }

    /// Why no computer can take this workspace, in words somebody can act on.
    fn why_no_computer(&self, workspace: &Workspace, now: i64) -> Result<String, String> {
        let hosts = self.store.hosts()?;
        if hosts.is_empty() {
            return Ok("No computer in this grid has offered anything yet".to_owned());
        }
        let free_room = self.free_everywhere(now)?;
        let still_here = self.store.active_devices()?;
        let pledges = self.store.standing_pledges()?;
        let conditions = self.store.conditions()?;
        for host in &hosts {
            if !still_here.contains(&host.device_id) {
                return Ok("No computer in this grid can take this workspace: the computer that offered is no longer in the grid".to_owned());
            }
            if let Some(why) = workspace::may_take(pledges.get(&host.id), conditions.get(&host.id)) {
                return Ok(format!("No computer in this grid can take this workspace: {why}"));
            }
            if !free_room.get(&host.id).is_some_and(|free| free.covers(&workspace.shape)) {
                return Ok(format!("No computer in this grid has room for this workspace: it needs {} GB of disk", workspace.shape.disk_gb));
            }
        }
        Ok("No computer in this grid has room for this workspace".to_owned())
    }

    /// Places a workspace on a computer: the piece of work that will build it, the reservation it
    /// holds there, and the placement's own row, written in one change.
    pub fn place_workspace(&mut self, by: &str, workspace_id: &str, seconds: i64, now: i64) -> Result<(Workload, Lease, Assignment), String> {
        self.allowed(by, Action::PlaceWork)?;
        let mut workspace = self.store.workspace(workspace_id)?.ok_or("No such workspace is in this grid")?;
        if workspace.state != WorkspaceState::Requested {
            return Err(format!("This workspace is {} and is not waiting for a computer", workspace.state.word()));
        }
        if self.store.live_assignment(workspace_id)?.is_some() {
            return Err("This workspace is already on a computer".into());
        }
        let tried: Vec<String> = Vec::new();
        let Some(host_id) = self.workspace_host_for(&workspace, &tried, now)? else {
            return Err(self.why_no_computer(&workspace, now)?);
        };
        let host = self.store.host(&host_id)?.ok_or("No such computer is in this grid")?;
        let placed = self.lay_out(&mut workspace, &host, work::Kind::Workspace, seconds, now)?;
        self.note(
            Entry::new(&self.realm.id, by, "workspace.placed", Decision::Allowed)
                .about(Capability::Workspaces, workspace_id)
                .from(&host.device_id)
                .for_work(&placed.0.id)
                .because(&host.name),
            now,
        )?;
        Ok((placed.0, placed.1, placed.2.expect("a build always writes a placement")))
    }

    /// The one write behind every placement: admit the work, reserve room on the computer, write
    /// the placement where there is one, and say where the workspace now stands. One change, so
    /// a workspace is never reserved with no placement or placed with no reservation.
    fn lay_out(&mut self, workspace: &mut Workspace, host: &Host, kind: work::Kind, seconds: i64, now: i64) -> Result<(Workload, Lease, Option<Assignment>), String> {
        let mut work = Workload::new(
            &self.realm.id,
            Capability::Workspaces,
            kind,
            workspace.owner_id.as_deref().unwrap_or(&workspace.ordered_by),
            &host.device_id,
            workspace.shape,
            self.store.policy_version()?,
            now,
        );
        work.note = Some(format!("workspace:{}", workspace.id));
        self.admit(&mut work, now)?;
        let tried = self.tried(&work.id)?.len() as u64;
        let lease = Lease {
            id: format!("lease-{}", &crate::token()[..16]),
            realm_id: self.realm.id.clone(),
            host_id: host.id.clone(),
            workload_id: work.id.clone(),
            resources: workspace.shape,
            generation: tried + 1,
            granted_at: now,
            expires_at: now + seconds.clamp(30, work::LONGEST_WAIT),
            released_at: None,
        };
        work.lease_id = Some(lease.id.clone());
        work.advance(Stage::Leased, now)?;
        let assignment = if kind == work::Kind::Workspace {
            let next = self.store.last_placement_number(&workspace.id)? + 1;
            workspace.attempts += 1;
            workspace.advance(WorkspaceState::Provisioning, "Building on its computer", now)?;
            Some(Assignment::new(workspace, &host.id, &work.id, next, now))
        } else {
            workspace.updated_at = now;
            None
        };
        self.store.place_workspace(&work, &lease, assignment.as_ref(), workspace)?;
        Ok((work, lease, assignment))
    }

    /// The workspace counterpart of `grant_model_lease`: the door a runner takes when it is
    /// asking for a computer for a workspace rather than placing one itself.
    ///
    /// A build goes to a computer that has held this workspace's data if one still fits, and to
    /// nowhere the ordinary rule would refuse. A move goes to the computer that holds the
    /// workspace now, because that is where the data is and packing it anywhere else is not a
    /// thing that can be done.
    pub fn grant_workspace_lease(&mut self, workload_id: &str, seconds: i64, now: i64) -> Result<Lease, String> {
        let work = self.store.workload(workload_id)?.ok_or("No such work")?;
        if !matches!(work.kind, work::Kind::Workspace | work::Kind::ArtifactTransfer) || work.stage != Stage::Queued {
            return Err("Only queued workspace work is given a computer this way".into());
        }
        let workspace_id = work.note.as_deref().and_then(|note| note.strip_prefix("workspace:")).ok_or("This piece of work names no workspace")?.to_owned();
        let mut workspace = self.store.workspace(&workspace_id)?.ok_or("No such workspace is in this grid")?;
        let tried = self.tried(workload_id)?;
        if tried.len() as u64 >= work::TRIES {
            return Err(format!("This workspace has already been tried on {} computers", work::TRIES));
        }
        let host_id = if work.kind == work::Kind::ArtifactTransfer {
            self.store.live_assignment(&workspace_id)?.map(|placement| placement.host_id).ok_or("This workspace is on no computer, so there is nothing to pack up")?
        } else {
            match self.workspace_host_for(&workspace, &tried, now)? {
                Some(host_id) => host_id,
                None => return Err(self.why_no_computer(&workspace, now)?),
            }
        };
        let host = self.store.host(&host_id)?.ok_or("No such computer is in this grid")?;
        // The work has already been admitted once; what is wanted here is the reservation and the
        // placement, so the piece of work is re-used rather than a second one invented.
        let next = self.store.last_placement_number(&workspace_id)? + 1;
        let lease = Lease {
            id: format!("lease-{}", &crate::token()[..16]),
            realm_id: self.realm.id.clone(),
            host_id: host.id.clone(),
            workload_id: work.id.clone(),
            resources: work.needs,
            generation: tried.len() as u64 + 1,
            granted_at: now,
            expires_at: now + seconds.clamp(30, work::LONGEST_WAIT),
            released_at: None,
        };
        let mut work = work;
        work.lease_id = Some(lease.id.clone());
        work.advance(Stage::Leased, now)?;
        let assignment = if work.kind == work::Kind::Workspace {
            workspace.attempts += 1;
            if workspace.state.may_become(WorkspaceState::Provisioning) {
                workspace.advance(WorkspaceState::Provisioning, "Building on its computer", now)?;
            }
            Some(Assignment::new(&workspace, &host.id, &work.id, next, now))
        } else {
            workspace.updated_at = now;
            None
        };
        self.store.place_workspace(&work, &lease, assignment.as_ref(), &workspace)?;
        self.note(
            Entry::new(&self.realm.id, &work.principal_id, "workspace.work.leased", Decision::Allowed)
                .about(Capability::Workspaces, &workspace_id)
                .from(&host.device_id)
                .for_work(&work.id),
            now,
        )?;
        Ok(lease)
    }

    /// The one door a computer's report about a workspace comes through.
    ///
    /// The computer is authenticated, the pair of numbers it presents is compared by equality,
    /// and then the same comparison is made again inside the statement that writes. A computer
    /// that has been left behind is refused with words it can act on, because a refusal that
    /// says nothing leaves a host asking the same stale question for ever.
    pub fn report_workspace(&mut self, device_id: &str, claim: &Claim, report: Report, now: i64) -> Result<WorkspaceState, String> {
        let device = self.store.device(device_id)?.filter(|device| device.active()).ok_or("This computer is not in this grid")?;
        self.store.host(&claim.host_id)?.filter(|host| host.device_id == device.id).ok_or("That is not this computer's workspace")?;
        let mut workspace = self.store.workspace(&claim.workspace_id)?.ok_or("No such workspace is in this grid")?;
        let superseded = "this placement was superseded; ask for your orders again";
        let Some(assignment) = self.store.live_assignment(&claim.workspace_id)?.filter(|placement| claim.matches(&workspace, placement)) else {
            self.note(
                Entry::new(&self.realm.id, &device.principal_id, "workspace.report.refused", Decision::Refused)
                    .about(Capability::Workspaces, &claim.workspace_id)
                    .from(device_id)
                    .because(superseded),
                now,
            )?;
            return Err("This placement was superseded; ask for your orders again".into());
        };
        if report.state == Reported::Parked {
            return Err(PARKING.into());
        }
        let placement_ref = match report.placement_ref.as_deref() {
            Some(raw) => Some(workspace::checked_placement_ref(raw)?),
            None => None,
        };
        let ready = matches!(report.state, Reported::Ready);
        if !self.store.claim_placement(claim, placement_ref.as_deref(), ready, now)? {
            self.note(
                Entry::new(&self.realm.id, &device.principal_id, "workspace.report.refused", Decision::Refused)
                    .about(Capability::Workspaces, &claim.workspace_id)
                    .from(device_id)
                    .because(superseded),
                now,
            )?;
            return Err("This placement was superseded; ask for your orders again".into());
        }
        if let Some(seen) = report.image_digest.as_deref() {
            self.pin_image(&device.principal_id, &workspace.image_id, seen, now)?;
            workspace.image_digest = self.store.image(&workspace.image_id)?.and_then(|image| image.digest);
        }
        match report.state {
            Reported::Building => {
                if workspace.state.may_become(WorkspaceState::Provisioning) {
                    workspace.advance(WorkspaceState::Provisioning, "Building on its computer", now)?;
                }
            }
            Reported::Adopted => {
                if let Some(waiting) = self.store.waiting_artifact(&workspace.id)? {
                    self.store.take_artifact(&waiting.id, now)?;
                }
                self.store.remove_artifacts(&workspace.id, now)?;
                if workspace.state.may_become(WorkspaceState::Provisioning) {
                    workspace.advance(WorkspaceState::Provisioning, "Starting on its new computer", now)?;
                }
            }
            Reported::Ready => {
                let next = if workspace.owner_id.is_some() { WorkspaceState::Assigned } else { WorkspaceState::Ready };
                if workspace.state.may_become(next) {
                    workspace.advance(next, "Ready", now)?;
                }
            }
            Reported::Failed => {
                self.store.release_assignment(&assignment.id, "the computer could not build it", now)?;
                self.store.release_for(&assignment.workload_id, now)?;
                workspace.advance(WorkspaceState::Failed, "The computer could not build it", now)?;
            }
            Reported::Gone => {
                self.store.release_assignment(&assignment.id, "the computer no longer has it", now)?;
                self.store.release_for(&assignment.workload_id, now)?;
                // Lost once is a computer that was reinstalled; lost again and again is a
                // computer that cannot keep it, and saying so is better than trying for ever.
                let retry = u64::from(workspace.attempts) < work::TRIES;
                if retry {
                    self.empty_and_rebuild(&mut workspace, "Its computer no longer has it; finding a computer again", now)?;
                } else {
                    workspace.advance(WorkspaceState::Failed, "Its computer lost it repeatedly", now)?;
                }
            }
            // Refused above, before anything was written; the arm is here so the match stays
            // honest rather than ending in something that would panic.
            Reported::Parked => return Err(PARKING.into()),
        }
        self.store.put_workspace(&workspace)?;
        self.note(
            Entry::new(&self.realm.id, &device.principal_id, &format!("workspace.{}", workspace.state.word()), Decision::Allowed)
                .about(Capability::Workspaces, &workspace.id)
                .from(device_id)
                .for_work(&assignment.workload_id)
                .because(report.state.say()),
            now,
        )?;
        Ok(workspace.state)
    }

    /// Moves a workspace on by hand, through the steps that are written down.
    pub fn advance_workspace(&mut self, by: &str, workspace_id: &str, next: WorkspaceState, note: &str, now: i64) -> Result<WorkspaceState, String> {
        self.allowed(by, Action::ManageWorkspaces)?;
        let mut workspace = self.store.workspace(workspace_id)?.ok_or("No such workspace is in this grid")?;
        workspace.advance(next, note, now)?;
        self.store.put_workspace(&workspace)?;
        self.note(
            Entry::new(&self.realm.id, by, &format!("workspace.{}", next.word()), Decision::Allowed).about(Capability::Workspaces, workspace_id).because(note),
            now,
        )?;
        Ok(workspace.state)
    }

    /// Starts a hand-off: the workspace is emptied off the computer it is on, with its data.
    ///
    /// It keeps running for its owner until the computer reports the data packed, because the
    /// alternative is taking somebody's desk away and then finding out the copy failed.
    pub fn move_workspace(&mut self, by: &str, workspace_id: &str, reason: &str, now: i64) -> Result<Workload, String> {
        self.allowed(by, Action::PlaceWork)?;
        let mut workspace = self.store.workspace(workspace_id)?.ok_or("No such workspace is in this grid")?;
        let Some(placement) = self.store.live_assignment(workspace_id)? else {
            return Err("This workspace is on no computer, so there is nothing to move".into());
        };
        if workspace.quota.artifact_gb <= 0.0 || workspace.shape.disk_gb > workspace::LARGEST_PARCEL_GB {
            return Err(format!(
                "Too large to move: its disk is {} GB and a move passes through the hub, which carries {} GB",
                workspace.shape.disk_gb,
                workspace::LARGEST_PARCEL_GB
            ));
        }
        let host = self.store.host(&placement.host_id)?.ok_or("No such computer is in this grid")?;
        if workspace.state.may_become(WorkspaceState::Draining) {
            workspace.advance(WorkspaceState::Draining, "Its computer is giving it up; moving the workspace with its data", now)?;
        }
        let (work, _, _) = self.lay_out(&mut workspace, &host, work::Kind::ArtifactTransfer, work::ANSWER_WITHIN, now)?;
        self.note(
            Entry::new(&self.realm.id, by, "workspace.moving", Decision::Allowed)
                .about(Capability::Workspaces, workspace_id)
                .from(&host.device_id)
                .for_work(&work.id)
                .because(reason),
            now,
        )?;
        Ok(work)
    }

    /// Records that a computer packed a workspace's data up: where it put it, how large it is and
    /// what it hashes to. The bytes themselves never reach here and there is nowhere to put them.
    pub fn park_workspace(
        &mut self,
        device_id: &str,
        claim: &Claim,
        store: ArtifactStore,
        destination: &str,
        object_key: &str,
        bytes: u64,
        sha256: &str,
        now: i64,
    ) -> Result<Artifact, String> {
        let device = self.store.device(device_id)?.filter(|device| device.active()).ok_or("This computer is not in this grid")?;
        self.store.host(&claim.host_id)?.filter(|host| host.device_id == device.id).ok_or("That is not this computer's workspace")?;
        let mut workspace = self.store.workspace(&claim.workspace_id)?.ok_or("No such workspace is in this grid")?;
        let Some(placement) = self.store.live_assignment(&claim.workspace_id)?.filter(|placement| claim.matches(&workspace, placement)) else {
            self.note(
                Entry::new(&self.realm.id, &device.principal_id, "workspace.report.refused", Decision::Refused)
                    .about(Capability::Workspaces, &claim.workspace_id)
                    .from(device_id)
                    .because("this placement was superseded; ask for your orders again"),
                now,
            )?;
            return Err("This placement was superseded; ask for your orders again".into());
        };
        let artifact = Artifact::new(&workspace, store, destination, object_key, bytes, sha256, &claim.host_id, now)?;
        self.store.put_artifact(&artifact)?;
        self.store.release_assignment(&placement.id, "its data was packed up and moved", now)?;
        self.store.release_for(&placement.workload_id, now)?;
        self.ask_for_a_computer_again(&mut workspace, "Its data is packed and waiting for a computer with room", now)?;
        self.store.put_workspace(&workspace)?;
        self.note(
            Entry::new(&self.realm.id, &device.principal_id, "workspace.parked", Decision::Allowed)
                .about(Capability::Workspaces, &workspace.id)
                .from(device_id)
                .because(&format!("{} bytes with the {}", artifact.bytes, artifact.store.word())),
            now,
        )?;
        Ok(artifact)
    }

    /// Puts a workspace back in the queue for a computer without touching its data. The packed
    /// copy stays where it is, because that copy is the data and keeping it is the whole point of
    /// a move.
    ///
    /// The sign-ins close here. A sign-in is bound to the placement it was opened against, so one
    /// left open once the placement has gone could never be used again, and it would still count
    /// against the number of people this workspace allows at once and keep its own owner out. The
    /// desk is still hers; she opens it again once it has a computer. Callers that closed the
    /// sign-ins before reaching here lose nothing by it, because only a sign-in that is still
    /// open is touched.
    fn ask_for_a_computer_again(&mut self, workspace: &mut Workspace, note: &str, now: i64) -> Result<(), String> {
        self.store.end_sessions(&workspace.id, "the workspace left its computer, so it must be opened again", now)?;
        if workspace.state != WorkspaceState::Requested {
            if !workspace.state.may_become(WorkspaceState::Requested) {
                workspace.advance(WorkspaceState::Draining, note, now)?;
            }
            workspace.advance(WorkspaceState::Requested, note, now)?;
        }
        workspace.attempts = 0;
        Ok(())
    }

    /// Hands the computer taking a workspace over the key and the checksum for its packed data.
    pub fn adopt_workspace(&mut self, device_id: &str, claim: &Claim, now: i64) -> Result<Artifact, String> {
        let device = self.store.device(device_id)?.filter(|device| device.active()).ok_or("This computer is not in this grid")?;
        self.store.host(&claim.host_id)?.filter(|host| host.device_id == device.id).ok_or("That is not this computer's workspace")?;
        let workspace = self.store.workspace(&claim.workspace_id)?.ok_or("No such workspace is in this grid")?;
        if !self.store.live_assignment(&claim.workspace_id)?.is_some_and(|placement| claim.matches(&workspace, &placement)) {
            return Err("This placement was superseded; ask for your orders again".into());
        }
        let artifact = self.store.waiting_artifact(&claim.workspace_id)?.ok_or("This workspace has no packed copy waiting")?;
        self.store.take_artifact(&artifact.id, now)?;
        self.note(
            Entry::new(&self.realm.id, &device.principal_id, "workspace.adopted", Decision::Allowed)
                .about(Capability::Workspaces, &workspace.id)
                .from(device_id)
                .because(&format!("{} bytes from the {}", artifact.bytes, artifact.store.word())),
            now,
        )?;
        Ok(artifact)
    }

    /// Empties a workspace and builds it again from the same image. The person keeps the
    /// workspace; what goes is everything in it.
    pub fn reset_workspace(&mut self, by: &str, workspace_id: &str, reason: &str, now: i64) -> Result<Workspace, String> {
        self.allowed(by, Action::ManageWorkspaces)?;
        let mut workspace = self.store.workspace(workspace_id)?.ok_or("No such workspace is in this grid")?;
        if workspace.state.finished() {
            return Err("This workspace has been archived".into());
        }
        workspace.generation = self.store.raise_workspace_generation(workspace_id, now)?;
        self.store.end_sessions(workspace_id, "this workspace was emptied", now)?;
        self.empty_and_rebuild(&mut workspace, "Emptied and waiting to be built again", now)?;
        workspace.reset_count += 1;
        self.store.put_workspace(&workspace)?;
        self.note(
            Entry::new(&self.realm.id, by, "workspace.reset", Decision::Allowed).about(Capability::Workspaces, workspace_id).because(reason),
            now,
        )?;
        Ok(workspace)
    }

    /// Builds a workspace from a different image, with or without what is in it now.
    ///
    /// Keeping the data means building again where the data is. Until somebody packs a workspace
    /// up there is only one copy of it, the disk on the computer holding it, so this stays on
    /// that computer rather than returning the workspace to the open queue, which would pass that
    /// computer over whenever its person was using it and build an empty workspace elsewhere.
    pub fn rebuild_workspace(&mut self, by: &str, workspace_id: &str, image_id: &str, data: Data, now: i64) -> Result<Workspace, String> {
        self.allowed(by, Action::ManageWorkspaces)?;
        let mut workspace = self.store.workspace(workspace_id)?.ok_or("No such workspace is in this grid")?;
        if workspace.state.finished() {
            return Err("This workspace has been archived".into());
        }
        let image = self.store.image(image_id)?.ok_or("No such image is in this grid")?;
        if !image.live() {
            return Err("That image has been retired; choose another".into());
        }
        if !workspace.quota.allows(&image.shape) {
            return Err(format!("This image needs {} GB of disk and this workspace allows {}", image.shape.disk_gb, workspace.quota.disk_gb));
        }
        let was = workspace.image_digest.clone().unwrap_or_else(|| "bytes nobody has hashed yet".to_owned());
        // Worked out before anything is written, so a refusal changes nothing and nobody is put
        // out of a workspace that then stays where it was.
        let live = self.store.live_assignment(workspace_id)?;
        let stay = match (data, &live) {
            (Data::Keep, Some(on)) if self.store.waiting_artifact(workspace_id)?.is_none() => {
                let host = self.store.host(&on.host_id)?.ok_or("No such computer is in this grid")?;
                if let Some(why) = workspace::may_take(self.store.standing_pledge(&host.id)?.as_ref(), self.store.condition(&host.id)?.as_ref()) {
                    return Err(format!(
                        "What is in this workspace is only on {}, and that computer cannot take work right now: {why}. Move it first, or build it again empty.",
                        host.name
                    ));
                }
                // The build below is admitted in the owner's name, as every placement of this
                // workspace is, so whatever would refuse it is asked here, through the one place
                // that decides it, rather than after the workspace has left its computer.
                let mut asking = Workload::new(
                    &self.realm.id,
                    Capability::Workspaces,
                    work::Kind::Workspace,
                    workspace.owner_id.as_deref().unwrap_or(&workspace.ordered_by),
                    &host.device_id,
                    workspace.shape,
                    1,
                    now,
                );
                self.admit(&mut asking, now)?;
                Some(host)
            }
            _ => None,
        };
        workspace.generation = self.store.raise_workspace_generation(workspace_id, now)?;
        self.store.end_sessions(workspace_id, "this workspace is being built again", now)?;
        workspace.image_id = image.id.clone();
        workspace.image_digest = image.digest.clone();
        workspace.shape = image.shape;
        match data {
            Data::Reset => self.empty_and_rebuild(&mut workspace, "Being built again from another image", now)?,
            Data::Keep => {
                if let Some(on) = &live {
                    self.store.release_assignment(&on.id, "it is being built again from another image", now)?;
                    self.store.release_for(&on.workload_id, now)?;
                }
                self.ask_for_a_computer_again(&mut workspace, "Being built again from another image, keeping its data", now)?;
                if let Some(host) = stay {
                    self.lay_out(&mut workspace, &host, work::Kind::Workspace, work::ANSWER_WITHIN, now)?;
                }
            }
        }
        self.store.put_workspace(&workspace)?;
        self.note(
            Entry::new(&self.realm.id, by, "workspace.rebuilt", Decision::Allowed)
                .about(Capability::Workspaces, workspace_id)
                .because(&format!("from {was} to {}, and {}", image.digest.clone().unwrap_or_else(|| "bytes nobody has hashed yet".to_owned()), data.say())),
            now,
        )?;
        Ok(workspace)
    }

    /// Takes a workspace out of use. The record and every event about it stay; the data is let go.
    /// This is what the product's delete calls.
    pub fn archive_workspace(&mut self, by: &str, workspace_id: &str, reason: &str, now: i64) -> Result<Workspace, String> {
        self.allowed(by, Action::ManageWorkspaces)?;
        let mut workspace = self.store.workspace(workspace_id)?.ok_or("No such workspace is in this grid")?;
        if workspace.state.finished() {
            return Err("This workspace has already been archived".into());
        }
        workspace.generation = self.store.raise_workspace_generation(workspace_id, now)?;
        self.store.end_sessions(workspace_id, "this workspace was archived", now)?;
        if let Some(live) = self.store.live_assignment(workspace_id)? {
            self.store.release_assignment(&live.id, "the workspace was archived", now)?;
            self.store.release_for(&live.workload_id, now)?;
        }
        self.store.remove_artifacts(workspace_id, now)?;
        workspace.advance(WorkspaceState::Archived, "Archived", now)?;
        self.store.put_workspace(&workspace)?;
        self.note(
            Entry::new(&self.realm.id, by, "workspace.archived", Decision::Allowed).about(Capability::Workspaces, workspace_id).because(reason),
            now,
        )?;
        Ok(workspace)
    }

    /// Removes a workspace's row, which is only allowed once it has been archived.
    ///
    /// The record of where it has been goes with it. That is said plainly rather than implied:
    /// forgetting a workspace leaves the sealed history, which still names the workspace, who
    /// owned it and everyone who decided anything about it, and nothing else.
    pub fn forget_workspace(&mut self, by: &str, workspace_id: &str, now: i64) -> Result<(), String> {
        self.allowed(by, Action::ManageWorkspaces)?;
        let workspace = self.store.workspace(workspace_id)?.ok_or("No such workspace is in this grid")?;
        self.store.forget_workspace(workspace_id)?;
        self.note(
            Entry::new(&self.realm.id, by, "workspace.forgotten", Decision::Allowed)
                .about(Capability::Workspaces, workspace_id)
                .because(&format!("{} is gone, and the record of where it had been with it", workspace.name)),
            now,
        )
    }

    /// Mints a short permission for somebody to open their own workspace.
    ///
    /// The permission is bound to the piece of work that is running the workspace on its
    /// computer, because that is the work this sign-in belongs to and `Authority::accept` is
    /// checked against it. Everything else is looked at here and again at the moment of use.
    pub fn open_workspace(&mut self, principal_id: &str, device_id: &str, workspace_id: &str, seconds: i64, now: i64) -> Result<String, String> {
        if !self.realm.can(Capability::Workspaces) {
            return Err("This grid does not host workspaces".into());
        }
        if !self.realm.lifecycle.serves() {
            return Err("This grid is not serving work at the moment".into());
        }
        // A suspended account is told so, and a withdrawn role bites here rather than waiting for
        // somebody to notice the owner field.
        let person = self.person(principal_id)?;
        if !person.active() {
            return Err("This account is suspended".into());
        }
        self.allowed(principal_id, Action::UseWorkspace)?;
        let device = self.store.device(device_id)?.filter(|device| device.active()).ok_or("This computer is not in this grid")?;
        if device.principal_id != principal_id {
            return Err("That computer belongs to someone else".into());
        }
        let mut workspace = self.store.workspace(workspace_id)?.ok_or("No such workspace is in this grid")?;
        if !workspace.owned_by(principal_id) {
            return Err("This workspace is not theirs".into());
        }
        if !workspace.state.open_to_its_owner() {
            return Err(format!("This workspace is {} and cannot be opened", workspace.state.word()));
        }
        let placement = self.store.live_assignment(workspace_id)?.ok_or("This workspace is on no computer just now")?;
        let host = self.store.host(&placement.host_id)?.ok_or("No such computer is in this grid")?;
        if !self.store.device(&host.device_id)?.is_some_and(|device| device.active()) {
            return Err("The computer holding this workspace is no longer in this grid".into());
        }
        self.store.end_lapsed_sessions(now)?;
        if self.store.live_sessions(workspace_id, now)? >= workspace.quota.sessions as usize {
            return Err(format!("This workspace allows {} people in it at once", workspace.quota.sessions));
        }
        let mut claims = Claims::new(&self.realm.id, Capability::Workspaces, principal_id, device_id, &placement.workload_id, workspace_id, now, seconds.min(workspace.quota.session_seconds));
        // A sign-in is held for its whole length and shown again whenever the computer asks, so
        // it is not spent on first use. What takes it away is closing it, which also moves the
        // workspace on a generation, and that is refused everywhere rather than only here.
        claims.single_use = false;
        let token = self.mint(&claims)?;
        self.store.open_session(&Session {
            capability_id: claims.id.clone(),
            realm_id: self.realm.id.clone(),
            workspace_id: workspace_id.to_owned(),
            principal_id: principal_id.to_owned(),
            device_id: device_id.to_owned(),
            host_id: host.id.clone(),
            workspace_generation: workspace.generation,
            assignment_generation: placement.generation,
            opened_at: now,
            expires_at: claims.expires_at,
            ended_at: None,
            ended_reason: String::new(),
        })?;
        if workspace.state == WorkspaceState::Assigned {
            workspace.advance(WorkspaceState::Running, "Its person is in it", now)?;
            self.store.put_workspace(&workspace)?;
        }
        self.note(
            Entry::new(&self.realm.id, principal_id, "workspace.opened", Decision::Allowed)
                .about(Capability::Workspaces, workspace_id)
                .from(device_id)
                .for_work(&placement.workload_id),
            now,
        )?;
        Ok(token)
    }

    /// Accepts a permission to be in a workspace, at the moment it is used.
    ///
    /// `accept` has already re-read the account, the computer, the realm, the policy and the
    /// workspace's own generation from the database. What is left is the pair of facts only this
    /// profile knows: that the sign-in has not been closed, and that the workspace is still
    /// theirs, still open to them and still on the computer the sign-in named.
    ///
    /// Whether the grid is serving at all is asked first, before the permission is accepted, so
    /// that pausing a grid stops the sign-ins people are already holding rather than only the
    /// next one they ask for, and so the history does not record a use as allowed and then refuse
    /// it. This is the same question the three entry doors ask.
    pub fn use_workspace(&mut self, token: &str, attempt: &Attempt<'_>, now: i64) -> Result<(Claims, Workspace), String> {
        if !self.realm.lifecycle.serves() {
            return Err("This grid is not serving work at the moment".into());
        }
        let claims = self.accept(token, attempt, now)?;
        if claims.capability != Capability::Workspaces {
            return Err("This permission is not for a workspace".into());
        }
        let session = self.store.session(&claims.id)?.ok_or("This grid has no record of this sign-in")?;
        if !session.live(now) {
            return Err(format!("This sign-in was closed: {}", if session.ended_reason.is_empty() { "it is no longer valid" } else { &session.ended_reason }));
        }
        let workspace = self.store.workspace(&claims.resource_id)?.ok_or("No such workspace is in this grid")?;
        if !workspace.owned_by(&claims.principal_id) {
            return Err("This workspace is not theirs".into());
        }
        if !workspace.state.open_to_its_owner() {
            return Err(format!("This workspace is {} and cannot be opened", workspace.state.word()));
        }
        let placement = self.store.live_assignment(&workspace.id)?.ok_or("This workspace is on no computer just now")?;
        if placement.generation != session.assignment_generation || placement.host_id != session.host_id {
            return Err("This workspace has moved to another computer; open it again".into());
        }
        Ok((claims, workspace))
    }

    /// Ends every live sign-in to a workspace and moves the workspace on a generation, so that
    /// taking somebody out of a workspace is a push and not only something noticed next time.
    pub fn close_workspace_sessions(&mut self, by: &str, workspace_id: &str, reason: &str, now: i64) -> Result<usize, String> {
        self.allowed(by, Action::ManageWorkspaces)?;
        let ended = self.store.end_sessions(workspace_id, reason, now)?;
        self.store.raise_workspace_generation(workspace_id, now)?;
        self.note(
            Entry::new(&self.realm.id, by, "workspace.sessions.closed", Decision::Allowed).about(Capability::Workspaces, workspace_id).because(reason),
            now,
        )?;
        Ok(ended.len())
    }

    /// Closes the sign-ins whose permission has run out, beside `expire` and `expire_approvals`.
    pub fn expire_workspace_sessions(&mut self, now: i64) -> usize {
        self.store.end_lapsed_sessions(now).unwrap_or(0)
    }

    /// The packed copies nobody has been able to take for long enough that somebody should know.
    /// The data is safe; what is wrong is that no computer has had room for a day.
    pub fn stuck_parcels(&self, now: i64) -> Result<Vec<Artifact>, String> {
        self.store.stuck_artifacts(now - workspace::PARCEL_PATIENCE)
    }

    /// A computer is gone, with whatever it was holding.
    ///
    /// Every workspace it had keeps its owner, its image and its trail. One whose data can still
    /// be found, because a copy was packed or because another computer that has held it is still
    /// in the grid, waits for a computer. One whose data was only ever on that computer has
    /// failed, and the record says exactly that rather than implying it can be recovered.
    pub fn host_lost(&mut self, by: &str, host_id: &str, reason: &str, now: i64) -> Result<Vec<String>, String> {
        self.allowed(by, Action::DrainHost)?;
        self.store.set_draining(host_id, true)?;
        self.workspaces_off(by, host_id, reason, now)
    }

    /// The one path behind every way a computer stops holding workspaces: it was lost, its
    /// commitment was withdrawn, or it was taken out of the grid.
    fn workspaces_off(&mut self, by: &str, host_id: &str, reason: &str, now: i64) -> Result<Vec<String>, String> {
        let held = self.store.release_assignments_on(host_id, reason, now)?;
        let mut affected = Vec::new();
        for workspace_id in held {
            let Some(mut workspace) = self.store.workspace(&workspace_id)? else { continue };
            if workspace.state.finished() {
                continue;
            }
            self.store.end_sessions(&workspace_id, reason, now)?;
            let parked = self.store.waiting_artifact(&workspace_id)?.is_some();
            let elsewhere = {
                let mut found = false;
                for previous in self.store.trail_of(&workspace_id)?.into_iter().filter(|previous| previous != host_id) {
                    if self.store.host(&previous)?.is_some() {
                        found = true;
                        break;
                    }
                }
                found
            };
            if parked || elsewhere {
                self.ask_for_a_computer_again(&mut workspace, "Waiting for a computer with room", now)?;
            } else {
                workspace.advance(WorkspaceState::Failed, "Its data was only on a computer that stopped answering", now)?;
            }
            self.store.put_workspace(&workspace)?;
            self.note(
                Entry::new(&self.realm.id, by, "workspace.host_lost", Decision::Allowed)
                    .about(Capability::Workspaces, &workspace_id)
                    .because(&format!("{reason}; it is now {}", workspace.state.word())),
                now,
            )?;
            affected.push(workspace_id);
        }
        Ok(affected)
    }

    /// Commits a computer to the realm, explicitly and in words.
    ///
    /// What is agreed is written down as a sentence and never edited. Dedicating a computer means
    /// the realm decides what runs on it; it does not mean the realm may read what is on it, and
    /// the agreed wording says so out loud to whoever is agreeing.
    pub fn commit_host(&mut self, by: &str, host_id: &str, commitment: Commitment, offered: Resources, idle_only: bool, now: i64) -> Result<Pledge, String> {
        self.allowed(by, Action::DrainHost)?;
        let mut host = self.store.host(host_id)?.ok_or("No such computer is in this grid")?;
        if !host.capacity.covers(&offered) {
            return Err("A computer cannot offer more than it has".into());
        }
        // Taking back what was agreed before is part of agreeing to something else, and both
        // halves stay in the record.
        self.store.withdraw_pledge(host_id, by, now)?;
        let pledge = Pledge::new(&self.realm.id, host_id, commitment, offered, idle_only, by, now);
        self.store.put_pledge(&pledge)?;
        host.commitment = commitment;
        host.offered = offered;
        self.store.put_host(&host)?;
        self.note(
            Entry::new(&self.realm.id, by, "host.committed", Decision::Allowed).about(Capability::Workspaces, host_id).because(&pledge.wording),
            now,
        )?;
        Ok(pledge)
    }

    /// Takes a commitment back. The computer stops taking new work, every workspace on it is
    /// moved off, and what it is committed to becomes nothing. Both halves are in the record, so
    /// what was agreed and what was taken back can both be read later.
    pub fn withdraw_commitment(&mut self, by: &str, host_id: &str, reason: &str, now: i64) -> Result<(), String> {
        self.allowed(by, Action::DrainHost)?;
        let mut host = self.store.host(host_id)?.ok_or("No such computer is in this grid")?;
        if self.store.withdraw_pledge(host_id, by, now)? == 0 {
            return Err("This computer has made no commitment to take back".into());
        }
        self.store.set_draining(host_id, true)?;
        self.workspaces_off(by, host_id, reason, now)?;
        host.commitment = Commitment::None;
        host.draining = true;
        self.store.put_host(&host)?;
        self.note(
            Entry::new(&self.realm.id, by, "host.commitment.withdrawn", Decision::Allowed).about(Capability::Workspaces, host_id).because(reason),
            now,
        )
    }

    /// Every commitment a computer has made and taken back, newest last.
    pub fn commitments(&self, host_id: &str) -> Result<Vec<Pledge>, String> {
        self.store.commitments(host_id)
    }

    /// What a computer last said about itself, which is what decides whether a workspace may be
    /// placed on it at all. A computer speaks only for itself: the host is found from the
    /// computer presenting the report, never taken from the report.
    pub fn report_condition(&mut self, device_id: &str, on_battery: bool, free_disk_gb: f64, in_use: bool, going_away: bool, now: i64) -> Result<Condition, String> {
        let device = self.store.device(device_id)?.filter(|device| device.active()).ok_or("This computer is not in this grid")?;
        let host = self.store.host_of_device(&device.id)?.ok_or("This computer offers nothing to this grid")?;
        let condition = Condition::new(&host.id, on_battery, free_disk_gb, in_use, going_away, now);
        self.store.put_condition(&self.realm.id, &condition)?;
        Ok(condition)
    }

    /// Everything the workspace profile holds, in the one shape a realm travels in, and one event
    /// saying it was read and how far the history had got.
    ///
    /// Metadata only: a record carries no file, no prompt and no secret, and the parts of it that
    /// belong to other profiles are deliberately left empty here.
    pub fn export_workspaces(&mut self, by: &str, now: i64) -> Result<Record, String> {
        self.allowed(by, Action::ReadRealm)?;
        let mut record = Record::new(self.realm.clone());
        record.images = self.store.images()?;
        record.workspaces = self.store.workspaces()?;
        record.assignments = self.store.assignments()?;
        record.artifacts = self.store.artifacts()?;
        record.commitments = self.store.all_commitments()?;
        let (sequence, _) = self.store.head()?;
        self.note(
            Entry::new(&self.realm.id, by, "workspace.exported", Decision::Allowed)
                .about(Capability::Workspaces, &self.realm.id)
                .because(&format!("{} workspaces and {} images, with the history at {sequence}", record.workspaces.len(), record.images.len())),
            now,
        )?;
        Ok(record)
    }

    // ---- Keeping and restoring ----

    /// Takes a backup: everything the realm holds, sealed with the realm's key, which must be
    /// supplied again to restore it. The key itself is never in the backup.
    pub fn backup(&self, now: i64) -> Result<store::Backup, String> {
        Ok(store::backup(&self.snapshot()?, &self.store.key_reference()?, &self.key, now))
    }

    /// An exact copy of this realm's database, taken while it is open.
    ///
    /// This is the hourly backup: SQLite's own consistent copy, which survives a crash and a bad
    /// write. Two things about it have to be said plainly rather than left in a runbook. It is the
    /// same shape as the original, so it does not survive a bad migration; that is what the
    /// portable backup is for. And it is a plain readable realm database, exactly as sensitive as
    /// the folder the realm lives in, so where it is written matters as much as whether it is
    /// written.
    pub fn copy_to(&self, path: &Path) -> Result<(), String> {
        self.store.copy_to(path)
    }

    /// Brings the realm's database up to this build's shape, taking a copy first.
    ///
    /// Migration is already safe step by step: each step and the record of having run it are one
    /// transaction, so a step that fails leaves the realm at the version it was at. What a copy
    /// adds is the case the transaction cannot help with, which is a step that runs perfectly and
    /// turns out to have been the wrong idea. The copy is taken only when there is something to
    /// do, and its path is returned so a runbook can name it.
    pub fn upgrade_with_a_copy(&mut self, folder: &Path, now: i64) -> Result<(Option<PathBuf>, Vec<u32>), String> {
        let at = self.store.version()?;
        if at >= store::SCHEMA_VERSION {
            return Ok((None, Vec::new()));
        }
        let copy = folder.join(format!("before-version-{}-at-{now}.db", at + 1));
        self.store.copy_to(&copy)?;
        self.store.migrate()?;
        Ok((Some(copy), ((at + 1)..=store::SCHEMA_VERSION).collect()))
    }

    /// Whether a version can be taken back out, and what to do when it cannot.
    ///
    /// A sentence rather than a boolean, because "no" here means "the copy is the only way back"
    /// and an operator reading a runbook needs to be told that, not left to work it out.
    pub fn how_to_undo(version: u32) -> String {
        match store::schema::rollback(version) {
            Some(_) => format!("Version {version} can be taken back out with this build"),
            None => format!("Version {version} was not written with a way back; the copy taken before the upgrade is the only way back"),
        }
    }

    /// Restores a backup into a folder of its own and says what came back, without touching any
    /// realm that is already here. The restore drill.
    ///
    /// `Core::restore` already refuses a path that exists, so a drill cannot land on a live realm
    /// by accident. What this adds is the report, and in particular the list of what a restore
    /// does not bring back, which is the part of a drill worth rehearsing: a drill that does not
    /// say those out loud teaches the wrong lesson about what a backup is.
    pub fn rehearse_restore(folder: &Path, backup: store::Backup, key: &str, now: i64) -> Result<RestoreReport, String> {
        let taken_at = backup.taken_at;
        let into = folder.join(format!("drill-{now}.db"));
        let restored = Core::restore(&into, backup, key)?;
        let report = RestoreReport {
            realm_id: restored.realm.id.clone(),
            realm_name: restored.realm.name.clone(),
            taken_at,
            schema_version: restored.store.version()?,
            counts: restored.store.counts()?,
            head_sequence: restored.store.head()?.0,
            history_verified: restored.verify_audit().is_ok(),
            faults: restored.check_storage()?,
            not_restored: NOT_RESTORED.iter().map(|said| (*said).to_owned()).collect(),
            kept_at: into,
        };
        restored.close()?;
        Ok(report)
    }

    /// Everything an engineer needs to look at an incident, and nothing anybody would mind
    /// sharing.
    ///
    /// Identifiers, counts and the words this code itself writes. There is no name, no path, no
    /// prompt and no value anywhere in it: the events carry decisions and reasons, and a reason
    /// has been through `Entry::safe` before it was ever written.
    pub fn evidence(&self, since: u64, now: i64) -> Result<Evidence, String> {
        Ok(Evidence {
            realm_id: self.realm.id.clone(),
            at: now,
            checkup: self.ready(now),
            reading: self.reading(now)?,
            migrations: self.store.history()?,
            recent: self.store.events_since(since)?.iter().map(Happened::of).collect(),
            stuck: self.stuck_parcels(now)?.into_iter().map(|parcel| parcel.id).collect(),
        })
    }

    /// Puts a backup on this computer as the realm it was taken from, with its key. The history
    /// is carried across sealed as it was, so it still verifies.
    pub fn restore(path: &Path, backup: store::Backup, key: &str) -> Result<Core, String> {
        let (record, reference) = store::restore(backup, key)?;
        let store = Store::import(path, &record, &reference, crate::now())?;
        let realm = store.realm()?;
        let authority = Authority::new(&realm.id, key);
        Ok(Core { store, realm, authority, key: key.to_owned(), command: None })
    }

    /// Checks the realm's history is whole: every seal, every link between one event and the one
    /// before it, and that the history still ends where this grid recorded it ending.
    ///
    /// The last part is here because the links alone cannot catch a run deleted off the end. A
    /// chain with its tail cut off is a genuine chain of a shorter history, and so is a chain with
    /// its front cut off, which is also what trimming an exported front legitimately produces. So
    /// the end is compared against `audit_chain`, which is what the realm wrote down as it went.
    ///
    /// What this does not catch is somebody who moves the recorded end back as well. The head is
    /// two columns in the same file as the events, and so is the export watermark the delete guard
    /// consults, so whoever can edit one can edit the others. Only a copy that left this computer
    /// settles an end, and `a_history_cut_off_at_either_end_is_caught_only_so_far` says exactly how
    /// far this goes.
    pub fn verify_audit(&self) -> Result<(), String> {
        let chain = self.store.chain()?;
        chain.verify(&self.key)?;
        let (sequence, seal) = self.store.head()?;
        match chain.events.last() {
            Some(last) if last.sequence == sequence && last.seal == seal => Ok(()),
            Some(last) => Err(format!("This history ends at event {} and this grid recorded it reaching event {sequence}", last.sequence)),
            None if sequence == 0 => Ok(()),
            None => Err(format!("This history holds nothing and this grid recorded it reaching event {sequence}")),
        }
    }

    /// Everything this realm can check about itself without reaching anywhere: the shape of its
    /// own file, whether every reference leads somewhere, and whether its history is whole.
    /// Nothing wrong is an empty list.
    ///
    /// For an administrator who suspects something, and for the moment after a restore, which is
    /// the one time a realm holds state this process did not write.
    pub fn check_storage(&self) -> Result<Vec<String>, String> {
        let mut found = self.store.faults()?;
        if let Err(said) = self.verify_audit() {
            found.push(format!("The grid's history: {said}"));
        }
        Ok(found)
    }

    /// The events after `sequence`, for carrying out of a realm that cannot reach anywhere.
    ///
    /// This with `exported` is the whole of delayed synchronisation for a caller that is Rust.
    /// `write_history_out` and `carried_out` are the same thing for an operator with a disk, and
    /// they are what a realm that can reach nothing actually needs.
    pub fn since(&self, sequence: u64) -> Result<Vec<audit::Event>, String> {
        self.store.events_since(sequence)
    }

    /// Writes everything this realm has not yet got off this computer into one file an operator
    /// can carry away, and moves nothing.
    ///
    /// This exists because of one realm in particular. An authorised research realm is built to
    /// reach nothing, so it can never export, so `exported_to` never moves, so `Store::trim` drops
    /// nothing and its chain grows for as long as it runs. Weakening the trim rule would have been
    /// the wrong answer: an unexported event must not be dropped, and the database refuses to drop
    /// one. What an operator can be given instead is the bytes, in a file, verified.
    ///
    /// Nothing is marked here, and that is deliberate rather than an omission. A file on the same
    /// disk as the realm is not a second copy of anything; one disk failure loses both. The marker
    /// moves in `carried_out`, which the operator runs once the bundle is somewhere else.
    ///
    /// The chain is verified before anything is written, for the same reason `export_history`
    /// verifies it: a history somebody edited must not be carried out of this computer as though
    /// this realm vouched for it.
    pub fn write_history_out(&mut self, by: &str, to: &Path, now: i64) -> Result<export::Bundle, String> {
        self.allowed(by, Action::ReadAudit)?;
        self.verify_audit()?;
        let after = self.store.exported_to()?;
        let events = self.store.events_since(after)?;
        if events.is_empty() {
            return Err("This grid has carried everything it has written off this computer already. There is nothing to write out.".into());
        }
        let reaches = events.last().map(|event| event.sequence).unwrap_or(after);
        let bundle = export::Bundle { realm_id: self.realm.id.clone(), written_at: now, after, reaches, events };
        bundle.write(to)?;
        self.note(
            Entry::new(&self.realm.id, by, "audit.written out", Decision::Allowed).because(&format!(
                "{} events up to {reaches} were written to a file to be carried off this computer. Nothing has been marked carried out and nothing will be dropped until it has been.",
                bundle.len()
            )),
            now,
        )?;
        Ok(bundle)
    }

    /// Marks the history as carried out, against the bundle the operator actually has.
    ///
    /// Keyed on the file rather than on a number, which is the whole difference between this and
    /// `exported`. A number is something somebody can type, and the marker is the one thing
    /// standing between an event and the delete guard letting it go; a bundle is something that
    /// has to exist, has to belong to this realm, has to verify under this realm's key, and has to
    /// end on an event this realm actually holds with the seal this realm gave it. A bundle from
    /// another realm, one somebody edited, one that was truncated and one that reaches past what
    /// this realm has written are each refused, in words.
    ///
    /// It never moves the marker backwards, and it never moves it past the bundle.
    pub fn carried_out(&mut self, by: &str, from: &Path, now: i64) -> Result<u64, String> {
        self.allowed(by, Action::ManageSecurity)?;
        let bundle = export::Bundle::read(from)?;
        if bundle.realm_id != self.realm.id {
            return Err("That history bundle was written by another grid. Nothing has been marked carried out.".into());
        }
        bundle.verify(&self.key)?;
        // The last event in the bundle has to be the event this realm holds at that sequence, with
        // the same seal. That is what stops a bundle that verifies on its own terms, because
        // whoever made it had the key, from moving this realm's marker past events it never held.
        let last = bundle.events.last().ok_or("That history bundle holds no events")?;
        let held = self.store.event_at(bundle.reaches)?.ok_or_else(|| {
            format!("This grid no longer holds event {}, so it cannot check that bundle against its own history. Nothing has been marked carried out.", bundle.reaches)
        })?;
        if held.seal != last.seal {
            return Err(format!("Event {} in that bundle is not the event this grid holds at that number. Nothing has been marked carried out.", bundle.reaches));
        }
        let already = self.store.exported_to()?;
        if bundle.reaches <= already {
            return Err(format!("This grid has already carried its history out as far as event {already}. Nothing has changed."));
        }
        // And it has to join on to what was carried out before it. A bundle holding only the back
        // of a run verifies perfectly well — its seals are this realm's own, and its last event is
        // the event this realm holds — while vouching for nothing in front of it. Taking the
        // marker to its end would mark the events it skipped as carried out, and the delete guard
        // is the only thing those events have.
        if bundle.after > already {
            return Err(format!(
                "That history bundle starts at event {}, and nobody has carried out event {}. There would be a gap, so nothing has been marked carried out.",
                bundle.after + 1,
                already + 1
            ));
        }
        self.store.exported(bundle.reaches)?;
        self.note(
            Entry::new(&self.realm.id, by, "audit.carried out", Decision::Allowed).because(&format!(
                "the history up to event {} has been carried somewhere this computer cannot reach, checked against the bundle that was carried, so it may now be trimmed",
                bundle.reaches
            )),
            now,
        )?;
        Ok(bundle.reaches)
    }

    /// Marks the history up to `sequence` as exported somewhere this computer cannot reach. Only
    /// exported events are ever dropped when the chain is trimmed.
    ///
    /// This asks for a permission and records who moved the marker, like every other door in here
    /// that changes something. The marker is the one thing standing between an event and the
    /// delete guard letting it go, so somebody who could move it quietly could arrange for a run
    /// of the history to be dropped, and the realm would have no note of who asked.
    pub fn exported(&mut self, by: &str, sequence: u64, now: i64) -> Result<(), String> {
        self.allowed(by, Action::ManageSecurity)?;
        // Not past the end of the history. A number beyond the head is a claim about events this
        // realm has never written, and it does not stay harmless: the events written afterwards
        // arrive already marked as carried out, and the delete guard lets them go without anybody
        // having carried anything anywhere.
        let (head, _) = self.store.head()?;
        if sequence > head {
            return Err(format!("This grid has not written event {sequence} yet; its history reaches event {head}. Nothing has been marked carried out."));
        }
        self.store.exported(sequence)?;
        self.note(
            Entry::new(&self.realm.id, by, "audit.carried out", Decision::Allowed)
                .because(&format!("the history up to event {sequence} has been carried somewhere this computer cannot reach, so it may now be trimmed")),
            now,
        )
    }

    /// Records how a computer's card is isolated, on an administrator's say-so.
    ///
    /// Nothing attests this. No driver here reports a partition's real isolation, so what is
    /// written is what a named person asserted, and the record says so. Until somebody asserts it
    /// a card stays `Unknown`, which the scheduler already refuses to share and which the research
    /// profile refuses outright.
    pub fn set_gpu_isolation(&mut self, by: &str, host_id: &str, isolation: work::GpuIsolation, now: i64) -> Result<(), String> {
        self.allowed(by, Action::ManageSecurity)?;
        self.store.host(host_id)?.ok_or("No such computer is in this grid")?;
        self.store.set_gpu_isolation(host_id, isolation)?;
        self.note(
            Entry::new(&self.realm.id, by, "host.gpu isolation", Decision::Allowed)
                .because(&format!("{isolation:?} on {host_id}, asserted by a person; nothing in this grid attests it")),
            now,
        )
    }

    /// Every version this realm's database has been through.
    pub fn history(&self) -> Result<Vec<(u32, i64, String)>, String> {
        self.store.history()
    }

    /// Raises the policy version. Work already admitted keeps the version it came in under, and
    /// permissions issued under the older version stop being accepted.
    pub fn raise_policy(&mut self, by: &str, reason: &str, now: i64) -> Result<u64, String> {
        self.allowed(by, Action::ManageSecurity)?;
        let version = self.store.raise_policy()?;
        self.note(Entry::new(&self.realm.id, by, "policy.raised", Decision::Allowed).because(reason), now)?;
        Ok(version)
    }

    /// Pauses or closes the realm.
    ///
    /// A grid that stops serving raises its policy version with the same call, so every
    /// permission already in somebody's hands stops at its next use rather than lasting until it
    /// expires. Pausing is something a security administrator reaches for when something is
    /// wrong, and it would be worth little if the work already under way carried on for hours.
    /// Opening the grid again does not bring those permissions back; they are asked for again.
    pub fn set_lifecycle(&mut self, by: &str, lifecycle: Lifecycle, now: i64) -> Result<(), String> {
        self.allowed(by, Action::ManageSecurity)?;
        self.store.set_lifecycle(lifecycle)?;
        self.realm.lifecycle = lifecycle;
        if !lifecycle.serves() {
            self.store.raise_policy()?;
        }
        self.note(Entry::new(&self.realm.id, by, "realm.lifecycle", Decision::Allowed).because(&format!("{lifecycle:?}")), now)
    }

    /// Closes the realm's database, flushing its journal, so a copy taken afterwards is whole.
    pub fn close(self) -> Result<(), String> {
        self.store.close()
    }
}

/// What a restore does not bring back. Every one of these is already true of the code, and each
/// is deliberate rather than an oversight.
const NOT_RESTORED: [&str; 3] = [
    "Sign-ins. A record carries no permissions, so a restored realm holding sign-ins would hand somebody a workspace on the strength of a permission that does not exist",
    "Every permission the realm ever issued. A restored realm has no record of issuing them, so each one is refused the next time it is used",
    "What every computer last said about itself. Every computer must report its condition again before a workspace can be placed on it",
];

/// What a restore drill found.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreReport {
    pub realm_id: String,
    pub realm_name: String,
    pub taken_at: i64,
    pub schema_version: u32,
    pub counts: store::Counts,
    pub head_sequence: u64,
    pub history_verified: bool,
    /// Anything the restored realm says is wrong with itself. Empty is the answer wanted.
    pub faults: Vec<String>,
    /// What a restore does not bring back, named rather than implied.
    pub not_restored: Vec<String>,
    /// Where the drill put the realm it built, so it can be looked at and then removed.
    pub kept_at: PathBuf,
}

/// One line of the history as an evidence bundle carries it: what happened, who it was about,
/// what it was about, and when.
///
/// The reason is deliberately left out. A reason is the realm's own words about what happened,
/// and some of those words are words a person typed: `principal.added` records the name somebody
/// was added under, and `credential.added` records the place a credential may be sent. Those
/// belong in the realm's sealed history, which stays on the realm's computer and is read there by
/// somebody who is allowed to. They do not belong in a bundle an operator sends to an engineer,
/// and leaving them out here is the difference between a bundle anybody can share and a bundle
/// somebody has to read through first.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Happened {
    pub sequence: u64,
    pub at: i64,
    /// A fixed word written in this code, such as `work.queued`, never anything a caller chose.
    pub action: String,
    pub decision: Decision,
    pub capability: Option<Capability>,
    pub principal_id: String,
    pub device_id: Option<String>,
    pub workload_id: Option<String>,
    pub resource_id: Option<String>,
    pub policy_version: u64,
}

impl Happened {
    fn of(event: &audit::Event) -> Happened {
        Happened {
            sequence: event.sequence,
            at: event.at,
            action: event.action.clone(),
            decision: event.decision,
            capability: event.capability,
            principal_id: event.principal_id.clone(),
            device_id: event.device_id.clone(),
            workload_id: event.workload_id.clone(),
            resource_id: event.resource_id.clone(),
            policy_version: event.policy_version,
        }
    }
}

/// Everything an engineer needs to look at an incident.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    pub realm_id: String,
    pub at: i64,
    pub checkup: health::Checkup,
    pub reading: metrics::Reading,
    /// Every version this realm's database has been through.
    pub migrations: Vec<(u32, i64, String)>,
    /// What the realm recorded since a sequence the engineer names, without the words.
    pub recent: Vec<Happened>,
    /// Identifiers of the packed copies nobody has been able to take. Identifiers only.
    pub stuck: Vec<String>,
}

/// Counting what a piece of core work asks the database (see docs/grid-core/operations.md).
#[cfg(test)]
pub(crate) mod bench;
/// The twelve families of attack, each one performed and each one asserted to fail.
#[cfg(test)]
mod attack;
/// The authorisation invariants, checked over generated runs.
#[cfg(test)]
mod invariant;
/// Malformed input, refused rather than crashed into.
#[cfg(test)]
mod fuzz;
/// Getting a realm back: power loss, corruption, a lost computer, two writers.
#[cfg(test)]
mod recovery;
/// The seeded generator the property and fuzz tests are driven by.
#[cfg(test)]
pub(crate) mod seed;
#[cfg(test)]
mod tests;
