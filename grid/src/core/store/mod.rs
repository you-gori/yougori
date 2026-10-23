//! Where a realm is kept.
//!
//! One database per realm, in write-ahead logging mode with every commit flushed, so a power cut
//! leaves the last committed state and nothing half-written. Each change is one transaction: a
//! decision and the allowance it creates land together or not at all.
//!
//! Three things are deliberately awkward to undo. A decision is written once and never changed.
//! An audit event is written once and never changed, and may only be dropped after it has been
//! exported. Withdrawing trust from an account or a computer raises that subject's generation, and
//! a permission issued under an older generation is refused the next time it is used, without
//! having to find and delete anything.
//!
//! The realm's key is never in here. The database holds the name of the vault entry that keeps it,
//! which version it is, and a check value that says whether a key offered later is the right one.
pub mod legacy;
/// How much room is left where a realm lives (see docs/grid-core/operations.md).
pub mod room;
pub mod schema;

// The portable shape, where anything written against the first core still finds it.
pub use legacy::{load, read, save, Record, VERSION};
pub use schema::VERSION as SCHEMA_VERSION;

use super::{
    approval::{Allowance, Approval, State},
    audit::{Chain, Decision, Entry, Event, KEEP},
    broker::Use,
    capability::Claims,
    connector::intent::{change_from, change_word, Intent, IntentState},
    credential::{Credential, Grant, Secret, Vault},
    hardware::Trust,
    identity::{Device, Principal, PrincipalKind, Role},
    model::{ModelAssignment, ModelPlan},
    realm::{Capability, Lifecycle, NetworkPolicy, Realm, RealmKind},
    work::{Commitment, GpuIsolation, Host, Kind, Lease, Resources, Stage, Workload},
    workspace::{Access, Artifact, ArtifactStore, Assignment, Claim, Condition, Image, ImageSource, Pledge, Quota, Session, Workspace, WorkspaceKind, WorkspaceState},
};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Row};
use serde::{de::DeserializeOwned, Serialize};
use std::path::{Path, PathBuf};

/// Which vault entry holds this realm's key, and which version of it. The key itself is not here
/// and never has been.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyReference {
    pub id: String,
    pub version: u32,
}

impl KeyReference {
    /// The vault entry a realm's key belongs in, by convention.
    pub fn for_realm(realm_id: &str) -> KeyReference {
        KeyReference { id: format!("yougori-core-{realm_id}"), version: 1 }
    }
}

/// One permission a person holds, and the role it came with when it was not granted on its own.
/// Administering and approving are separate rows, so neither is implied by reading the other.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Permission {
    pub permission: Role,
    pub derived_from: Option<Role>,
    pub granted_by: String,
    pub granted_at: i64,
}

/// Why a permission handed to a piece of work is no longer good.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stale {
    /// The account or the computer has been withdrawn since it was issued.
    Withdrawn,
    /// The realm's policy changed after it was issued.
    PolicyChanged,
    /// It has already been used, and it was for one use.
    AlreadyUsed,
    /// The credential it names has been rotated or retired since it was issued.
    Replaced,
    /// This realm has no record of issuing it. A restored realm is in exactly this position:
    /// everything it handed out before the backup was taken stops being accepted.
    Unknown,
}

impl Stale {
    pub fn describe(&self) -> String {
        match self {
            Stale::Withdrawn => "This permission's account or computer is no longer in this grid".into(),
            Stale::PolicyChanged => "This grid's policy changed after this permission was issued".into(),
            Stale::AlreadyUsed => "This permission was already used".into(),
            Stale::Replaced => "This credential was rotated or retired after this permission was issued".into(),
            Stale::Unknown => "This grid has no record of issuing this permission".into(),
        }
    }
}

/// A realm's database.
pub struct Store {
    path: PathBuf,
    connection: Connection,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Store").field("path", &self.path).finish()
    }
}

fn trouble(what: &str, error: rusqlite::Error) -> String {
    format!("Cannot {what}: {error}")
}

/// A unit enum as the one word it is written as.
fn word<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value).ok().and_then(|value| value.as_str().map(str::to_owned)).unwrap_or_default()
}

/// The reverse, naming what was being read when it does not fit.
fn unword<T: DeserializeOwned>(text: &str, what: &str) -> rusqlite::Result<T> {
    serde_json::from_value(serde_json::Value::String(text.to_owned()))
        .map_err(|error| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(std::io::Error::other(format!("{what}: {error}")))))
}

fn json<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".into())
}

fn unjson<T: DeserializeOwned>(text: &str, what: &str) -> rusqlite::Result<T> {
    serde_json::from_str(text)
        .map_err(|error| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(std::io::Error::other(format!("{what}: {error}")))))
}

impl Store {
    // ---- Opening and building ----

    /// Starts a realm's database. `key` is the realm's signing secret, which the caller keeps in
    /// the vault; only a check value derived from it is written here.
    pub fn create(path: &Path, realm: &Realm, reference: &KeyReference, now: i64) -> Result<Store, String> {
        if path.exists() {
            return Err("This computer already holds a grid of that name".into());
        }
        // Asked here and not on the write path. An operator told now can put the grid on another
        // disk and has lost nothing; an operator told six months from now, by a grid that has
        // stopped being able to record what it decided, has an outage.
        room::enough_for(path, 0, "for this grid")?;
        let mut store = Store::connect(path)?;
        store.migrate()?;
        store.put_realm(realm, reference, now)?;
        Ok(store)
    }

    /// Opens a realm's database, bringing it up to this build's shape if an older one wrote it.
    pub fn open(path: &Path) -> Result<Store, String> {
        if !path.exists() {
            return Err("There is no grid on this computer by that name".into());
        }
        let mut store = Store::connect(path)?;
        store.migrate()?;
        Ok(store)
    }

    /// Opens a realm's database to look at it, and nothing else.
    ///
    /// `open` brings a database up to this build's shape, which is a write. A survey, a rehearsal
    /// and a reading of a realm found on a disk must not do that: bringing somebody's realm
    /// forward because a tool looked at it is exactly the accident this phase exists to prevent.
    ///
    /// The handle is asked for read-only, and the flag is the part that matters rather than the
    /// pragma. `query_only` refuses every write a statement could make, and it does not stop
    /// SQLite's own housekeeping: a realm is in write-ahead logging, and when a read-write
    /// connection is the last one to close such a file, SQLite checkpoints, which folds whatever
    /// frames a crashed writer left in the journal into the main file and removes the two files
    /// beside it. That rewrites bytes in somebody's realm for no reason but that a tool looked at
    /// it. A read-only handle cannot write the main file at all, so it cannot do that. Both are
    /// kept, the flag as the refusal and the pragma as a second one.
    ///
    /// What the flag does not buy, said rather than discovered. SQLite may still create `-shm` and
    /// `-wal` beside a write-ahead-logging realm in order to read it, so files can appear in the
    /// folder; the realm's own file is what is left alone. And a realm whose folder cannot be
    /// written may refuse to open here at all, which a survey reports as a refusal note rather
    /// than quietly rewriting the realm.
    ///
    /// A realm at a version this build does not know is still readable here, because nothing is
    /// written; `version()` says which version it is and the caller decides.
    pub fn open_for_reading(path: &Path) -> Result<Store, String> {
        if !path.exists() {
            return Err("There is no grid on this computer by that name".into());
        }
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX | OpenFlags::SQLITE_OPEN_URI;
        let connection = Connection::open_with_flags(path, flags).map_err(|error| trouble("open the grid", error))?;
        for pragma in ["PRAGMA query_only = ON", "PRAGMA foreign_keys = ON"] {
            connection.execute_batch(pragma).map_err(|error| trouble("prepare the grid to be read", error))?;
        }
        connection.busy_timeout(std::time::Duration::from_secs(10)).map_err(|error| trouble("prepare the grid to be read", error))?;
        Ok(Store { path: path.to_owned(), connection })
    }

    /// An exact, consistent copy of a realm's database, taken without opening the realm.
    ///
    /// `VACUUM INTO` is how SQLite takes a copy that is whole and has no journal beside it, and
    /// it does that by writing: it cannot run on the connection `open_for_reading` hands back,
    /// because `query_only` refuses every write, the copy included. So this opens a connection of
    /// its own. It does not migrate and it does not change the journal mode, so the realm's
    /// contents and its version come out the other side exactly as they went in.
    ///
    /// What it is not is a read-only connection, and that has a consequence worth saying plainly
    /// rather than leaving somebody to find. A realm is in write-ahead logging, and when the
    /// connection that closes such a file last is a read-write one, SQLite checkpoints: whatever
    /// frames a crashed writer left in the journal are folded into the main file and the two files
    /// beside it are removed. So taking a copy can rewrite bytes of the realm it copied. It
    /// changes no row, no version and no answer the realm gives, and
    /// `taking_a_copy_leaves_the_realm_holding_exactly_what_it_held` is the test that says which
    /// of those two is claimed.
    pub fn copy_of(from: &Path, to: &Path) -> Result<(), String> {
        if !from.exists() {
            return Err("There is no grid on this computer by that name".into());
        }
        if to.exists() {
            return Err("There is already a file where that copy would go".into());
        }
        if let Some(folder) = to.parent() {
            if !folder.as_os_str().is_empty() {
                std::fs::create_dir_all(folder).map_err(|error| format!("Cannot open the folder for the copy: {error}"))?;
            }
        }
        room::enough_for(to, std::fs::metadata(from).map(|about| about.len()).unwrap_or(0), "for a copy of this grid")?;
        let connection = Connection::open(from).map_err(|error| trouble("open the grid", error))?;
        connection
            .execute("VACUUM INTO ?1", params![to.to_string_lossy()])
            .map(|_| ())
            .map_err(|error| trouble("take a copy of the grid", error))
    }

    fn connect(path: &Path) -> Result<Store, String> {
        if let Some(folder) = path.parent() {
            if !folder.as_os_str().is_empty() {
                std::fs::create_dir_all(folder).map_err(|error| format!("Cannot open the grid's folder: {error}"))?;
            }
        }
        let connection = Connection::open(path).map_err(|error| trouble("open the grid", error))?;
        // Write-ahead logging with every commit flushed to the disk: a crash loses nothing that
        // was committed, and leaves no half-written change behind.
        connection
            .query_row("PRAGMA journal_mode = WAL", [], |row| row.get::<_, String>(0))
            .map_err(|error| trouble("prepare the grid's journal", error))?;
        for pragma in ["PRAGMA synchronous = FULL", "PRAGMA foreign_keys = ON"] {
            connection.execute_batch(pragma).map_err(|error| trouble("prepare the grid", error))?;
        }
        connection.busy_timeout(std::time::Duration::from_secs(10)).map_err(|error| trouble("prepare the grid", error))?;
        Ok(Store { path: path.to_owned(), connection })
    }

    /// Runs several writes in one change, for a test that needs a table of a given size without
    /// paying one transaction and one fsync per row.
    #[cfg(test)]
    pub(crate) fn in_one_change(&self, work: impl FnOnce(&Connection) -> Result<(), String>) -> Result<(), String> {
        let change = self.connection.unchecked_transaction().map_err(|error| trouble("begin a change", error))?;
        work(&change)?;
        change.commit().map_err(|error| trouble("finish the change", error))
    }

    /// Turns SQLite's own statement trace on or off, for `core::bench`.
    ///
    /// Test support, and only reachable in a build that has the tests: nothing shipped calls it,
    /// and the callback is handed the statement text with its placeholders still in it, never the
    /// values bound to them.
    #[cfg(test)]
    pub(crate) fn watch(&self, watcher: Option<fn(rusqlite::trace::TraceEvent<'_>)>) {
        use rusqlite::trace::TraceEventCodes;
        self.connection.trace_v2(TraceEventCodes::SQLITE_TRACE_STMT | TraceEventCodes::SQLITE_TRACE_ROW, watcher);
    }

    /// Whether the database answers at all: one row, no table, for a liveness probe.
    pub fn ping(&self) -> Result<(), String> {
        self.connection.query_row("SELECT 1", [], |row| row.get::<_, i64>(0)).map(|_| ()).map_err(|error| trouble("reach the grid's database", error))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The version this database is at.
    pub fn version(&self) -> Result<u32, String> {
        let present: bool = self
            .connection
            .query_row("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'migrations'", [], |_| Ok(true))
            .optional()
            .map_err(|error| trouble("read the grid's version", error))?
            .unwrap_or(false);
        if !present {
            return Ok(0);
        }
        self.connection
            .query_row("SELECT COALESCE(MAX(version), 0) FROM migrations", [], |row| row.get::<_, i64>(0))
            .map(|version| version as u32)
            .map_err(|error| trouble("read the grid's version", error))
    }

    /// Brings the database up to this build's shape, one version at a time. Each step and the
    /// record of having run it are one transaction, so a step that fails leaves the database at
    /// the version it was already at.
    pub fn migrate(&mut self) -> Result<(), String> {
        let at = self.version()?;
        if at > SCHEMA_VERSION {
            return Err(format!("This grid was written by a newer Yougori (version {at}); update Yougori to open it"));
        }
        if at == 0 {
            self.connection
                .execute_batch("CREATE TABLE IF NOT EXISTS migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL, description TEXT NOT NULL)")
                .map_err(|error| trouble("prepare the grid for its first version", error))?;
        }
        let now = crate::now();
        for version in (at + 1)..=SCHEMA_VERSION {
            let Some(statements) = schema::step(version) else {
                return Err(format!("This build has no step to version {version}"));
            };
            let change = self.connection.unchecked_transaction().map_err(|error| trouble("begin a change", error))?;
            change.execute_batch(statements).map_err(|error| trouble(&format!("move the grid to version {version}"), error))?;
            change
                .execute("INSERT INTO migrations (version, applied_at, description) VALUES (?1, ?2, ?3)", params![version as i64, now, schema::describe(version)])
                .map_err(|error| trouble("record the change of version", error))?;
            change.commit().map_err(|error| trouble(&format!("finish moving the grid to version {version}"), error))?;
        }
        Ok(())
    }

    /// Takes the database back one version, where that version was written with a way back.
    ///
    /// The step and the record of it are one transaction, exactly as going forward is, so a
    /// rollback that fails leaves the database at the version it was already at. Opening the
    /// realm with this build afterwards runs the step again, which is what makes a rollback
    /// rehearsable rather than a one-way door.
    pub fn roll_back(&mut self, version: u32) -> Result<(), String> {
        let at = self.version()?;
        if at != version {
            return Err(format!("This grid is at version {at}, not {version}"));
        }
        let Some(statements) = schema::rollback(version) else {
            return Err(format!("Version {version} was not written with a way back"));
        };
        let change = self.connection.unchecked_transaction().map_err(|error| trouble("begin a change", error))?;
        change.execute_batch(statements).map_err(|error| trouble(&format!("take the grid back from version {version}"), error))?;
        change
            .execute("DELETE FROM migrations WHERE version = ?1", params![version as i64])
            .map_err(|error| trouble("record the change of version", error))?;
        change.commit().map_err(|error| trouble(&format!("finish taking the grid back from version {version}"), error))
    }

    /// Every version this database has been through, with when it happened.
    pub fn history(&self) -> Result<Vec<(u32, i64, String)>, String> {
        let mut query = self.connection.prepare("SELECT version, applied_at, description FROM migrations ORDER BY version").map_err(|error| trouble("read the grid's versions", error))?;
        let rows = query
            .query_map([], |row| Ok((row.get::<_, i64>(0)? as u32, row.get::<_, i64>(1)?, row.get::<_, String>(2)?)))
            .map_err(|error| trouble("read the grid's versions", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read the grid's versions", error))
    }

    // ---- The realm ----

    fn put_realm(&self, realm: &Realm, reference: &KeyReference, now: i64) -> Result<(), String> {
        let change = self.connection.unchecked_transaction().map_err(|error| trouble("begin a change", error))?;
        change
            .execute(
                "INSERT INTO realms (id, name, kind, capabilities, network, lifecycle, key_id, key_version, key_check, generation, policy_version, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1, 1, ?10)",
                params![
                    realm.id,
                    realm.name,
                    word(&realm.kind),
                    json(&realm.capabilities),
                    json(&realm.network),
                    word(&realm.lifecycle),
                    reference.id,
                    reference.version as i64,
                    realm.key_fingerprint,
                    realm.created_at,
                ],
            )
            .map_err(|error| trouble("write the grid", error))?;
        change
            .execute(
                "INSERT INTO audit_chain (realm_id, key_id, key_version, head_seal, head_sequence, exported_to, started_at, updated_at)
                 VALUES (?1, ?2, ?3, 'root', 0, 0, ?4, ?4)",
                params![realm.id, reference.id, reference.version as i64, now],
            )
            .map_err(|error| trouble("start the grid's history", error))?;
        change.commit().map_err(|error| trouble("finish writing the grid", error))
    }

    pub fn realm(&self) -> Result<Realm, String> {
        self.connection
            .query_row("SELECT id, name, kind, capabilities, network, lifecycle, key_check, created_at FROM realms LIMIT 1", [], |row| {
                Ok(Realm {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    kind: unword::<RealmKind>(&row.get::<_, String>(2)?, "what this grid is for")?,
                    capabilities: unjson::<Vec<Capability>>(&row.get::<_, String>(3)?, "what this grid does")?,
                    network: unjson::<NetworkPolicy>(&row.get::<_, String>(4)?, "this grid's network rules")?,
                    lifecycle: unword::<Lifecycle>(&row.get::<_, String>(5)?, "this grid's state")?,
                    key_fingerprint: row.get(6)?,
                    created_at: row.get(7)?,
                })
            })
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => "This file holds no grid".to_owned(),
                other => trouble("read the grid", other),
            })
    }

    pub fn key_reference(&self) -> Result<KeyReference, String> {
        self.connection
            .query_row("SELECT key_id, key_version FROM realms LIMIT 1", [], |row| Ok(KeyReference { id: row.get(0)?, version: row.get::<_, i64>(1)? as u32 }))
            .map_err(|error| trouble("read which key this grid uses", error))
    }

    pub fn set_lifecycle(&self, lifecycle: Lifecycle) -> Result<(), String> {
        self.connection
            .execute("UPDATE realms SET lifecycle = ?1", params![word(&lifecycle)])
            .map(|_| ())
            .map_err(|error| trouble("change what this grid is doing", error))
    }

    pub fn policy_version(&self) -> Result<u64, String> {
        self.connection
            .query_row("SELECT policy_version FROM realms LIMIT 1", [], |row| row.get::<_, i64>(0))
            .map(|version| version as u64)
            .map_err(|error| trouble("read this grid's policy version", error))
    }

    /// Raises the policy version. Work already admitted keeps the version it came in under.
    pub fn raise_policy(&self) -> Result<u64, String> {
        self.connection.execute("UPDATE realms SET policy_version = policy_version + 1", []).map_err(|error| trouble("raise this grid's policy version", error))?;
        self.policy_version()
    }

    pub fn realm_generation(&self) -> Result<u64, String> {
        self.connection
            .query_row("SELECT generation FROM realms LIMIT 1", [], |row| row.get::<_, i64>(0))
            .map(|generation| generation as u64)
            .map_err(|error| trouble("read this grid's generation", error))
    }

    /// Withdraws every permission issued so far in this realm at once, by moving the realm on a
    /// generation. Nothing has to be found and deleted; every older permission simply stops.
    pub fn withdraw_realm(&self, by: &str, reason: &str, now: i64) -> Result<u64, String> {
        let realm_id = self.realm_id()?;
        let change = self.connection.unchecked_transaction().map_err(|error| trouble("begin a change", error))?;
        change.execute("UPDATE realms SET generation = generation + 1", []).map_err(|error| trouble("withdraw this grid's permissions", error))?;
        let generation: i64 = change.query_row("SELECT generation FROM realms LIMIT 1", [], |row| row.get(0)).map_err(|error| trouble("withdraw this grid's permissions", error))?;
        change
            .execute(
                "INSERT INTO revocations (id, realm_id, subject, subject_id, generation, revoked_by, revoked_at, reason)
                 VALUES (?1, ?2, 'realm', ?3, ?4, ?5, ?6, ?7)",
                params![fresh("revocation"), realm_id, realm_id, generation, by, now, clean(reason)],
            )
            .map_err(|error| trouble("record the withdrawal", error))?;
        change.commit().map_err(|error| trouble("finish withdrawing", error))?;
        Ok(generation as u64)
    }

    fn realm_id(&self) -> Result<String, String> {
        self.connection.query_row("SELECT id FROM realms LIMIT 1", [], |row| row.get::<_, String>(0)).map_err(|error| trouble("read the grid", error))
    }

    // ---- People and what they may do ----

    /// Adds a person or a service, with their permissions. A permission that comes with a role is
    /// written in its own right, naming the role it came from.
    pub fn add_principal(&self, principal: &Principal, by: &str, now: i64) -> Result<(), String> {
        let change = self.connection.unchecked_transaction().map_err(|error| trouble("begin a change", error))?;
        change
            .execute(
                "INSERT INTO principals (id, realm_id, kind, name, email, created_at, suspended_at, generation) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1)",
                params![principal.id, principal.realm_id, word(&principal.kind), principal.name, principal.email, principal.created_at, principal.suspended_at],
            )
            .map_err(|error| trouble("add this person", error))?;
        for role in &principal.roles {
            Store::write_permission(&change, &principal.realm_id, &principal.id, *role, None, by, now)?;
            for implied in role.implies() {
                Store::write_permission(&change, &principal.realm_id, &principal.id, *implied, Some(*role), by, now)?;
            }
        }
        change.commit().map_err(|error| trouble("finish adding this person", error))
    }

    fn write_permission(change: &rusqlite::Transaction<'_>, realm_id: &str, principal_id: &str, permission: Role, derived_from: Option<Role>, by: &str, now: i64) -> Result<(), String> {
        change
            .execute(
                "INSERT OR IGNORE INTO permissions (id, realm_id, principal_id, permission, derived_from, granted_by, granted_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![fresh("permission"), realm_id, principal_id, word(&permission), derived_from.map(|role| word(&role)), by, now],
            )
            .map(|_| ())
            .map_err(|error| trouble("write a permission", error))
    }

    /// Gives someone another permission, and whatever that one brings with it.
    pub fn grant(&self, principal_id: &str, role: Role, by: &str, now: i64) -> Result<(), String> {
        let realm_id = self.realm_id()?;
        let change = self.connection.unchecked_transaction().map_err(|error| trouble("begin a change", error))?;
        Store::write_permission(&change, &realm_id, principal_id, role, None, by, now)?;
        for implied in role.implies() {
            Store::write_permission(&change, &realm_id, principal_id, *implied, Some(role), by, now)?;
        }
        change.commit().map_err(|error| trouble("finish granting", error))
    }

    /// Takes a permission away, and anything that only came with it.
    pub fn withdraw(&self, principal_id: &str, role: Role) -> Result<(), String> {
        let change = self.connection.unchecked_transaction().map_err(|error| trouble("begin a change", error))?;
        change
            .execute("DELETE FROM permissions WHERE principal_id = ?1 AND (permission = ?2 OR derived_from = ?2)", params![principal_id, word(&role)])
            .map_err(|error| trouble("take a permission away", error))?;
        change.commit().map_err(|error| trouble("finish taking a permission away", error))
    }

    /// Everything someone holds, and where each of it came from.
    pub fn permissions(&self, principal_id: &str) -> Result<Vec<Permission>, String> {
        let mut query = self
            .connection
            .prepare("SELECT permission, derived_from, granted_by, granted_at FROM permissions WHERE principal_id = ?1 ORDER BY permission")
            .map_err(|error| trouble("read what this person holds", error))?;
        let rows = query
            .query_map(params![principal_id], |row| {
                Ok(Permission {
                    permission: unword::<Role>(&row.get::<_, String>(0)?, "a permission")?,
                    derived_from: match row.get::<_, Option<String>>(1)? {
                        Some(text) => Some(unword::<Role>(&text, "a permission")?),
                        None => None,
                    },
                    granted_by: row.get(2)?,
                    granted_at: row.get(3)?,
                })
            })
            .map_err(|error| trouble("read what this person holds", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read what this person holds", error))
    }

    pub fn principal(&self, id: &str) -> Result<Option<Principal>, String> {
        let found = self
            .connection
            .query_row("SELECT id, realm_id, kind, name, email, created_at, suspended_at FROM principals WHERE id = ?1", params![id], principal_without_roles)
            .optional()
            .map_err(|error| trouble("read this person", error))?;
        let Some(mut principal) = found else { return Ok(None) };
        principal.roles = self.permissions(id)?.into_iter().map(|held| held.permission).collect();
        principal.roles.sort();
        principal.roles.dedup();
        Ok(Some(principal))
    }

    pub fn principals(&self) -> Result<Vec<Principal>, String> {
        let mut query = self
            .connection
            .prepare("SELECT id, realm_id, kind, name, email, created_at, suspended_at FROM principals ORDER BY created_at, id")
            .map_err(|error| trouble("read this grid's people", error))?;
        let rows = query.query_map([], principal_without_roles).map_err(|error| trouble("read this grid's people", error))?;
        let mut people = rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this grid's people", error))?;
        for person in &mut people {
            person.roles = self.permissions(&person.id)?.into_iter().map(|held| held.permission).collect();
            person.roles.sort();
            person.roles.dedup();
        }
        Ok(people)
    }

    /// Suspends an account. Everything it holds stops at once, because its generation moves on.
    pub fn suspend_principal(&self, id: &str, by: &str, reason: &str, now: i64) -> Result<u64, String> {
        let realm_id = self.realm_id()?;
        let change = self.connection.unchecked_transaction().map_err(|error| trouble("begin a change", error))?;
        let touched = change
            .execute("UPDATE principals SET suspended_at = ?2, generation = generation + 1 WHERE id = ?1 AND suspended_at IS NULL", params![id, now])
            .map_err(|error| trouble("suspend this account", error))?;
        if touched == 0 {
            return Err("No such account is in this grid, or it is already suspended".into());
        }
        let generation: i64 = change.query_row("SELECT generation FROM principals WHERE id = ?1", params![id], |row| row.get(0)).map_err(|error| trouble("suspend this account", error))?;
        change
            .execute(
                "INSERT INTO revocations (id, realm_id, subject, subject_id, generation, revoked_by, revoked_at, reason) VALUES (?1, ?2, 'principal', ?3, ?4, ?5, ?6, ?7)",
                params![fresh("revocation"), realm_id, id, generation, by, now, clean(reason)],
            )
            .map_err(|error| trouble("record the suspension", error))?;
        change.commit().map_err(|error| trouble("finish suspending", error))?;
        Ok(generation as u64)
    }

    /// Lets a suspended account work again, under a generation of its own, so permissions issued
    /// before the suspension stay dead.
    pub fn restore_principal(&self, id: &str) -> Result<(), String> {
        self.connection
            .execute("UPDATE principals SET suspended_at = NULL WHERE id = ?1", params![id])
            .map(|_| ())
            .map_err(|error| trouble("bring this account back", error))
    }

    // ---- Computers ----

    pub fn enrol_device(&self, device: &Device) -> Result<(), String> {
        self.connection
            .execute(
                "INSERT INTO devices (id, realm_id, principal_id, name, platform, token_hash, attestation, enrolled_at, last_seen_at, revoked_at, generation)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 1)",
                params![
                    device.id,
                    device.realm_id,
                    device.principal_id,
                    device.name,
                    device.platform,
                    device.token_hash,
                    json(&device.attestation),
                    device.enrolled_at,
                    device.last_seen_at,
                    device.revoked_at,
                ],
            )
            .map(|_| ())
            .map_err(|error| trouble("enrol this computer", error))
    }

    pub fn device(&self, id: &str) -> Result<Option<Device>, String> {
        self.connection
            .query_row(
                "SELECT id, realm_id, principal_id, name, platform, token_hash, attestation, enrolled_at, last_seen_at, revoked_at FROM devices WHERE id = ?1",
                params![id],
                device_from,
            )
            .optional()
            .map_err(|error| trouble("read this computer", error))
    }

    pub fn devices(&self) -> Result<Vec<Device>, String> {
        let mut query = self
            .connection
            .prepare("SELECT id, realm_id, principal_id, name, platform, token_hash, attestation, enrolled_at, last_seen_at, revoked_at FROM devices ORDER BY enrolled_at, id")
            .map_err(|error| trouble("read this grid's computers", error))?;
        let rows = query.query_map([], device_from).map_err(|error| trouble("read this grid's computers", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this grid's computers", error))
    }

    /// The computers still in this realm, by identifier. `Device::active` in SQL.
    ///
    /// Placement asks this once and then looks each computer up in the answer. It used to ask it
    /// once per computer, which is the difference between a decision costing one statement and a
    /// decision costing one statement per computer in the grid.
    pub fn active_devices(&self) -> Result<std::collections::HashSet<String>, String> {
        let mut query = self.connection.prepare("SELECT id FROM devices WHERE revoked_at IS NULL").map_err(|error| trouble("read this grid's computers", error))?;
        let rows = query.query_map([], |row| row.get::<_, String>(0)).map_err(|error| trouble("read this grid's computers", error))?;
        rows.collect::<rusqlite::Result<std::collections::HashSet<_>>>().map_err(|error| trouble("read this grid's computers", error))
    }

    pub fn set_attestation(&self, id: &str, attestation: &super::identity::Attestation) -> Result<(), String> {
        self.connection
            .execute("UPDATE devices SET attestation = ?2 WHERE id = ?1", params![id, json(attestation)])
            .map(|_| ())
            .map_err(|error| trouble("record what this computer proved", error))
    }

    pub fn seen(&self, id: &str, now: i64) -> Result<(), String> {
        self.connection.execute("UPDATE devices SET last_seen_at = ?2 WHERE id = ?1", params![id, now]).map(|_| ()).map_err(|error| trouble("record this computer", error))
    }

    /// Takes a computer out of the realm and moves it on a generation, so every permission it was
    /// given stops being accepted.
    pub fn revoke_device(&self, id: &str, by: &str, reason: &str, now: i64) -> Result<u64, String> {
        let realm_id = self.realm_id()?;
        let change = self.connection.unchecked_transaction().map_err(|error| trouble("begin a change", error))?;
        let touched = change
            .execute("UPDATE devices SET revoked_at = ?2, generation = generation + 1 WHERE id = ?1 AND revoked_at IS NULL", params![id, now])
            .map_err(|error| trouble("remove this computer", error))?;
        if touched == 0 {
            return Err("No such computer is in this grid".into());
        }
        let generation: i64 = change.query_row("SELECT generation FROM devices WHERE id = ?1", params![id], |row| row.get(0)).map_err(|error| trouble("remove this computer", error))?;
        change
            .execute(
                "INSERT INTO revocations (id, realm_id, subject, subject_id, generation, revoked_by, revoked_at, reason) VALUES (?1, ?2, 'device', ?3, ?4, ?5, ?6, ?7)",
                params![fresh("revocation"), realm_id, id, generation, by, now, clean(reason)],
            )
            .map_err(|error| trouble("record the removal", error))?;
        change.commit().map_err(|error| trouble("finish removing this computer", error))?;
        Ok(generation as u64)
    }

    /// Everything that has been withdrawn in this realm, newest first.
    pub fn revocations(&self) -> Result<Vec<(String, String, u64, i64)>, String> {
        let mut query = self
            .connection
            .prepare("SELECT subject, subject_id, generation, revoked_at FROM revocations ORDER BY revoked_at DESC, id")
            .map_err(|error| trouble("read what has been withdrawn", error))?;
        let rows = query
            .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)? as u64, row.get::<_, i64>(3)?)))
            .map_err(|error| trouble("read what has been withdrawn", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read what has been withdrawn", error))
    }

    /// Removes exactly what a bridge brought into this realm, in one change, so an import that
    /// was a mistake leaves no half-realm behind. Nothing else is touched, and the history of the
    /// import and of undoing it stays: events are never removed.
    ///
    /// Things go in the reverse of the order they arrived, and the database refuses the change if
    /// anything that came later still depends on them, which is the honest answer rather than
    /// deleting someone's work along with the import.
    pub fn forget_imported(&self, principals: &[String], devices: &[String], hosts: &[String], plans: &[String]) -> Result<(), String> {
        let change = self.connection.unchecked_transaction().map_err(|error| trouble("begin undoing the import", error))?;
        let depends = |error: rusqlite::Error| match error {
            rusqlite::Error::SqliteFailure(failure, _) if failure.code == rusqlite::ErrorCode::ConstraintViolation => {
                "Something in this grid now depends on what the import brought in, so it cannot be undone".to_owned()
            }
            other => trouble("undo the import", other),
        };
        for plan in plans {
            change.execute("DELETE FROM model_plans WHERE id = ?1", params![plan]).map_err(depends)?;
        }
        for host in hosts {
            change.execute("DELETE FROM model_assignments WHERE host_id = ?1", params![host]).map_err(depends)?;
            change.execute("DELETE FROM hosts WHERE id = ?1", params![host]).map_err(depends)?;
        }
        for device in devices {
            change.execute("DELETE FROM devices WHERE id = ?1", params![device]).map_err(depends)?;
        }
        for principal in principals {
            change.execute("DELETE FROM principals WHERE id = ?1", params![principal]).map_err(depends)?;
        }
        change.commit().map_err(|error| trouble("finish undoing the import", error))
    }

    // ---- Computers that offer resources ----

    /// Records what a computer gives to the realm, replacing anything it offered before.
    ///
    /// A computer that offers again under another identity takes its workspace trail with it.
    /// The rows that say which computers have held a workspace's data outlive the offer on
    /// purpose, so they are re-pointed at the identity that is staying rather than deleted with
    /// the one that is going; deleting them would both lose the trail and make the database
    /// refuse the offer.
    pub fn put_host(&self, host: &Host) -> Result<(), String> {
        let change = self.connection.unchecked_transaction().map_err(|error| trouble("begin a change", error))?;
        // The row that is staying is written first, so the rows moved onto it below always have
        // somewhere to point.
        change
            .execute(
                "INSERT INTO hosts (id, realm_id, device_id, name, capacity, offered, gpu_isolation, commitment, draining, joined_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT(id) DO UPDATE SET name = excluded.name, capacity = excluded.capacity, offered = excluded.offered,
                     gpu_isolation = excluded.gpu_isolation, commitment = excluded.commitment, draining = excluded.draining",
                params![
                    host.id,
                    host.realm_id,
                    host.device_id,
                    host.name,
                    json(&host.capacity),
                    json(&host.offered),
                    word(&host.gpu_isolation),
                    word(&host.commitment),
                    host.draining as i64,
                    host.joined_at,
                ],
            )
            .map_err(|error| trouble("record this computer's offer", error))?;
        for moving in [
            // A reservation belongs to the computer that is staying, for the same reason: the
            // room is still taken, and a reservation pointing at a row that has gone would make
            // the offer itself fail.
            "UPDATE leases SET host_id = ?2 WHERE host_id IN (SELECT id FROM hosts WHERE device_id = ?1 AND id <> ?2)",
            "UPDATE workspace_assignments SET host_id = ?2 WHERE host_id IN (SELECT id FROM hosts WHERE device_id = ?1 AND id <> ?2)",
            "UPDATE workspace_artifacts SET packed_by = ?2 WHERE packed_by IN (SELECT id FROM hosts WHERE device_id = ?1 AND id <> ?2)",
            "UPDATE workspace_sessions SET host_id = ?2 WHERE host_id IN (SELECT id FROM hosts WHERE device_id = ?1 AND id <> ?2)",
            "UPDATE host_commitments SET host_id = ?2 WHERE host_id IN (SELECT id FROM hosts WHERE device_id = ?1 AND id <> ?2)",
        ] {
            change.execute(moving, params![host.device_id, host.id]).map_err(|error| trouble("carry this computer's workspaces across", error))?;
        }
        change.execute("DELETE FROM hosts WHERE device_id = ?1 AND id <> ?2", params![host.device_id, host.id]).map_err(|error| trouble("record this computer's offer", error))?;
        change.commit().map_err(|error| trouble("finish recording this computer's offer", error))
    }

    pub fn host(&self, id: &str) -> Result<Option<Host>, String> {
        self.connection
            .query_row(
                "SELECT id, realm_id, device_id, name, capacity, offered, gpu_isolation, commitment, draining, joined_at FROM hosts WHERE id = ?1",
                params![id],
                host_from,
            )
            .optional()
            .map_err(|error| trouble("read this computer", error))
    }

    pub fn hosts(&self) -> Result<Vec<Host>, String> {
        let mut query = self
            .connection
            // Computers come back in the order they joined. Two that joined in the same second
            // fall back to the order they were written, which is still that order; ordering them
            // by their random identifiers instead would move models between them for no reason.
            .prepare("SELECT id, realm_id, device_id, name, capacity, offered, gpu_isolation, commitment, draining, joined_at FROM hosts ORDER BY joined_at, rowid")
            .map_err(|error| trouble("read this grid's computers", error))?;
        let rows = query.query_map([], host_from).map_err(|error| trouble("read this grid's computers", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this grid's computers", error))
    }

    /// The host row one computer offers, if it offers one.
    ///
    /// `put_host` keeps there being at most one. Where a realm imported from an older record
    /// carries more, the newest offer is the one that answers, which is the row `put_host` would
    /// have kept.
    pub fn host_of_device(&self, device_id: &str) -> Result<Option<Host>, String> {
        self.connection
            .query_row(&format!("{HOSTS} WHERE device_id = ?1 ORDER BY joined_at DESC, rowid DESC"), params![device_id], host_from)
            .optional()
            .map_err(|error| trouble("read this computer", error))
    }

    /// Every host row one computer has offered, by identifier.
    pub fn hosts_of_device(&self, device_id: &str) -> Result<Vec<String>, String> {
        let mut query = self.connection.prepare("SELECT id FROM hosts WHERE device_id = ?1").map_err(|error| trouble("read this computer", error))?;
        let rows = query.query_map(params![device_id], |row| row.get::<_, String>(0)).map_err(|error| trouble("read this computer", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this computer", error))
    }

    pub fn host_count(&self) -> Result<usize, String> {
        self.count("SELECT COUNT(*) FROM hosts", params![])
    }

    pub fn set_draining(&self, host_id: &str, draining: bool) -> Result<(), String> {
        let touched = self
            .connection
            .execute("UPDATE hosts SET draining = ?2 WHERE id = ?1", params![host_id, draining as i64])
            .map_err(|error| trouble("empty this computer", error))?;
        if touched == 0 {
            return Err("No such computer is in this grid".into());
        }
        Ok(())
    }

    pub fn set_gpu_isolation(&self, host_id: &str, isolation: GpuIsolation) -> Result<(), String> {
        self.connection
            .execute("UPDATE hosts SET gpu_isolation = ?2 WHERE id = ?1", params![host_id, word(&isolation)])
            .map(|_| ())
            .map_err(|error| trouble("record how this card is shared", error))
    }

    // ---- Model serving profile ----

    pub fn model_plans(&self) -> Result<Vec<ModelPlan>, String> {
        let mut query = self
            .connection
            // Plans come back in the order the admin made them, because that order decides which
            // plan fills first when two want the same computer. Plans made in the same second
            // keep the order they were written in rather than the order of their identifiers.
            .prepare("SELECT id, realm_id, model, quant, percent, policy, target, created_at FROM model_plans ORDER BY created_at, rowid")
            .map_err(|error| trouble("read this grid's model plans", error))?;
        let rows = query.query_map([], model_plan_from).map_err(|error| trouble("read this grid's model plans", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this grid's model plans", error))
    }

    pub fn model_plan(&self, id: &str) -> Result<Option<ModelPlan>, String> {
        self.connection
            .query_row("SELECT id, realm_id, model, quant, percent, policy, target, created_at FROM model_plans WHERE id = ?1", params![id], model_plan_from)
            .optional()
            .map_err(|error| trouble("read this model plan", error))
    }

    pub fn model_assignments(&self) -> Result<Vec<ModelAssignment>, String> {
        let mut query = self
            .connection
            .prepare("SELECT plan_id, host_id, assigned_at FROM model_assignments ORDER BY assigned_at, plan_id, host_id")
            .map_err(|error| trouble("read this grid's model assignments", error))?;
        let rows = query.query_map([], model_assignment_from).map_err(|error| trouble("read this grid's model assignments", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this grid's model assignments", error))
    }

    /// Replaces the model profile atomically. The old assignment set is never visible between
    /// the plan update and its reconciliation.
    pub fn replace_model_state(&self, plans: &[ModelPlan], assignments: &[ModelAssignment]) -> Result<(), String> {
        let change = self.connection.unchecked_transaction().map_err(|error| trouble("begin a model change", error))?;
        change.execute("DELETE FROM model_assignments", []).map_err(|error| trouble("clear model assignments", error))?;
        change.execute("DELETE FROM model_plans", []).map_err(|error| trouble("clear model plans", error))?;
        for plan in plans {
            change.execute(
                "INSERT INTO model_plans (id, realm_id, model, quant, percent, policy, target, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![plan.id, plan.realm_id, plan.model, plan.quant, plan.percent as i64, json(&plan.policy), json(&plan.target), plan.created_at],
            ).map_err(|error| trouble("write a model plan", error))?;
        }
        for assignment in assignments {
            change.execute(
                "INSERT INTO model_assignments (plan_id, host_id, assigned_at) VALUES (?1, ?2, ?3)",
                params![assignment.plan_id, assignment.host_id, assignment.assigned_at],
            ).map_err(|error| trouble("write a model assignment", error))?;
        }
        change.commit().map_err(|error| trouble("finish the model change", error))
    }

    // ---- Work and reservations ----

    pub fn put_workload(&self, work: &Workload) -> Result<(), String> {
        Store::write_workload(&self.connection, work)
    }

    pub(crate) fn write_workload(connection: &Connection, work: &Workload) -> Result<(), String> {
        connection
            .execute(
                "INSERT INTO workloads (id, realm_id, capability, kind, principal_id, device_id, stage, needs, policy_version, lease_id, note, created_at, updated_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
                 ON CONFLICT(id) DO UPDATE SET stage = excluded.stage, needs = excluded.needs, lease_id = excluded.lease_id,
                     note = excluded.note, updated_at = excluded.updated_at, expires_at = excluded.expires_at",
                params![
                    work.id,
                    work.realm_id,
                    word(&work.capability),
                    word(&work.kind),
                    work.principal_id,
                    work.device_id,
                    word(&work.stage),
                    json(&work.needs),
                    work.policy_version as i64,
                    work.lease_id,
                    work.note,
                    work.created_at,
                    work.updated_at,
                    work.expires_at,
                ],
            )
            .map(|_| ())
            .map_err(|error| trouble("record this work", error))
    }

    pub fn workload(&self, id: &str) -> Result<Option<Workload>, String> {
        self.connection
            .query_row(
                "SELECT id, realm_id, capability, kind, principal_id, device_id, stage, needs, policy_version, lease_id, note, created_at, updated_at, expires_at
                 FROM workloads WHERE id = ?1",
                params![id],
                workload_from,
            )
            .optional()
            .map_err(|error| trouble("read this work", error))
    }

    pub fn workloads(&self) -> Result<Vec<Workload>, String> {
        let mut query = self
            .connection
            .prepare(
                "SELECT id, realm_id, capability, kind, principal_id, device_id, stage, needs, policy_version, lease_id, note, created_at, updated_at, expires_at
                 FROM workloads ORDER BY created_at, id",
            )
            .map_err(|error| trouble("read this grid's work", error))?;
        let rows = query.query_map([], workload_from).map_err(|error| trouble("read this grid's work", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this grid's work", error))
    }

    /// Work on a given computer that has not finished.
    ///
    /// The stages are spelled out here rather than filtered in Rust because the question is about
    /// one computer and reading every workload in the grid to answer it is what made this the
    /// clearest unscalable query in the file. `UNFINISHED` is the one place those words are
    /// written, and `the_words_for_a_finished_stage_match_the_code` keeps it honest against
    /// `Stage::finished`.
    pub fn unfinished_on(&self, device_id: &str) -> Result<Vec<Workload>, String> {
        self.workloads_where(&format!("WHERE device_id = ?1 AND {UNFINISHED} ORDER BY created_at, id"), params![device_id])
    }

    /// Work that has not finished and whose own deadline has passed. The sweep's query.
    pub fn unfinished_before(&self, deadline: i64) -> Result<Vec<Workload>, String> {
        self.workloads_where(&format!("WHERE expires_at IS NOT NULL AND expires_at <= ?1 AND {UNFINISHED} ORDER BY created_at, id"), params![deadline])
    }

    /// One person's work that has not finished.
    pub fn unfinished_of(&self, principal_id: &str) -> Result<Vec<Workload>, String> {
        self.workloads_where(&format!("WHERE principal_id = ?1 AND {UNFINISHED} ORDER BY created_at, id"), params![principal_id])
    }

    /// Work that has not finished, with a note of a given shape. The research profile asks this
    /// about one scope, and asked it by reading every workload in the realm.
    pub fn unfinished_noted(&self, note: &str) -> Result<Vec<Workload>, String> {
        self.workloads_where(&format!("WHERE note = ?1 AND {UNFINISHED} ORDER BY created_at, id"), params![note])
    }

    /// How much work is in flight at once, which is the number every sweep walks.
    pub fn unfinished_count(&self) -> Result<usize, String> {
        self.count(&format!("SELECT COUNT(*) FROM workloads WHERE {UNFINISHED}"), params![])
    }

    fn workloads_where(&self, tail: &str, binding: impl rusqlite::Params) -> Result<Vec<Workload>, String> {
        let mut query = self.connection.prepare(&format!("{WORKLOADS} {tail}")).map_err(|error| trouble("read this grid's work", error))?;
        let rows = query.query_map(binding, workload_from).map_err(|error| trouble("read this grid's work", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this grid's work", error))
    }

    /// One count, from one statement, so a caller never reads a table to measure it.
    fn count(&self, sql: &str, binding: impl rusqlite::Params) -> Result<usize, String> {
        self.connection.query_row(sql, binding, |row| row.get::<_, i64>(0)).map(|count| count.max(0) as usize).map_err(|error| trouble("count what this grid holds", error))
    }

    /// Whether a statement finds anything at all, without building what it found.
    fn any(&self, sql: &str, binding: impl rusqlite::Params) -> Result<bool, String> {
        self.connection.query_row(sql, binding, |row| row.get::<_, i64>(0)).map(|found| found != 0).map_err(|error| trouble("read this grid", error))
    }

    pub fn put_lease(&self, lease: &Lease) -> Result<(), String> {
        Store::write_lease(&self.connection, lease)
    }

    pub(crate) fn write_lease(connection: &Connection, lease: &Lease) -> Result<(), String> {
        connection
            .execute(
                "INSERT INTO leases (id, realm_id, host_id, workload_id, resources, generation, granted_at, expires_at, released_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(id) DO UPDATE SET resources = excluded.resources, generation = excluded.generation,
                     expires_at = excluded.expires_at, released_at = excluded.released_at",
                params![
                    lease.id,
                    lease.realm_id,
                    lease.host_id,
                    lease.workload_id,
                    json(&lease.resources),
                    lease.generation as i64,
                    lease.granted_at,
                    lease.expires_at,
                    lease.released_at,
                ],
            )
            .map(|_| ())
            .map_err(|error| trouble("reserve room on that computer", error))
    }

    pub fn lease(&self, id: &str) -> Result<Option<Lease>, String> {
        self.connection
            .query_row("SELECT id, realm_id, host_id, workload_id, resources, generation, granted_at, expires_at, released_at FROM leases WHERE id = ?1", params![id], lease_from)
            .optional()
            .map_err(|error| trouble("read this reservation", error))
    }

    pub fn leases(&self) -> Result<Vec<Lease>, String> {
        let mut query = self
            .connection
            .prepare("SELECT id, realm_id, host_id, workload_id, resources, generation, granted_at, expires_at, released_at FROM leases ORDER BY granted_at, id")
            .map_err(|error| trouble("read this grid's reservations", error))?;
        let rows = query.query_map([], lease_from).map_err(|error| trouble("read this grid's reservations", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this grid's reservations", error))
    }

    pub fn release_lease(&self, id: &str, now: i64) -> Result<(), String> {
        self.connection
            .execute("UPDATE leases SET released_at = ?2 WHERE id = ?1 AND released_at IS NULL", params![id, now])
            .map(|_| ())
            .map_err(|error| trouble("give that reservation back", error))
    }

    /// Gives back every reservation held by a piece of work.
    pub fn release_for(&self, workload_id: &str, now: i64) -> Result<usize, String> {
        self.connection
            .execute("UPDATE leases SET released_at = ?2 WHERE workload_id = ?1 AND released_at IS NULL", params![workload_id, now])
            .map_err(|error| trouble("give those reservations back", error))
    }

    /// What is reserved on one computer at `now`, as the reservations say it.
    ///
    /// This is the query behind `Core::free_on`, which used to read every reservation in the grid
    /// to total what was taken on one computer. The subtraction stays in Rust: `hosts.offered` and
    /// `leases.resources` are both written as JSON, and splitting them into columns would make a
    /// second source of truth for what a computer gave.
    pub fn reserved_on(&self, host_id: &str, now: i64) -> Result<Vec<Resources>, String> {
        let mut query = self
            .connection
            .prepare("SELECT resources FROM leases WHERE host_id = ?1 AND released_at IS NULL AND ?2 < expires_at")
            .map_err(|error| trouble("read what is reserved on this computer", error))?;
        let rows = query
            .query_map(params![host_id, now], |row| unjson::<Resources>(&row.get::<_, String>(0)?, "a reservation"))
            .map_err(|error| trouble("read what is reserved on this computer", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read what is reserved on this computer", error))
    }

    /// Every reservation still holding room at `now`. One query for a decision that has to look at
    /// every computer, instead of one query per computer.
    pub fn live_leases(&self, now: i64) -> Result<Vec<Lease>, String> {
        let mut query = self
            .connection
            .prepare(&format!("{LEASES} WHERE released_at IS NULL AND ?1 < expires_at ORDER BY granted_at, id"))
            .map_err(|error| trouble("read this grid's reservations", error))?;
        let rows = query.query_map(params![now], lease_from).map_err(|error| trouble("read this grid's reservations", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this grid's reservations", error))
    }

    /// The reservations on one computer that have not been given back, whether or not they have
    /// run out. Served by the index on (host_id, released_at).
    pub fn leases_on(&self, host_id: &str) -> Result<Vec<Lease>, String> {
        let mut query = self
            .connection
            .prepare(&format!("{LEASES} WHERE host_id = ?1 AND released_at IS NULL ORDER BY granted_at, id"))
            .map_err(|error| trouble("read this grid's reservations", error))?;
        let rows = query.query_map(params![host_id], lease_from).map_err(|error| trouble("read this grid's reservations", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this grid's reservations", error))
    }

    /// The computers one piece of work has held a reservation on, in the order it held them.
    ///
    /// One entry per reservation and not one per computer, because the count is the retry budget:
    /// `work::TRIES` is compared against the length of this.
    pub fn leases_tried(&self, workload_id: &str) -> Result<Vec<String>, String> {
        let mut query = self
            .connection
            .prepare("SELECT host_id FROM leases WHERE workload_id = ?1 ORDER BY granted_at, id")
            .map_err(|error| trouble("read where this work has been", error))?;
        let rows = query.query_map(params![workload_id], |row| row.get::<_, String>(0)).map_err(|error| trouble("read where this work has been", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read where this work has been", error))
    }

    /// How old the oldest reservation still holding room is, in seconds, and how many there are.
    pub fn live_lease_age(&self, now: i64) -> Result<(usize, i64), String> {
        self.connection
            .query_row(
                "SELECT COUNT(*), COALESCE(?1 - MIN(granted_at), 0) FROM leases WHERE released_at IS NULL AND ?1 < expires_at",
                params![now],
                |row| Ok((row.get::<_, i64>(0)?.max(0) as usize, row.get::<_, i64>(1)?)),
            )
            .map_err(|error| trouble("read this grid's reservations", error))
    }

    /// Reservations that have run out, with the work that held them.
    pub fn lapsed_leases(&self, now: i64) -> Result<Vec<(String, String)>, String> {
        let mut query = self
            .connection
            .prepare("SELECT id, workload_id FROM leases WHERE released_at IS NULL AND ?1 >= expires_at")
            .map_err(|error| trouble("read this grid's reservations", error))?;
        let rows = query.query_map(params![now], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))).map_err(|error| trouble("read this grid's reservations", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this grid's reservations", error))
    }

    // ---- Requests and decisions ----

    pub fn put_request(&self, request: &Approval) -> Result<(), String> {
        self.connection
            .execute(
                "INSERT INTO requests (id, realm_id, action, resource_id, method, path, requested_by, requested_at, expires_at, every_time, state)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    request.id,
                    request.realm_id,
                    request.action,
                    request.resource_id,
                    request.method,
                    request.path,
                    request.requested_by,
                    request.requested_at,
                    request.expires_at,
                    request.every_time as i64,
                    word(&request.state),
                ],
            )
            .map(|_| ())
            .map_err(|error| trouble("ask for agreement", error))
    }

    pub fn request(&self, id: &str) -> Result<Option<Approval>, String> {
        self.connection
            .query_row(&format!("{REQUESTS} WHERE r.id = ?1"), params![id], approval_from)
            .optional()
            .map_err(|error| trouble("read this request", error))
    }

    pub fn requests(&self) -> Result<Vec<Approval>, String> {
        let mut query = self.connection.prepare(&format!("{REQUESTS} ORDER BY r.requested_at, r.id")).map_err(|error| trouble("read this grid's requests", error))?;
        let rows = query.query_map([], approval_from).map_err(|error| trouble("read this grid's requests", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this grid's requests", error))
    }

    /// The agreements one person holds about one thing that still stand at `now`, oldest first.
    ///
    /// The caller still reads the action, the method and the path off each one, because those
    /// rules are the difference between an agreement to send a company secret and an agreement to
    /// approve research. What this narrows is which rows are read at all: one person and one
    /// credential, rather than every request the realm has ever held.
    pub fn standing_requests_about(&self, resource_id: &str, requested_by: &str, now: i64) -> Result<Vec<Approval>, String> {
        let mut query = self
            .connection
            .prepare(&format!("{REQUESTS} WHERE r.resource_id = ?1 AND r.requested_by = ?2 AND r.state = 'granted' AND ?3 < r.expires_at ORDER BY r.requested_at, r.id"))
            .map_err(|error| trouble("read this grid's requests", error))?;
        let rows = query.query_map(params![resource_id, requested_by, now], approval_from).map_err(|error| trouble("read this grid's requests", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this grid's requests", error))
    }

    /// Whether anybody other than `besides` holds one of these permissions and is not suspended.
    ///
    /// This is `approval::other_approvers(...).is_empty()` asked of the database instead of of
    /// every account in the realm. The join to `principals` is the part that must not be dropped:
    /// `Principal::may` is `active() && any role may`, so a suspended approver has never counted,
    /// and an answer that forgot the join would leave a realm where the last unsuspended approver
    /// is refused their own request and nothing can be approved at all.
    pub fn another_holder_of(&self, permissions: &[Role], besides: &str) -> Result<bool, String> {
        if permissions.is_empty() {
            return Ok(false);
        }
        let words: Vec<String> = permissions.iter().map(word).collect();
        let places = (0..words.len()).map(|at| format!("?{}", at + 2)).collect::<Vec<_>>().join(", ");
        let sql = format!(
            "SELECT EXISTS(SELECT 1 FROM permissions p JOIN principals s ON s.id = p.principal_id
                            WHERE p.principal_id <> ?1 AND s.suspended_at IS NULL AND p.permission IN ({places}))"
        );
        let mut binding: Vec<&dyn rusqlite::ToSql> = Vec::with_capacity(words.len() + 1);
        binding.push(&besides);
        for held in &words {
            binding.push(held);
        }
        self.any(&sql, rusqlite::params_from_iter(binding))
    }

    /// How many requests are waiting for somebody to answer them, and how long the oldest has
    /// waited.
    pub fn waiting_requests(&self, now: i64) -> Result<(usize, i64), String> {
        self.connection
            .query_row(
                "SELECT COUNT(*), COALESCE(?1 - MIN(requested_at), 0) FROM requests WHERE state = 'waiting' AND ?1 < expires_at",
                params![now],
                |row| Ok((row.get::<_, i64>(0)?.max(0) as usize, row.get::<_, i64>(1)?)),
            )
            .map_err(|error| trouble("read this grid's requests", error))
    }

    /// How many decisions were made since `since`, and how long on average they took.
    pub fn decided_since(&self, since: i64) -> Result<(usize, i64), String> {
        self.connection
            .query_row(
                "SELECT COUNT(*), CAST(COALESCE(AVG(d.decided_at - r.requested_at), 0) AS INTEGER)
                   FROM decisions d JOIN requests r ON r.id = d.request_id WHERE d.decided_at > ?1",
                params![since],
                |row| Ok((row.get::<_, i64>(0)?.max(0) as usize, row.get::<_, i64>(1)?)),
            )
            .map_err(|error| trouble("read this grid's decisions", error))
    }

    /// Writes a decision and, where there is one, the standing allowance it creates. Both land
    /// together. The decision itself is insert-only: there is no path here that changes one.
    pub fn record_decision(&self, decided: &Approval, verdict: &str, until: Option<i64>, allowance: Option<&Allowance>) -> Result<(), String> {
        let change = self.connection.unchecked_transaction().map_err(|error| trouble("begin a change", error))?;
        let state: String = change
            .query_row("SELECT state FROM requests WHERE id = ?1", params![decided.id], |row| row.get(0))
            .optional()
            .map_err(|error| trouble("read this request", error))?
            .ok_or("No such request")?;
        if state != "waiting" {
            return Err("This request was already decided".into());
        }
        change
            .execute("UPDATE requests SET state = ?2 WHERE id = ?1 AND state = 'waiting'", params![decided.id, word(&decided.state)])
            .map_err(|error| trouble("record the decision", error))?;
        change
            .execute(
                "INSERT INTO decisions (id, request_id, realm_id, verdict, until, decided_by, decided_at, self_issued, reason, allowance_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    fresh("decision"),
                    decided.id,
                    decided.realm_id,
                    verdict,
                    until,
                    decided.decided_by.clone().unwrap_or_default(),
                    decided.decided_at.unwrap_or_default(),
                    decided.self_issued as i64,
                    decided.reason,
                    allowance.map(|allowance| allowance.id.clone()),
                ],
            )
            .map_err(|error| trouble("record the decision", error))?;
        if let Some(allowance) = allowance {
            change
                .execute(
                    "INSERT INTO standing_allowances (id, realm_id, principal_id, resource_id, method, path, approver_id, request_id, created_at, expires_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    params![
                        allowance.id,
                        allowance.realm_id,
                        allowance.principal_id,
                        allowance.resource_id,
                        allowance.method,
                        allowance.path,
                        allowance.approved_by,
                        allowance.approval_id,
                        allowance.granted_at,
                        allowance.expires_at,
                    ],
                )
                .map_err(|error| trouble("record the standing allowance", error))?;
        }
        change.commit().map_err(|error| trouble("finish recording the decision", error))
    }

    /// Lapses requests nobody answered.
    pub fn lapse_requests(&self, now: i64) -> Result<usize, String> {
        self.connection
            .execute("UPDATE requests SET state = 'expired' WHERE state = 'waiting' AND ?1 >= expires_at", params![now])
            .map_err(|error| trouble("lapse the requests nobody answered", error))
    }

    pub fn allowances(&self) -> Result<Vec<Allowance>, String> {
        let mut query = self
            .connection
            .prepare("SELECT id, realm_id, principal_id, resource_id, method, path, request_id, approver_id, created_at, expires_at FROM standing_allowances ORDER BY created_at, id")
            .map_err(|error| trouble("read this grid's standing allowances", error))?;
        let rows = query.query_map([], allowance_from).map_err(|error| trouble("read this grid's standing allowances", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this grid's standing allowances", error))
    }

    /// The standing allowance that covers this, if one does.
    ///
    /// The `WHERE` reproduces `Allowance::covers` exactly, including that an allowance with no
    /// method or no path covers any, and the order decides which of several wins, exactly as the
    /// Rust filter over `allowances()` did. A difference here would be a change to who may use a
    /// credential made in the name of speed, which is why the two are tested against each other.
    pub fn allowance_for(&self, principal_id: &str, resource_id: &str, method: Option<&str>, path: Option<&str>, now: i64) -> Result<Option<Allowance>, String> {
        let wanted = method.map(|method| method.to_ascii_uppercase());
        self.connection
            .query_row(
                "SELECT id, realm_id, principal_id, resource_id, method, path, request_id, approver_id, created_at, expires_at FROM standing_allowances
                  WHERE principal_id = ?1 AND resource_id = ?2 AND ?3 < expires_at
                    AND (method IS NULL OR method = ?4)
                    AND (path IS NULL OR path = ?5)
                  ORDER BY created_at, id LIMIT 1",
                params![principal_id, resource_id, now, wanted, path],
                allowance_from,
            )
            .optional()
            .map_err(|error| trouble("read this grid's standing allowances", error))
    }

    /// Whether a standing allowance that came from this request is still live.
    pub fn allowance_from(&self, approval_id: &str, now: i64) -> Result<bool, String> {
        self.any("SELECT EXISTS(SELECT 1 FROM standing_allowances WHERE request_id = ?1 AND ?2 < expires_at)", params![approval_id, now])
    }

    /// How many standing allowances are live.
    pub fn live_allowance_count(&self, now: i64) -> Result<usize, String> {
        self.count("SELECT COUNT(*) FROM standing_allowances WHERE ?1 < expires_at", params![now])
    }

    pub fn drop_lapsed_allowances(&self, now: i64) -> Result<usize, String> {
        self.connection.execute("DELETE FROM standing_allowances WHERE ?1 >= expires_at", params![now]).map_err(|error| trouble("drop the allowances that ran out", error))
    }

    // ---- Permissions handed to work ----

    /// Remembers a permission as it was issued, with the generations it was issued under, so its
    /// use can be checked against what is true at that moment.
    pub fn remember_capability(&self, claims: &Claims) -> Result<(), String> {
        let realm_generation = self.realm_generation()? as i64;
        let principal_generation = self.generation_of("principals", &claims.principal_id)?;
        let device_generation = self.generation_of("devices", &claims.device_id)?;
        let policy_version = self.policy_version()? as i64;
        // What the permission is for has a generation of its own when it is a workspace, and it
        // is written here rather than left to the one caller that knows about it. A permission
        // whose workspace has since changed hands is then refused by the same mechanism that
        // refuses a suspended account, on every path, not only the workspace one.
        let resource_generation = self.resource_generation(claims)?;
        self.connection
            .execute(
                "INSERT INTO capabilities (id, realm_id, capability, principal_id, device_id, workload_id, resource_id, realm_gen, principal_gen, device_gen, policy_version, single_use, issued_at, expires_at, spent_at, approval_id, resource_gen)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, NULL, ?15, ?16)",
                params![
                    claims.id,
                    claims.realm_id,
                    word(&claims.capability),
                    claims.principal_id,
                    claims.device_id,
                    claims.workload_id,
                    claims.resource_id,
                    realm_generation,
                    principal_generation,
                    device_generation,
                    policy_version,
                    claims.single_use as i64,
                    claims.issued_at,
                    claims.expires_at,
                    claims.approval_id,
                    resource_generation,
                ],
            )
            .map(|_| ())
            .map_err(|error| trouble("issue this permission", error))
    }

    /// The generation of the thing a permission is for, where that thing has one.
    ///
    /// A workspace raises its generation whenever it changes hands or is rebuilt, a credential
    /// raises its own on every rotation and on retirement, and a research scope raises its own
    /// whenever what it allows narrows. All three are written here rather than left to the one
    /// caller that knows about them, so a permission whose subject has moved on is refused by the
    /// same mechanism that refuses a suspended account, on every path.
    ///
    /// A research permission names its scope, so this finds one. A research permission about
    /// anything else finds no row, the column is left null, and nothing is compared.
    fn resource_generation(&self, claims: &Claims) -> Result<Option<i64>, String> {
        let (table, what) = match claims.capability {
            Capability::Workspaces => ("workspaces", "read this workspace's generation"),
            Capability::Credentials => ("credentials", "read this credential's generation"),
            Capability::Research => ("research_scopes", "read this research scope's generation"),
            _ => return Ok(None),
        };
        self.connection
            .query_row(&format!("SELECT generation FROM {table} WHERE id = ?1"), params![claims.resource_id], |row| row.get::<_, i64>(0))
            .optional()
            .map_err(|error| trouble(what, error))
    }

    /// Whether an agreement has already been turned into a permission. An approver who agreed
    /// once agreed to one use, and this is how that is known without changing the decision.
    pub fn approval_spent(&self, approval_id: &str) -> Result<bool, String> {
        self.connection
            .query_row("SELECT 1 FROM capabilities WHERE approval_id = ?1 LIMIT 1", params![approval_id], |_| Ok(true))
            .optional()
            .map(|found| found.unwrap_or(false))
            .map_err(|error| trouble("read what this agreement allowed", error))
    }

    /// What the database says about its own shape, and whether every reference leads somewhere.
    /// Nothing wrong is an empty list.
    ///
    /// The realm turns foreign keys on when it opens, so a realm this process wrote through its
    /// own doors has nothing to find here. What this is for is a realm that came from somewhere
    /// else: an import, a restore, a file that was copied while it was being written, or one
    /// something has damaged. Before this there was no way to ask at all.
    pub fn faults(&self) -> Result<Vec<String>, String> {
        let mut found = Vec::new();
        let mut shape = self.connection.prepare("PRAGMA integrity_check").map_err(|error| trouble("check the grid's file", error))?;
        let answers = shape.query_map([], |row| row.get::<_, String>(0)).map_err(|error| trouble("check the grid's file", error))?;
        for answer in answers {
            let answer = answer.map_err(|error| trouble("check the grid's file", error))?;
            if answer != "ok" {
                found.push(format!("The grid's file: {answer}"));
            }
        }
        let mut references = self.connection.prepare("PRAGMA foreign_key_check").map_err(|error| trouble("check the grid's references", error))?;
        let broken = references
            .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<i64>>(1)?, row.get::<_, String>(2)?)))
            .map_err(|error| trouble("check the grid's references", error))?;
        for row in broken {
            let (table, rowid, points_at) = row.map_err(|error| trouble("check the grid's references", error))?;
            found.push(format!("A row in {table} ({}) points at {points_at}, which is not there", rowid.map(|id| id.to_string()).unwrap_or_else(|| "no row id".into())));
        }
        Ok(found)
    }

    /// The open connection, for the tests that ask the database about its own shape: which tables
    /// it has, which columns, and what a trigger refuses. Nothing outside a test has a reason to
    /// reach past the methods here.
    #[cfg(test)]
    pub(crate) fn connection_for_tests(&self) -> &Connection {
        &self.connection
    }

    /// A row's generation, for the property tests. There is no reason for a caller outside this
    /// file to read one, so this is `cfg(test)` rather than a method that could become public by
    /// being convenient.
    #[cfg(test)]
    pub(crate) fn generation_for_tests(&self, table: &str, id: &str) -> Result<i64, String> {
        self.generation_of(table, id)
    }

    /// Every decision written for one request, as who decided and when. Nought or one of them,
    /// which is what the property test is there to find out.
    #[cfg(test)]
    pub(crate) fn decisions_for_tests(&self, request_id: &str) -> Result<Vec<(String, i64)>, String> {
        let mut query = self
            .connection
            .prepare("SELECT decided_by, decided_at FROM decisions WHERE request_id = ?1 ORDER BY decided_at")
            .map_err(|error| trouble("read the decisions on a request", error))?;
        let rows = query.query_map(params![request_id], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))).map_err(|error| trouble("read the decisions on a request", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read the decisions on a request", error))
    }

    fn generation_of(&self, table: &str, id: &str) -> Result<i64, String> {
        let query = format!("SELECT generation FROM {table} WHERE id = ?1");
        Ok(self.connection.query_row(&query, params![id], |row| row.get::<_, i64>(0)).optional().map_err(|error| trouble("read a generation", error))?.unwrap_or(0))
    }

    /// Checks a permission against what is true now: the realm, the account, the computer, the
    /// policy, and whether it has already been used. Nothing here trusts the claims the holder
    /// carries; every one of them is looked up again.
    pub fn check_capability(&self, claims: &Claims, now: i64) -> Result<Option<Stale>, String> {
        let _ = now;
        let found = self
            .connection
            .query_row(
                "SELECT realm_gen, principal_gen, device_gen, policy_version, single_use, spent_at, resource_gen FROM capabilities WHERE id = ?1",
                params![claims.id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)? != 0,
                        row.get::<_, Option<i64>>(5)?,
                        row.get::<_, Option<i64>>(6)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| trouble("read this permission", error))?;
        // Whether or not this realm still remembers issuing it, the account and the computer it
        // names are looked at as they are now.
        if let Some(person) = self.principal(&claims.principal_id)? {
            if !person.active() {
                return Ok(Some(Stale::Withdrawn));
            }
        }
        if let Some(device) = self.device(&claims.device_id)? {
            if !device.active() {
                return Ok(Some(Stale::Withdrawn));
            }
        }
        let Some((realm_generation, principal_generation, device_generation, policy_version, single_use, spent_at, resource_generation)) = found else {
            return Ok(Some(Stale::Unknown));
        };
        if realm_generation != self.realm_generation()? as i64 {
            return Ok(Some(Stale::Withdrawn));
        }
        if principal_generation != self.generation_of("principals", &claims.principal_id)? {
            return Ok(Some(Stale::Withdrawn));
        }
        if device_generation != self.generation_of("devices", &claims.device_id)? {
            return Ok(Some(Stale::Withdrawn));
        }
        // What the permission was for may itself have moved on. Compared by equality, like every
        // other generation here: a workspace that has changed hands, been emptied or been rebuilt
        // refuses what was handed out before it did, and a workspace that is gone refuses
        // everything. A credential that has been rotated or retired does the same, which is what
        // makes a rotation stop the next request without anything having to be found and deleted.
        if let Some(issued_under) = resource_generation {
            if Some(issued_under) != self.resource_generation(claims)? {
                return Ok(Some(if claims.capability == Capability::Credentials { Stale::Replaced } else { Stale::Withdrawn }));
            }
        }
        if policy_version != self.policy_version()? as i64 {
            return Ok(Some(Stale::PolicyChanged));
        }
        if single_use && spent_at.is_some() {
            return Ok(Some(Stale::AlreadyUsed));
        }
        Ok(None)
    }

    /// Marks a single-use permission as spent, so a restart does not forget it, and says whether
    /// this call is the one that spent it.
    ///
    /// The answer matters. One statement with `spent_at IS NULL` in its WHERE is the only thing
    /// here that settles a race between two writers, so a caller that reads a permission as
    /// unspent and then calls this has to be told whether somebody else got there first. A row
    /// count of nought means it was already spent, or this realm never issued it.
    pub fn spend_capability(&self, id: &str, now: i64) -> Result<usize, String> {
        self.connection
            .execute("UPDATE capabilities SET spent_at = ?2 WHERE id = ?1 AND spent_at IS NULL AND single_use = 1", params![id, now])
            .map_err(|error| trouble("spend this permission", error))
    }

    /// Forgets permissions that expired a while ago. An expired one is refused on its own expiry,
    /// so nothing is weakened by letting the record of it go, with one exception: while the
    /// agreement a permission came from still stands, that row is the only record anywhere that
    /// the agreement was already used, and `approval_spent` reads it. Someone who agreed once
    /// agreed to one use, so such a row stays until the agreement has itself run out, after which
    /// the agreement allows nothing and the row proves nothing.
    ///
    /// Most permissions name no agreement at all, and `NOT EXISTS` is true for those, so ordinary
    /// housekeeping is untouched.
    pub fn forget_expired_capabilities(&self, before: i64) -> Result<usize, String> {
        self.connection
            .execute(
                "DELETE FROM capabilities WHERE expires_at < ?1
                   AND NOT EXISTS (SELECT 1 FROM requests
                                    WHERE requests.id = capabilities.approval_id
                                      AND requests.state = 'granted'
                                      AND ?1 < requests.expires_at)",
                params![before],
            )
            .map_err(|error| trouble("tidy old permissions", error))
    }

    // ---- Credentials ----

    /// Records a credential: where its value is kept, and the one place it may be sent. The value
    /// itself never reaches this method, and there is no column that could hold one.
    pub fn put_credential(&self, credential: &Credential) -> Result<(), String> {
        let change = self.connection.unchecked_transaction().map_err(|error| trouble("begin a change", error))?;
        change
            .execute(
                "INSERT INTO credentials (id, realm_id, name, kind, vault_id, vault_version, fingerprint, destination, methods, paths, maximum_bytes, owner_id, every_time, created_at, rotated_at, rotate_by, retired_at, generation, presentation, field, settings, query_allowed_by, query_allowed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23)
                 ON CONFLICT(id) DO UPDATE SET name = excluded.name, vault_version = excluded.vault_version, fingerprint = excluded.fingerprint,
                     methods = excluded.methods, paths = excluded.paths, maximum_bytes = excluded.maximum_bytes,
                     every_time = excluded.every_time, rotated_at = excluded.rotated_at, rotate_by = excluded.rotate_by, retired_at = excluded.retired_at,
                     presentation = excluded.presentation, field = excluded.field, settings = excluded.settings,
                     query_allowed_by = excluded.query_allowed_by, query_allowed_at = excluded.query_allowed_at,
                     generation = MAX(credentials.generation, excluded.generation)",
                params![
                    credential.id,
                    credential.realm_id,
                    credential.name,
                    word(&credential.kind),
                    credential.vault.id,
                    credential.vault.version as i64,
                    credential.fingerprint,
                    credential.destination,
                    json(&credential.methods),
                    json(&credential.paths),
                    credential.maximum_bytes.map(|bytes| bytes as i64),
                    credential.owner_id,
                    credential.every_time as i64,
                    credential.created_at,
                    credential.rotated_at,
                    credential.rotate_by,
                    credential.retired_at,
                    credential.generation.max(1) as i64,
                    word(&credential.presentation),
                    credential.field,
                    json(&credential.settings),
                    credential.query_allowed_by,
                    credential.query_allowed_at,
                ],
            )
            .map_err(|error| trouble("record this credential", error))?;
        // The places it may be sent arrive with it, so a credential brought across from a backup
        // is not left with a list the broker would refuse.
        for destination in credential.places() {
            change
                .execute(
                    "INSERT OR IGNORE INTO credential_destinations (credential_id, destination, added_by, added_at) VALUES (?1, ?2, ?3, ?4)",
                    params![credential.id, destination, credential.owner_id, credential.created_at],
                )
                .map_err(|error| trouble("record where this credential may be sent", error))?;
        }
        change.commit().map_err(|error| trouble("finish recording this credential", error))
    }

    pub fn credential(&self, id: &str) -> Result<Option<Credential>, String> {
        let found = self
            .connection
            .query_row(&format!("{CREDENTIALS} WHERE id = ?1"), params![id], credential_from)
            .optional()
            .map_err(|error| trouble("read this credential", error))?;
        match found {
            Some(mut credential) => {
                credential.destinations = self.destinations(&credential.id)?;
                Ok(Some(credential))
            }
            None => Ok(None),
        }
    }

    pub fn credentials(&self) -> Result<Vec<Credential>, String> {
        let mut query = self.connection.prepare(&format!("{CREDENTIALS} ORDER BY created_at, id")).map_err(|error| trouble("read this grid's credentials", error))?;
        let rows = query.query_map([], credential_from).map_err(|error| trouble("read this grid's credentials", error))?;
        let mut credentials = rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this grid's credentials", error))?;
        for credential in &mut credentials {
            credential.destinations = self.destinations(&credential.id)?;
        }
        Ok(credentials)
    }

    /// Adds a place a credential may be sent. The caller has already written the destination the
    /// forwarder's way; this only records it.
    pub fn put_destination(&self, credential_id: &str, destination: &str, by: &str, now: i64) -> Result<(), String> {
        self.connection
            .execute(
                "INSERT OR IGNORE INTO credential_destinations (credential_id, destination, added_by, added_at) VALUES (?1, ?2, ?3, ?4)",
                params![credential_id, destination, by, now],
            )
            .map(|_| ())
            .map_err(|error| trouble("record where this credential may be sent", error))
    }

    /// Records that an administrator allowed this credential's value to travel in the URL, or
    /// takes that back. The pair moves together, because one without the other says nothing, and
    /// the database refuses a half of it.
    pub fn set_query_allowed(&self, credential_id: &str, allowed: Option<(&str, i64)>) -> Result<(), String> {
        let touched = self
            .connection
            .execute(
                "UPDATE credentials SET query_allowed_by = ?2, query_allowed_at = ?3 WHERE id = ?1 AND retired_at IS NULL",
                params![credential_id, allowed.map(|(by, _)| by), allowed.map(|(_, at)| at)],
            )
            .map_err(|error| trouble("record how this credential may travel", error))?;
        if touched == 0 {
            return Err("No such credential is in this grid, or it has been retired".into());
        }
        Ok(())
    }

    /// Writes a credential's one destination the way a version 4 build wrote one, so a test can
    /// make the realm version 5's backfill could not carry and then read the report of it.
    ///
    /// A version 4 build's only rule was that a destination began `https://`, and this grid's
    /// doors refuse such an address, so there is no other way to build that realm here.
    #[cfg(test)]
    pub fn write_destination_as_version_four_did(&self, credential_id: &str, destination: &str) -> Result<(), String> {
        self.connection
            .execute("UPDATE credentials SET destination = ?2 WHERE id = ?1", params![credential_id, destination])
            .map(|_| ())
            .map_err(|error| trouble("write a version four destination", error))
    }

    /// Replaces what a minting credential needs besides its value. Names and addresses; the
    /// caller has already put them through `credential::checked_settings`.
    pub fn set_credential_settings(&self, credential_id: &str, settings: &std::collections::BTreeMap<String, String>) -> Result<(), String> {
        let touched = self
            .connection
            .execute("UPDATE credentials SET settings = ?2 WHERE id = ?1 AND retired_at IS NULL", params![credential_id, json(settings)])
            .map_err(|error| trouble("record what this credential needs to make a token", error))?;
        if touched == 0 {
            return Err("No such credential is in this grid, or it has been retired".into());
        }
        Ok(())
    }

    /// Takes one away, and says how many rows that was, so a caller can tell nothing from
    /// something.
    pub fn drop_destination(&self, credential_id: &str, destination: &str) -> Result<usize, String> {
        self.connection
            .execute("DELETE FROM credential_destinations WHERE credential_id = ?1 AND destination = ?2", params![credential_id, destination])
            .map_err(|error| trouble("take a place away from this credential", error))
    }

    /// Every place one credential may be sent, oldest first, so the first is the one it was
    /// recorded with.
    pub fn destinations(&self, credential_id: &str) -> Result<Vec<String>, String> {
        let mut query = self
            .connection
            .prepare("SELECT destination FROM credential_destinations WHERE credential_id = ?1 ORDER BY added_at, destination")
            .map_err(|error| trouble("read where this credential may be sent", error))?;
        let rows = query.query_map(params![credential_id], |row| row.get::<_, String>(0)).map_err(|error| trouble("read where this credential may be sent", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read where this credential may be sent", error))
    }

    /// The realm's own outbound rules. The caller refreshes its copy of the realm afterwards.
    pub fn set_network(&self, network: &NetworkPolicy) -> Result<(), String> {
        self.connection
            .execute("UPDATE realms SET network = ?1", params![json(network)])
            .map(|_| ())
            .map_err(|error| trouble("change what this grid may reach", error))
    }

    /// Opens the record of one brokered request, before any value is read.
    ///
    /// A conflict on the permission is a refusal rather than a database error: it means another
    /// hub holding the same realm is already inside this permission, and the one that loses the
    /// insert is the one that does not send.
    pub fn open_use(&self, row: &Use) -> Result<(), String> {
        self.connection
            .execute(
                "INSERT INTO credential_uses (id, realm_id, credential_id, capability_id, approval_id, principal_id, device_id, workload_id, destination, method, path,
                     request_bytes, answer_bytes, status, vault_id, vault_version, outcome, reason, policy_version, started_at, finished_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, NULL, NULL, ?13, ?14, 'opening', '', ?15, ?16, NULL)",
                params![
                    row.id,
                    row.realm_id,
                    row.credential_id,
                    row.capability_id,
                    row.approval_id,
                    row.principal_id,
                    row.device_id,
                    row.workload_id,
                    row.destination,
                    row.method,
                    row.path,
                    row.request_bytes as i64,
                    row.vault_id,
                    row.vault_version as i64,
                    row.policy_version as i64,
                    row.started_at,
                ],
            )
            .map(|_| ())
            .map_err(|error| match error {
                // 2067 and 1555 are SQLite's own codes for a unique column and a primary key. The
                // unique column here is the permission, so this is the other hub winning the race.
                rusqlite::Error::SqliteFailure(failure, _) if matches!(failure.extended_code, 2067 | 1555) => "Another computer is already using this permission".to_owned(),
                error => trouble("open the record of this request", error),
            })
    }

    /// Closes it, once, with how it ended. The database refuses a second close.
    pub fn close_use(&self, id: &str, outcome: &str, reason: &str, status: Option<u16>, answer_bytes: Option<u64>, now: i64) -> Result<(), String> {
        let touched = self
            .connection
            .execute(
                "UPDATE credential_uses SET outcome = ?2, reason = ?3, status = ?4, answer_bytes = ?5, finished_at = ?6 WHERE id = ?1",
                params![id, outcome, reason, status.map(i64::from), answer_bytes.map(|bytes| bytes as i64), now],
            )
            .map_err(|error| trouble("close the record of this request", error))?;
        if touched == 0 {
            return Err("There is no open record of that request".into());
        }
        Ok(())
    }

    /// The ledger of brokered requests, newest last, for one credential or for all of them.
    pub fn uses(&self, credential_id: Option<&str>, since: i64) -> Result<Vec<Use>, String> {
        let (query, parameters): (String, Vec<Box<dyn rusqlite::ToSql>>) = match credential_id {
            Some(id) => (format!("{USES} WHERE credential_id = ?1 AND started_at >= ?2 ORDER BY started_at, id"), vec![Box::new(id.to_owned()), Box::new(since)]),
            None => (format!("{USES} WHERE started_at >= ?1 ORDER BY started_at, id"), vec![Box::new(since)]),
        };
        let mut statement = self.connection.prepare(&query).map_err(|error| trouble("read what this grid has sent", error))?;
        let rows = statement
            .query_map(rusqlite::params_from_iter(parameters.iter().map(|value| value.as_ref())), use_from)
            .map_err(|error| trouble("read what this grid has sent", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read what this grid has sent", error))
    }

    /// The requests still recorded as opening, for closing after a crash.
    pub fn open_uses(&self, started_before: i64) -> Result<Vec<Use>, String> {
        let mut query = self
            .connection
            .prepare(&format!("{USES} WHERE finished_at IS NULL AND started_at < ?1 ORDER BY started_at"))
            .map_err(|error| trouble("read what this grid has sent", error))?;
        let rows = query.query_map(params![started_before], use_from).map_err(|error| trouble("read what this grid has sent", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read what this grid has sent", error))
    }

    /// Records that the value behind a credential has been replaced. The new value goes into the
    /// vault; what changes here is which version is current and what it fingerprints to.
    pub fn rotate_credential(&self, id: &str, fingerprint: &str, now: i64) -> Result<u32, String> {
        let touched = self
            .connection
            .execute(
                "UPDATE credentials SET vault_version = vault_version + 1, fingerprint = ?2, rotated_at = ?3, generation = generation + 1 WHERE id = ?1 AND retired_at IS NULL",
                params![id, fingerprint, now],
            )
            .map_err(|error| trouble("rotate this credential", error))?;
        if touched == 0 {
            return Err("No such credential is in this grid, or it has been retired".into());
        }
        self.connection
            .query_row("SELECT vault_version FROM credentials WHERE id = ?1", params![id], |row| row.get::<_, i64>(0))
            .map(|version| version as u32)
            .map_err(|error| trouble("rotate this credential", error))
    }

    /// Takes a credential out of use. Nothing is deleted: what was decided about it stays.
    pub fn retire_credential(&self, id: &str, now: i64) -> Result<(), String> {
        let touched = self
            .connection
            .execute("UPDATE credentials SET retired_at = ?2, generation = generation + 1 WHERE id = ?1 AND retired_at IS NULL", params![id, now])
            .map_err(|error| trouble("retire this credential", error))?;
        if touched == 0 {
            return Err("No such credential is in this grid, or it is already retired".into());
        }
        Ok(())
    }

    pub fn put_grant(&self, grant: &Grant) -> Result<(), String> {
        self.connection
            .execute(
                "INSERT INTO credential_grants (id, realm_id, credential_id, principal_id, methods, paths, granted_by, granted_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(credential_id, principal_id) DO UPDATE SET methods = excluded.methods, paths = excluded.paths,
                     granted_by = excluded.granted_by, granted_at = excluded.granted_at, expires_at = excluded.expires_at",
                params![
                    grant.id,
                    grant.realm_id,
                    grant.credential_id,
                    grant.principal_id,
                    json(&grant.methods),
                    json(&grant.paths),
                    grant.granted_by,
                    grant.granted_at,
                    grant.expires_at,
                ],
            )
            .map(|_| ())
            .map_err(|error| trouble("say who may use this credential", error))
    }

    pub fn grants(&self) -> Result<Vec<Grant>, String> {
        let mut query = self.connection.prepare(&format!("{GRANTS} ORDER BY granted_at, id")).map_err(|error| trouble("read who may use this grid's credentials", error))?;
        let rows = query.query_map([], grant_from).map_err(|error| trouble("read who may use this grid's credentials", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read who may use this grid's credentials", error))
    }

    /// What someone may do with one credential, if anything.
    pub fn grant_for(&self, credential_id: &str, principal_id: &str) -> Result<Option<Grant>, String> {
        self.connection
            .query_row(&format!("{GRANTS} WHERE credential_id = ?1 AND principal_id = ?2"), params![credential_id, principal_id], grant_from)
            .optional()
            .map_err(|error| trouble("read who may use this credential", error))
    }

    pub fn take_grant(&self, credential_id: &str, principal_id: &str) -> Result<(), String> {
        self.connection
            .execute("DELETE FROM credential_grants WHERE credential_id = ?1 AND principal_id = ?2", params![credential_id, principal_id])
            .map(|_| ())
            .map_err(|error| trouble("take this credential back", error))
    }

    // ---- Workspace profile ----
    //
    // Images, workspaces, where each one is placed, where its packed-up data waits, who is in it,
    // how its computer was committed and how that computer last said it was. There is no column
    // anywhere below that could hold what is inside a workspace.

    /// Records an image, or replaces what is known about one. The digest is deliberately not
    /// updated here: pinning is its own statement, so that learning what bytes an image has can
    /// never happen by accident in the middle of an ordinary save.
    pub fn put_image(&self, image: &Image) -> Result<(), String> {
        self.connection
            .execute(
                "INSERT INTO workspace_images (id, realm_id, name, version, description, kind, digest, source_kind, source, bytes, shape, applications, published_by, published_at, verified_at, retired_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
                 ON CONFLICT(id) DO UPDATE SET name = excluded.name, version = excluded.version, description = excluded.description,
                     source_kind = excluded.source_kind, source = excluded.source, bytes = excluded.bytes, shape = excluded.shape,
                     applications = excluded.applications, retired_at = excluded.retired_at",
                params![
                    image.id,
                    image.realm_id,
                    image.name,
                    image.version,
                    image.description,
                    word(&image.kind),
                    image.digest,
                    image.source.word(),
                    json(&image.source),
                    image.bytes.map(|bytes| bytes as i64),
                    json(&image.shape),
                    json(&image.applications),
                    image.published_by,
                    image.published_at,
                    image.verified_at,
                    image.retired_at,
                ],
            )
            .map(|_| ())
            .map_err(|error| match error {
                rusqlite::Error::SqliteFailure(failure, _) if failure.code == rusqlite::ErrorCode::ConstraintViolation => {
                    "An image of that name and version, or of those exact bytes, is already in this grid".to_owned()
                }
                other => trouble("record this image", other),
            })
    }

    pub fn image(&self, id: &str) -> Result<Option<Image>, String> {
        self.connection.query_row(&format!("{IMAGES} WHERE id = ?1"), params![id], image_from).optional().map_err(|error| trouble("read this image", error))
    }

    pub fn images(&self) -> Result<Vec<Image>, String> {
        let mut query = self.connection.prepare(&format!("{IMAGES} ORDER BY published_at, id")).map_err(|error| trouble("read this grid's images", error))?;
        let rows = query.query_map([], image_from).map_err(|error| trouble("read this grid's images", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this grid's images", error))
    }

    /// Writes down what an image's bytes hash to, the first time anybody has hashed them, and
    /// records that they were seen again every time after. An image that is already pinned keeps
    /// the digest it has; whether the bytes matched is the caller's question, not this one's.
    pub fn pin_image(&self, id: &str, digest: &str, now: i64) -> Result<(), String> {
        let touched = self
            .connection
            .execute("UPDATE workspace_images SET digest = COALESCE(digest, ?2), verified_at = ?3 WHERE id = ?1", params![id, digest, now])
            .map_err(|error| match error {
                rusqlite::Error::SqliteFailure(failure, _) if failure.code == rusqlite::ErrorCode::ConstraintViolation => {
                    "Another image in this grid is already those exact bytes".to_owned()
                }
                other => trouble("record what this image hashes to", other),
            })?;
        if touched == 0 {
            return Err("No such image is in this grid".into());
        }
        Ok(())
    }

    /// Takes an image out of use. Nothing is deleted, and a workspace built from it keeps the
    /// digest it was built from.
    pub fn retire_image(&self, id: &str, now: i64) -> Result<(), String> {
        let touched = self
            .connection
            .execute("UPDATE workspace_images SET retired_at = ?2 WHERE id = ?1 AND retired_at IS NULL", params![id, now])
            .map_err(|error| trouble("retire this image", error))?;
        if touched == 0 {
            return Err("No such image is in this grid, or it is already retired".into());
        }
        Ok(())
    }

    /// Records a workspace. Every column is written, which is the house style, and the database
    /// refuses the one that must never go backwards.
    pub fn put_workspace(&self, workspace: &Workspace) -> Result<(), String> {
        self.connection
            .execute(
                "INSERT INTO workspaces (id, realm_id, name, owner_id, image_id, image_digest, shape, access, quota, state, note, generation, attempts, reset_count, ordered_by, created_at, updated_at, archived_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
                 ON CONFLICT(id) DO UPDATE SET name = excluded.name, owner_id = excluded.owner_id, image_id = excluded.image_id,
                     image_digest = excluded.image_digest, shape = excluded.shape, access = excluded.access, quota = excluded.quota,
                     state = excluded.state, note = excluded.note, generation = excluded.generation, attempts = excluded.attempts,
                     reset_count = excluded.reset_count, updated_at = excluded.updated_at, archived_at = excluded.archived_at",
                params![
                    workspace.id,
                    workspace.realm_id,
                    workspace.name,
                    workspace.owner_id,
                    workspace.image_id,
                    workspace.image_digest,
                    json(&workspace.shape),
                    word(&workspace.access),
                    json(&workspace.quota),
                    word(&workspace.state),
                    workspace.note,
                    workspace.generation as i64,
                    workspace.attempts as i64,
                    workspace.reset_count as i64,
                    workspace.ordered_by,
                    workspace.created_at,
                    workspace.updated_at,
                    workspace.archived_at,
                ],
            )
            .map(|_| ())
            .map_err(|error| trouble("record this workspace", error))
    }

    pub fn workspace(&self, id: &str) -> Result<Option<Workspace>, String> {
        self.connection.query_row(&format!("{WORKSPACES} WHERE id = ?1"), params![id], workspace_from).optional().map_err(|error| trouble("read this workspace", error))
    }

    pub fn workspaces(&self) -> Result<Vec<Workspace>, String> {
        let mut query = self.connection.prepare(&format!("{WORKSPACES} ORDER BY created_at, id")).map_err(|error| trouble("read this grid's workspaces", error))?;
        let rows = query.query_map([], workspace_from).map_err(|error| trouble("read this grid's workspaces", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this grid's workspaces", error))
    }

    /// Raises a workspace's generation, in a statement of its own, and says what it is now.
    /// One person's own workspaces, which is what their portal reads.
    pub fn workspaces_owned_by(&self, principal_id: &str) -> Result<Vec<Workspace>, String> {
        let mut query = self
            .connection
            .prepare(&format!("{WORKSPACES} WHERE owner_id = ?1 ORDER BY created_at, id"))
            .map_err(|error| trouble("read this person's workspaces", error))?;
        let rows = query.query_map(params![principal_id], workspace_from).map_err(|error| trouble("read this person's workspaces", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this person's workspaces", error))
    }

    /// How many workspaces the realm holds, for the limit that is checked before another is
    /// ordered. A count rather than the rows, because the rows were only ever counted.
    pub fn workspace_count(&self) -> Result<usize, String> {
        self.count("SELECT COUNT(*) FROM workspaces", params![])
    }

    /// How many workspaces are in each of the states an operator acts on.
    pub fn workspace_states(&self, waiting_since: i64) -> Result<(usize, usize, usize, usize), String> {
        self.connection
            .query_row(
                "SELECT (SELECT COUNT(*) FROM workspaces WHERE state = 'failed'),
                        (SELECT COUNT(*) FROM workspaces WHERE state = 'requested' AND updated_at <= ?1),
                        (SELECT COALESCE(SUM(attempts), 0) FROM workspaces),
                        (SELECT COALESCE(SUM(reset_count), 0) FROM workspaces)",
                params![waiting_since],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?.max(0) as usize,
                        row.get::<_, i64>(1)?.max(0) as usize,
                        row.get::<_, i64>(2)?.max(0) as usize,
                        row.get::<_, i64>(3)?.max(0) as usize,
                    ))
                },
            )
            .map_err(|error| trouble("read this grid's workspaces", error))
    }

    /// The highest placement number this workspace has had, which is the one the next placement
    /// follows. The index on (workspace_id, generation DESC) is there for exactly this, and
    /// reading every placement to take the largest never used it.
    pub fn last_placement_number(&self, workspace_id: &str) -> Result<u64, String> {
        self.connection
            .query_row("SELECT COALESCE(MAX(generation), 0) FROM workspace_assignments WHERE workspace_id = ?1", params![workspace_id], |row| row.get::<_, i64>(0))
            .map(|number| number.max(0) as u64)
            .map_err(|error| trouble("read this workspace's placements", error))
    }

    pub fn raise_workspace_generation(&self, id: &str, now: i64) -> Result<u64, String> {
        let touched = self
            .connection
            .execute("UPDATE workspaces SET generation = generation + 1, updated_at = ?2 WHERE id = ?1", params![id, now])
            .map_err(|error| trouble("move this workspace on", error))?;
        if touched == 0 {
            return Err("No such workspace is in this grid".into());
        }
        self.connection
            .query_row("SELECT generation FROM workspaces WHERE id = ?1", params![id], |row| row.get::<_, i64>(0))
            .map(|generation| generation as u64)
            .map_err(|error| trouble("move this workspace on", error))
    }

    /// Removes a workspace, and with it the record of where it has been. The database refuses
    /// this unless the workspace has been archived first, so deleting somebody's desk is always
    /// two deliberate steps; what remains afterwards is the sealed history, which still names the
    /// workspace and everyone who decided anything about it.
    pub fn forget_workspace(&self, id: &str) -> Result<(), String> {
        let change = self.connection.unchecked_transaction().map_err(|error| trouble("begin a change", error))?;
        change.execute("DELETE FROM workspace_sessions WHERE workspace_id = ?1", params![id]).map_err(|error| trouble("forget this workspace", error))?;
        let gone = change.execute("DELETE FROM workspaces WHERE id = ?1", params![id]).map_err(|error| match error {
            rusqlite::Error::SqliteFailure(_, Some(message)) if message.contains("archive this workspace") => "Archive this workspace before forgetting it".to_owned(),
            other => trouble("forget this workspace", other),
        })?;
        if gone == 0 {
            return Err("No such workspace is in this grid".into());
        }
        change.commit().map_err(|error| trouble("finish forgetting this workspace", error))
    }

    /// Writes one placement. Insert only: a placement is a record of an attempt, and the two
    /// things that can happen to it afterwards, being claimed and being given back, are each a
    /// statement of their own.
    pub fn put_assignment(&self, assignment: &Assignment) -> Result<(), String> {
        Store::write_assignment(&self.connection, assignment)
    }

    fn write_assignment(connection: &Connection, assignment: &Assignment) -> Result<(), String> {
        connection
            .execute(
                "INSERT INTO workspace_assignments (id, realm_id, workspace_id, host_id, generation, workspace_gen, workload_id, placement_ref, placed_at, ready_at, released_at, release_reason)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    assignment.id,
                    assignment.realm_id,
                    assignment.workspace_id,
                    assignment.host_id,
                    assignment.generation as i64,
                    assignment.workspace_generation as i64,
                    assignment.workload_id,
                    assignment.placement_ref,
                    assignment.placed_at,
                    assignment.ready_at,
                    assignment.released_at,
                    assignment.release_reason,
                ],
            )
            .map(|_| ())
            .map_err(|error| match error {
                rusqlite::Error::SqliteFailure(_, Some(message)) if message.contains("already used") => {
                    "That placement number has already been used for this workspace".to_owned()
                }
                rusqlite::Error::SqliteFailure(failure, _) if failure.code == rusqlite::ErrorCode::ConstraintViolation => {
                    "This workspace is already placed on a computer".to_owned()
                }
                other => trouble("record this placement", other),
            })
    }

    pub fn assignments(&self) -> Result<Vec<Assignment>, String> {
        let mut query = self
            .connection
            .prepare(&format!("{ASSIGNMENTS} ORDER BY workspace_id, generation"))
            .map_err(|error| trouble("read this grid's placements", error))?;
        let rows = query.query_map([], assignment_from).map_err(|error| trouble("read this grid's placements", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this grid's placements", error))
    }

    /// Every placement this workspace has had, newest last.
    pub fn assignments_of(&self, workspace_id: &str) -> Result<Vec<Assignment>, String> {
        let mut query = self
            .connection
            .prepare(&format!("{ASSIGNMENTS} WHERE workspace_id = ?1 ORDER BY generation"))
            .map_err(|error| trouble("read this workspace's placements", error))?;
        let rows = query.query_map(params![workspace_id], assignment_from).map_err(|error| trouble("read this workspace's placements", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this workspace's placements", error))
    }

    /// Where this workspace is now, if anywhere.
    pub fn live_assignment(&self, workspace_id: &str) -> Result<Option<Assignment>, String> {
        self.connection
            .query_row(&format!("{ASSIGNMENTS} WHERE workspace_id = ?1 AND released_at IS NULL"), params![workspace_id], assignment_from)
            .optional()
            .map_err(|error| trouble("read where this workspace is", error))
    }

    /// The computers that have held this workspace's data, newest first. No table of its own is
    /// needed: the placements already say it.
    pub fn trail_of(&self, workspace_id: &str) -> Result<Vec<String>, String> {
        let mut query = self
            .connection
            .prepare("SELECT host_id, MAX(generation) AS last FROM workspace_assignments WHERE workspace_id = ?1 GROUP BY host_id ORDER BY last DESC")
            .map_err(|error| trouble("read where this workspace has been", error))?;
        let rows = query.query_map(params![workspace_id], |row| row.get::<_, String>(0)).map_err(|error| trouble("read where this workspace has been", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read where this workspace has been", error))
    }

    pub fn release_assignment(&self, id: &str, reason: &str, now: i64) -> Result<(), String> {
        self.connection
            .execute("UPDATE workspace_assignments SET released_at = ?2, release_reason = ?3 WHERE id = ?1 AND released_at IS NULL", params![id, now, clean(reason)])
            .map(|_| ())
            .map_err(|error| trouble("give this placement back", error))
    }

    /// Gives back every live placement on one computer, and says which workspaces were on it.
    pub fn release_assignments_on(&self, host_id: &str, reason: &str, now: i64) -> Result<Vec<String>, String> {
        let mut query = self
            .connection
            .prepare("SELECT workspace_id FROM workspace_assignments WHERE host_id = ?1 AND released_at IS NULL")
            .map_err(|error| trouble("read what this computer holds", error))?;
        let rows = query.query_map(params![host_id], |row| row.get::<_, String>(0)).map_err(|error| trouble("read what this computer holds", error))?;
        let held = rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read what this computer holds", error))?;
        self.connection
            .execute("UPDATE workspace_assignments SET released_at = ?2, release_reason = ?3 WHERE host_id = ?1 AND released_at IS NULL", params![host_id, now, clean(reason)])
            .map_err(|error| trouble("give this computer's placements back", error))?;
        Ok(held)
    }

    /// The write that makes a placement that has been left behind harmless.
    ///
    /// Whatever was read a moment ago is not trusted: this re-checks both numbers and the
    /// computer inside the same statement that writes. No rows changed means the claim was
    /// stale, which the caller refuses and records.
    pub fn claim_placement(&self, claim: &Claim, placement_ref: Option<&str>, ready: bool, now: i64) -> Result<bool, String> {
        let touched = self
            .connection
            .execute(
                "UPDATE workspace_assignments
                    SET placement_ref = COALESCE(?5, placement_ref), ready_at = CASE WHEN ?6 = 1 THEN COALESCE(ready_at, ?7) ELSE ready_at END
                  WHERE workspace_id = ?1 AND host_id = ?2 AND generation = ?3 AND released_at IS NULL
                    AND ?4 = (SELECT generation FROM workspaces WHERE id = ?1)",
                params![claim.workspace_id, claim.host_id, claim.assignment_generation as i64, claim.workspace_generation as i64, placement_ref, ready as i64, now],
            )
            .map_err(|error| trouble("record what this computer said", error))?;
        Ok(touched > 0)
    }

    /// Everything one placement writes, in a single transaction: the piece of work that will
    /// build it, the reservation that work holds on the computer, the placement's own row, and
    /// where the workspace now stands.
    ///
    /// This exists because every other method here commits on its own and writing an audit event
    /// commits again, so a façade that called four of them would leave a workspace placed with no
    /// reservation, or reserved with no placement, if the process stopped in between.
    /// A move carries no new placement: the workspace stays where it is until its data is packed
    /// up, so the transfer's work and reservation are written and the placement is left alone.
    pub fn place_workspace(&self, work: &Workload, lease: &Lease, assignment: Option<&Assignment>, workspace: &Workspace) -> Result<(), String> {
        let change = self.connection.unchecked_transaction().map_err(|error| trouble("begin this placement", error))?;
        Store::write_workload(&change, work)?;
        Store::write_lease(&change, lease)?;
        if let Some(assignment) = assignment {
            Store::write_assignment(&change, assignment)?;
        }
        change
            .execute(
                "UPDATE workspaces SET state = ?2, note = ?3, attempts = ?4, updated_at = ?5 WHERE id = ?1",
                params![workspace.id, word(&workspace.state), workspace.note, workspace.attempts as i64, workspace.updated_at],
            )
            .map_err(|error| trouble("record where this workspace is", error))?;
        change.commit().map_err(|error| trouble("finish this placement", error))
    }

    pub fn put_artifact(&self, artifact: &Artifact) -> Result<(), String> {
        self.connection
            .execute(
                "INSERT INTO workspace_artifacts (id, realm_id, workspace_id, workspace_gen, store, destination, object_key, bytes, sha256, packed_by, packed_at, taken_at, removed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
                 ON CONFLICT(id) DO UPDATE SET taken_at = excluded.taken_at, removed_at = excluded.removed_at",
                params![
                    artifact.id,
                    artifact.realm_id,
                    artifact.workspace_id,
                    artifact.workspace_generation as i64,
                    word(&artifact.store),
                    artifact.destination,
                    artifact.object_key,
                    artifact.bytes as i64,
                    artifact.sha256,
                    artifact.packed_by,
                    artifact.packed_at,
                    artifact.taken_at,
                    artifact.removed_at,
                ],
            )
            .map(|_| ())
            .map_err(|error| trouble("record this packed copy", error))
    }

    pub fn artifacts(&self) -> Result<Vec<Artifact>, String> {
        let mut query = self.connection.prepare(&format!("{ARTIFACTS} ORDER BY packed_at, id")).map_err(|error| trouble("read this grid's packed copies", error))?;
        let rows = query.query_map([], artifact_from).map_err(|error| trouble("read this grid's packed copies", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this grid's packed copies", error))
    }

    /// Packed copies nobody has taken since `before`, oldest first. What `Artifact::stuck` asks,
    /// asked of the index rather than of every packed copy ever written.
    pub fn stuck_artifacts(&self, before: i64) -> Result<Vec<Artifact>, String> {
        let mut query = self
            .connection
            .prepare(&format!("{ARTIFACTS} WHERE taken_at IS NULL AND removed_at IS NULL AND packed_at < ?1 ORDER BY packed_at, id"))
            .map_err(|error| trouble("read this grid's packed copies", error))?;
        let rows = query.query_map(params![before], artifact_from).map_err(|error| trouble("read this grid's packed copies", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this grid's packed copies", error))
    }

    /// How many packed copies nobody has taken since `before`.
    ///
    /// The same question `stuck_artifacts` asks, counted in the database, because a reading wants
    /// the number and not the rows. Nothing deletes from `workspace_artifacts` and a workspace
    /// packed again writes another row, so building every stuck row to take its length was the one
    /// statement in a reading whose cost grew with how much the realm had done.
    pub fn count_stuck_artifacts(&self, before: i64) -> Result<usize, String> {
        self.count("SELECT COUNT(*) FROM workspace_artifacts WHERE taken_at IS NULL AND removed_at IS NULL AND packed_at < ?1", params![before])
    }

    /// The packed copy of this workspace that is still waiting for a computer, if there is one.
    pub fn waiting_artifact(&self, workspace_id: &str) -> Result<Option<Artifact>, String> {
        self.connection
            .query_row(
                &format!("{ARTIFACTS} WHERE workspace_id = ?1 AND taken_at IS NULL AND removed_at IS NULL ORDER BY packed_at DESC"),
                params![workspace_id],
                artifact_from,
            )
            .optional()
            .map_err(|error| trouble("read this workspace's packed copy", error))
    }

    pub fn take_artifact(&self, id: &str, now: i64) -> Result<(), String> {
        let touched = self
            .connection
            .execute("UPDATE workspace_artifacts SET taken_at = ?2 WHERE id = ?1 AND taken_at IS NULL AND removed_at IS NULL", params![id, now])
            .map_err(|error| trouble("hand this packed copy over", error))?;
        if touched == 0 {
            return Err("That packed copy has already been taken or removed".into());
        }
        Ok(())
    }

    /// Marks every packed copy of a workspace as no longer wanted. The bytes themselves are the
    /// hub's or the bucket's to remove; this is the record that nobody is waiting for them.
    pub fn remove_artifacts(&self, workspace_id: &str, now: i64) -> Result<usize, String> {
        self.connection
            .execute("UPDATE workspace_artifacts SET removed_at = ?2 WHERE workspace_id = ?1 AND removed_at IS NULL", params![workspace_id, now])
            .map_err(|error| trouble("let this workspace's packed copies go", error))
    }

    pub fn open_session(&self, session: &Session) -> Result<(), String> {
        self.connection
            .execute(
                "INSERT INTO workspace_sessions (capability_id, realm_id, workspace_id, principal_id, device_id, host_id, workspace_gen, assignment_gen, opened_at, expires_at, ended_at, ended_reason)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    session.capability_id,
                    session.realm_id,
                    session.workspace_id,
                    session.principal_id,
                    session.device_id,
                    session.host_id,
                    session.workspace_generation as i64,
                    session.assignment_generation as i64,
                    session.opened_at,
                    session.expires_at,
                    session.ended_at,
                    session.ended_reason,
                ],
            )
            .map(|_| ())
            .map_err(|error| trouble("open this workspace", error))
    }

    pub fn session(&self, capability_id: &str) -> Result<Option<Session>, String> {
        self.connection
            .query_row(&format!("{SESSIONS} WHERE capability_id = ?1"), params![capability_id], session_from)
            .optional()
            .map_err(|error| trouble("read this sign-in", error))
    }

    pub fn sessions_of(&self, workspace_id: &str) -> Result<Vec<Session>, String> {
        let mut query = self.connection.prepare(&format!("{SESSIONS} WHERE workspace_id = ?1 ORDER BY opened_at")).map_err(|error| trouble("read who is in this workspace", error))?;
        let rows = query.query_map(params![workspace_id], session_from).map_err(|error| trouble("read who is in this workspace", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read who is in this workspace", error))
    }

    /// How many people could still be in this workspace. A sign-in whose permission has simply
    /// run out is not one of them, so an abandoned sign-in cannot lock a one-person desk.
    pub fn live_sessions(&self, workspace_id: &str, now: i64) -> Result<usize, String> {
        self.connection
            .query_row("SELECT COUNT(*) FROM workspace_sessions WHERE workspace_id = ?1 AND ended_at IS NULL AND expires_at > ?2", params![workspace_id, now], |row| {
                row.get::<_, i64>(0)
            })
            .map(|count| count as usize)
            .map_err(|error| trouble("count who is in this workspace", error))
    }

    /// Ends every live sign-in to a workspace and says which permissions were behind them, so
    /// that revoking somebody is a push as well as something noticed at the next use.
    pub fn end_sessions(&self, workspace_id: &str, reason: &str, now: i64) -> Result<Vec<String>, String> {
        let change = self.connection.unchecked_transaction().map_err(|error| trouble("begin a change", error))?;
        let ended = {
            let mut query = change
                .prepare("SELECT capability_id FROM workspace_sessions WHERE workspace_id = ?1 AND ended_at IS NULL")
                .map_err(|error| trouble("read who is in this workspace", error))?;
            let rows = query.query_map(params![workspace_id], |row| row.get::<_, String>(0)).map_err(|error| trouble("read who is in this workspace", error))?;
            rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read who is in this workspace", error))?
        };
        change
            .execute("UPDATE workspace_sessions SET ended_at = ?2, ended_reason = ?3 WHERE workspace_id = ?1 AND ended_at IS NULL", params![workspace_id, now, clean(reason)])
            .map_err(|error| trouble("close these sign-ins", error))?;
        for capability in &ended {
            change
                .execute("UPDATE capabilities SET spent_at = ?2 WHERE id = ?1 AND spent_at IS NULL", params![capability, now])
                .map_err(|error| trouble("close these sign-ins", error))?;
        }
        change.commit().map_err(|error| trouble("finish closing these sign-ins", error))?;
        Ok(ended)
    }

    /// Closes sign-ins whose permission has run out. Nothing is weakened by doing it, because
    /// such a permission is already refused; what it buys is that the count of who is in a
    /// workspace is the truth rather than a high-water mark.
    pub fn end_lapsed_sessions(&self, now: i64) -> Result<usize, String> {
        self.connection
            .execute(
                "UPDATE workspace_sessions SET ended_at = ?1, ended_reason = 'the permission to be here ran out' WHERE ended_at IS NULL AND expires_at <= ?1",
                params![now],
            )
            .map_err(|error| trouble("close the sign-ins that ran out", error))
    }

    /// Records a commitment as it was made. Insert only: the database refuses an edit, so taking
    /// one back is a second record rather than a field overwritten.
    pub fn put_pledge(&self, pledge: &Pledge) -> Result<(), String> {
        self.connection
            .execute(
                "INSERT INTO host_commitments (id, realm_id, host_id, commitment, offered, idle_only, wording, committed_by, committed_at, withdrawn_by, withdrawn_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    pledge.id,
                    pledge.realm_id,
                    pledge.host_id,
                    word(&pledge.commitment),
                    json(&pledge.offered),
                    pledge.idle_only as i64,
                    pledge.wording,
                    pledge.committed_by,
                    pledge.committed_at,
                    pledge.withdrawn_by,
                    pledge.withdrawn_at,
                ],
            )
            .map(|_| ())
            .map_err(|error| trouble("record this commitment", error))
    }

    /// Writes the withdrawal into the record that was made, and nothing else.
    pub fn withdraw_pledge(&self, host_id: &str, by: &str, now: i64) -> Result<usize, String> {
        self.connection
            .execute("UPDATE host_commitments SET withdrawn_by = ?2, withdrawn_at = ?3 WHERE host_id = ?1 AND withdrawn_at IS NULL", params![host_id, by, now])
            .map_err(|error| trouble("take this commitment back", error))
    }

    /// Every commitment a computer has made and withdrawn, newest last.
    pub fn commitments(&self, host_id: &str) -> Result<Vec<Pledge>, String> {
        let mut query = self.connection.prepare(&format!("{PLEDGES} WHERE host_id = ?1 ORDER BY committed_at, id")).map_err(|error| trouble("read what was agreed", error))?;
        let rows = query.query_map(params![host_id], pledge_from).map_err(|error| trouble("read what was agreed", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read what was agreed", error))
    }

    pub fn all_commitments(&self) -> Result<Vec<Pledge>, String> {
        let mut query = self.connection.prepare(&format!("{PLEDGES} ORDER BY committed_at, id")).map_err(|error| trouble("read what was agreed", error))?;
        let rows = query.query_map([], pledge_from).map_err(|error| trouble("read what was agreed", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read what was agreed", error))
    }

    /// The commitment a computer is standing by now, if any.
    pub fn standing_pledge(&self, host_id: &str) -> Result<Option<Pledge>, String> {
        self.connection
            .query_row(&format!("{PLEDGES} WHERE host_id = ?1 AND withdrawn_at IS NULL ORDER BY committed_at DESC"), params![host_id], pledge_from)
            .optional()
            .map_err(|error| trouble("read what this computer agreed to", error))
    }

    /// What every computer is committed to now, by computer. One query for a decision that looks
    /// at every computer, instead of one query per computer.
    pub fn standing_pledges(&self) -> Result<std::collections::HashMap<String, Pledge>, String> {
        let mut query = self
            .connection
            .prepare(&format!("{PLEDGES} WHERE withdrawn_at IS NULL ORDER BY committed_at"))
            .map_err(|error| trouble("read what these computers agreed to", error))?;
        let rows = query.query_map([], pledge_from).map_err(|error| trouble("read what these computers agreed to", error))?;
        let mut held = std::collections::HashMap::new();
        for pledge in rows {
            let pledge = pledge.map_err(|error| trouble("read what these computers agreed to", error))?;
            // Newest last, exactly as standing_pledge takes the newest.
            held.insert(pledge.host_id.clone(), pledge);
        }
        Ok(held)
    }

    /// What every computer last said about itself, by computer.
    pub fn conditions(&self) -> Result<std::collections::HashMap<String, Condition>, String> {
        let mut query = self
            .connection
            .prepare("SELECT host_id, on_battery, free_disk_gb, in_use, going_away, reported_at FROM host_conditions")
            .map_err(|error| trouble("read how these computers are", error))?;
        let rows = query.query_map([], condition_from).map_err(|error| trouble("read how these computers are", error))?;
        let mut said = std::collections::HashMap::new();
        for condition in rows {
            let condition = condition.map_err(|error| trouble("read how these computers are", error))?;
            said.insert(condition.host_id.clone(), condition);
        }
        Ok(said)
    }

    /// Records what a computer last said about itself.
    pub fn put_condition(&self, realm_id: &str, condition: &Condition) -> Result<(), String> {
        self.connection
            .execute(
                "INSERT INTO host_conditions (host_id, realm_id, on_battery, free_disk_gb, in_use, going_away, reported_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(host_id) DO UPDATE SET on_battery = excluded.on_battery, free_disk_gb = excluded.free_disk_gb,
                     in_use = excluded.in_use, going_away = excluded.going_away, reported_at = excluded.reported_at",
                params![condition.host_id, realm_id, condition.on_battery as i64, condition.free_disk_gb, condition.in_use as i64, condition.going_away as i64, condition.reported_at],
            )
            .map(|_| ())
            .map_err(|error| trouble("record how this computer is", error))
    }

    pub fn condition(&self, host_id: &str) -> Result<Option<Condition>, String> {
        self.connection
            .query_row(
                "SELECT host_id, on_battery, free_disk_gb, in_use, going_away, reported_at FROM host_conditions WHERE host_id = ?1",
                params![host_id],
                condition_from,
            )
            .optional()
            .map_err(|error| trouble("read how this computer is", error))
    }

    /// Removes exactly the workspaces and images a bridge brought in, in one change.
    ///
    /// A workspace is archived first and then removed, because the database refuses to forget one
    /// that was not, and undoing an import must not be the one path that goes round that rule. It
    /// refuses outright if anything that arrived later still depends on what is going.
    pub fn forget_imported_workspaces(&self, workspaces: &[String], images: &[String], now: i64) -> Result<(), String> {
        let change = self.connection.unchecked_transaction().map_err(|error| trouble("begin undoing the import", error))?;
        let depends = |error: rusqlite::Error| match error {
            rusqlite::Error::SqliteFailure(failure, _) if failure.code == rusqlite::ErrorCode::ConstraintViolation => {
                "Something in this grid now depends on what the import brought in, so it cannot be undone".to_owned()
            }
            other => trouble("undo the import", other),
        };
        for workspace in workspaces {
            change.execute("DELETE FROM workspace_sessions WHERE workspace_id = ?1", params![workspace]).map_err(depends)?;
            change.execute("DELETE FROM workspace_artifacts WHERE workspace_id = ?1", params![workspace]).map_err(depends)?;
            change.execute("DELETE FROM workspace_assignments WHERE workspace_id = ?1", params![workspace]).map_err(depends)?;
            change
                .execute("UPDATE workspaces SET state = 'archived', archived_at = ?2 WHERE id = ?1", params![workspace, now])
                .map_err(depends)?;
            change.execute("DELETE FROM workspaces WHERE id = ?1", params![workspace]).map_err(depends)?;
        }
        for image in images {
            change.execute("DELETE FROM workspace_images WHERE id = ?1", params![image]).map_err(depends)?;
        }
        change.commit().map_err(|error| trouble("finish undoing the import", error))
    }

    /// Removes a piece of work a bridge brought in. Refused while anything still points at it,
    /// which is the honest answer rather than deleting somebody's reservation along with it.
    pub fn forget_workload(&self, id: &str) -> Result<(), String> {
        self.connection.execute("DELETE FROM workloads WHERE id = ?1", params![id]).map(|_| ()).map_err(|error| match error {
            rusqlite::Error::SqliteFailure(failure, _) if failure.code == rusqlite::ErrorCode::ConstraintViolation => {
                "Something in this grid still depends on that piece of work".to_owned()
            }
            other => trouble("forget this work", other),
        })
    }

    /// Removes exactly the credentials, permissions and requests a bridge brought in, in one
    /// change, in the reverse of the order they arrived.
    ///
    /// A request that somebody has decided is not in the list a bridge hands here: the decision
    /// that goes with it is written once and never withdrawn, which the database itself enforces,
    /// so `compat::access::roll_back` refuses an import that carried one rather than meeting a
    /// refusal half way through taking the realm apart.
    pub fn forget_imported_credentials(&self, grants: &[String], credentials: &[String], requests: &[String]) -> Result<(), String> {
        let change = self.connection.unchecked_transaction().map_err(|error| trouble("begin undoing the import", error))?;
        let depends = |error: rusqlite::Error| match error {
            rusqlite::Error::SqliteFailure(failure, _) if failure.code == rusqlite::ErrorCode::ConstraintViolation => {
                "Something in this grid now depends on what the import brought in, so it cannot be undone".to_owned()
            }
            other => trouble("undo the import", other),
        };
        for grant in grants {
            change.execute("DELETE FROM credential_grants WHERE id = ?1", params![grant]).map_err(depends)?;
        }
        for credential in credentials {
            change.execute("DELETE FROM credential_destinations WHERE credential_id = ?1", params![credential]).map_err(depends)?;
            change.execute("DELETE FROM credentials WHERE id = ?1", params![credential]).map_err(depends)?;
        }
        for request in requests {
            change.execute("DELETE FROM requests WHERE id = ?1", params![request]).map_err(depends)?;
        }
        change.commit().map_err(|error| trouble("finish undoing the import", error))
    }

    /// Removes one commitment a bridge wrote, by name, so undoing an import takes off exactly the
    /// agreements it put on and leaves alone any the computer already had.
    pub fn forget_commitment(&self, id: &str) -> Result<(), String> {
        self.connection
            .execute("DELETE FROM host_commitments WHERE id = ?1", params![id])
            .map(|_| ())
            .map_err(|error| trouble("forget what this computer agreed to", error))
    }

    // ---- The history ----

    /// Which key seals this realm's history, and which version of it.
    pub fn chain_key(&self) -> Result<KeyReference, String> {
        self.connection
            .query_row("SELECT key_id, key_version FROM audit_chain LIMIT 1", [], |row| Ok(KeyReference { id: row.get(0)?, version: row.get::<_, i64>(1)? as u32 }))
            .map_err(|error| trouble("read which key seals this history", error))
    }

    /// Where the chain has got to: the last sequence number and the seal over it.
    pub fn head(&self) -> Result<(u64, String), String> {
        self.connection
            .query_row("SELECT head_sequence, head_seal FROM audit_chain LIMIT 1", [], |row| Ok((row.get::<_, i64>(0)? as u64, row.get::<_, String>(1)?)))
            .map_err(|error| trouble("read where this history has got to", error))
    }

    /// Adds one event, sealed with the realm's key over its own fields and the seal before it.
    /// The event and the new head move together, so the chain never points at nothing.
    pub fn append_event(&self, entry: Entry, at: i64, key: &str) -> Result<Event, String> {
        self.append_events(vec![entry], at, key)?.pop().ok_or_else(|| "The event was not written".to_owned())
    }

    /// Several events in one transaction, each sealed over the one before it.
    ///
    /// This is `chain_onto` with a change of its own around it, so a caller with nothing else to
    /// write does not have to begin one. What it does not do is own the chaining: that is in
    /// `chain_onto`, in one place, because `settle_intent` has to seal events into a change it
    /// began itself and cannot call this.
    pub fn append_events(&self, entries: Vec<Entry>, at: i64, key: &str) -> Result<Vec<Event>, String> {
        if entries.is_empty() {
            return Ok(Vec::new());
        }
        let change = self.connection.unchecked_transaction().map_err(|error| trouble("begin a change", error))?;
        let written = Store::chain_onto(&change, entries, at, key)?;
        change.commit().map_err(|error| trouble("finish recording what happened", error))?;
        // How long the chain is, without counting it. `sequence` is the table's own row
        // identifier, so the smallest one is a single seek, and the largest is the head that was
        // just written. A `SELECT COUNT(*)` here ran on every audited action in the realm, which
        // is every door in the core, and it was a whole scan of the history each time.
        if let Some(last) = written.last() {
            let oldest: i64 = self
                .connection
                .query_row("SELECT COALESCE(MIN(sequence), 0) FROM audit_events", [], |row| row.get(0))
                .map_err(|error| trouble("read this history", error))?;
            if oldest > 0 && last.sequence as i64 - oldest + 1 > KEEP as i64 {
                self.trim()?;
            }
        }
        Ok(written)
    }

    /// Seals `entries` onto the end of the chain inside a change somebody else began, and moves
    /// the head to the last of them.
    ///
    /// It does not begin a change, commit one or trim, because the caller owns the change. That is
    /// why it is separate: one account of one thing has to land whole, so `settle_intent` puts a
    /// connector task's ending and the notes the connector kept in one change, and SQLite will not
    /// nest a change inside a change. This is the only account anywhere of how a seal carries
    /// forward. Two copies of it would drift, and a run of events sealed the old way by one of
    /// them is a run `Chain::verify` then refuses.
    fn chain_onto(change: &rusqlite::Connection, entries: Vec<Entry>, at: i64, key: &str) -> Result<Vec<Event>, String> {
        let (head, mut previous_seal): (i64, String) = change
            .query_row("SELECT head_sequence, head_seal FROM audit_chain LIMIT 1", [], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|error| trouble("read where this history has got to", error))?;
        let mut written = Vec::with_capacity(entries.len());
        for (step, entry) in entries.into_iter().enumerate() {
            let event = Event::sealed(entry, (head + 1 + step as i64) as u64, at, previous_seal, key);
            change
                .execute(
                    "INSERT INTO audit_events (sequence, id, realm_id, at, capability, principal_id, device_id, workload_id, action, resource_id, policy_version, decision, reason, command, previous_seal, seal)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
                    params![
                        event.sequence as i64,
                        event.id,
                        event.realm_id,
                        event.at,
                        event.capability.map(|capability| word(&capability)),
                        event.principal_id,
                        event.device_id,
                        event.workload_id,
                        event.action,
                        event.resource_id,
                        event.policy_version as i64,
                        word(&event.decision),
                        event.reason,
                        event.command,
                        event.previous_seal,
                        event.seal,
                    ],
                )
                .map_err(|error| trouble("record what happened", error))?;
            previous_seal = event.seal.clone();
            written.push(event);
        }
        if let Some(last) = written.last() {
            change
                .execute("UPDATE audit_chain SET head_sequence = ?1, head_seal = ?2, updated_at = ?3", params![last.sequence as i64, last.seal, at])
                .map_err(|error| trouble("record what happened", error))?;
        }
        Ok(written)
    }

    /// Drops the oldest events once there are more than the chain keeps, and only as far as they
    /// have been exported. An unexported event is never dropped; the database itself refuses.
    ///
    /// Public because upkeep calls it on its own schedule. It is still called from the write path,
    /// but only when the cheap length check in `append_events` says the chain is over `KEEP`, and
    /// even then it reads the export marker and the oldest sequence before it counts anything, so
    /// the ordinary audited action pays a few index seeks rather than a scan of the whole history.
    /// That holds for a realm that never exports too, which is the realm it matters for: nothing
    /// is ever dropped there, so the oldest sequence never moves and the length check above is
    /// true for ever once the chain passes `KEEP`.
    pub fn trim(&self) -> Result<usize, String> {
        // The marker first, because nothing past it is droppable whatever the length is, and
        // reading it is one seek against a count that walks the whole history.
        let exported: i64 = self.connection.query_row("SELECT exported_to FROM audit_chain LIMIT 1", [], |row| row.get(0)).map_err(|error| trouble("read this history", error))?;
        let oldest: i64 = self
            .connection
            .query_row("SELECT COALESCE(MIN(sequence), 0) FROM audit_events", [], |row| row.get(0))
            .map_err(|error| trouble("read this history", error))?;
        // `exported < oldest` is the realm that never exported, where the marker is nought, and
        // also the realm that exported once and stopped, where the marker sits behind everything
        // still held. An empty history is `oldest = 0` and falls out here too.
        if oldest == 0 || exported < oldest {
            return Ok(0);
        }
        // How far to drop is a sequence number, so it has to be worked out from one. Taking it
        // from a row count was right only while the oldest held event was sequence one, which is
        // true of the first trim and of no trim after it: once the front has gone, the count is
        // far below the sequences still held, nothing matches, and the history grows for ever.
        // The head is one seek on the primary key, the same cost the count was meant to avoid.
        let head: i64 = self
            .connection
            .query_row("SELECT COALESCE(MAX(sequence), 0) FROM audit_events", [], |row| row.get(0))
            .map_err(|error| trouble("read this history", error))?;
        // Everything at or below this may go, as far as the marker allows. Nothing is held but a
        // run of sequences, because only the front is ever dropped, so `head - oldest + 1` is what
        // the chain holds and this is below `oldest` exactly when it holds `KEEP` or fewer.
        let drop_to = (head - KEEP as i64).min(exported);
        if drop_to < oldest {
            return Ok(0);
        }
        self.connection.execute("DELETE FROM audit_events WHERE sequence <= ?1", params![drop_to]).map_err(|error| trouble("tidy this history", error))
    }

    /// How many events the history holds, how far back it reaches, and how many of them have not
    /// been carried off this computer yet.
    ///
    /// The third number is the one that matters operationally: `trim` drops nothing past the
    /// export marker, so a realm nobody exports from grows for ever, and this is what says so
    /// before the file does.
    ///
    /// The length is arithmetic on the ends of the chain rather than a `COUNT(*)`, because this is
    /// on the readiness path and a count with no `WHERE` walks the whole b-tree. `sequence` is the
    /// table's own row identifier, so the smallest and the largest are one descent each.
    /// Sequences are dense: `chain_onto` writes them one after another and `trim` only ever drops
    /// a prefix, so the span is the number of rows. What that does not survive is somebody
    /// reaching into the file with another tool and taking an event out of the middle, where this
    /// reports the span the chain claims rather than the rows left; `verify_audit` is what finds
    /// that, and it is the thing to run when this number looks wrong.
    pub fn history_shape(&self) -> Result<(usize, i64, usize), String> {
        self.connection
            .query_row(
                "SELECT (SELECT COALESCE(MIN(sequence), 0) FROM audit_events),
                        (SELECT COALESCE(MAX(sequence), 0) FROM audit_events),
                        (SELECT COALESCE(MIN(at), 0) FROM audit_events),
                        (SELECT head_sequence FROM audit_chain LIMIT 1),
                        (SELECT exported_to FROM audit_chain LIMIT 1)",
                [],
                |row| {
                    let oldest = row.get::<_, i64>(0)?;
                    let newest = row.get::<_, i64>(1)?;
                    let held = if oldest == 0 { 0 } else { (newest - oldest + 1).max(0) as usize };
                    let reaches = row.get::<_, i64>(2)?;
                    let waiting = (row.get::<_, i64>(3)? - row.get::<_, i64>(4)?).max(0) as usize;
                    Ok((held, reaches, waiting))
                },
            )
            .map_err(|error| trouble("read this grid's history", error))
    }

    /// How many events since `since` named this capability and were refused. The credential
    /// failure count comes from the chain rather than from a counter, because the chain is what
    /// the realm actually wrote down.
    pub fn refusals_since(&self, capability: Capability, since: i64) -> Result<usize, String> {
        self.count("SELECT COUNT(*) FROM audit_events WHERE at > ?1 AND capability = ?2 AND decision = 'refused'", params![since, word(&capability)])
    }

    /// How far this history has been carried off this computer. Everything after it is still only
    /// here, and `trim` will not drop any of it.
    pub fn exported_to(&self) -> Result<u64, String> {
        self.connection
            .query_row("SELECT exported_to FROM audit_chain LIMIT 1", [], |row| row.get::<_, i64>(0))
            .map(|sequence| sequence.max(0) as u64)
            .map_err(|error| trouble("read how far this history has been carried out", error))
    }

    /// Marks everything up to `sequence` as exported somewhere this computer cannot reach.
    pub fn exported(&self, sequence: u64) -> Result<(), String> {
        self.connection
            .execute("UPDATE audit_chain SET exported_to = MAX(exported_to, ?1)", params![sequence as i64])
            .map(|_| ())
            .map_err(|error| trouble("record the export", error))
    }

    pub fn chain(&self) -> Result<Chain, String> {
        let mut query = self
            .connection
            .prepare(
                "SELECT sequence, id, realm_id, at, capability, principal_id, device_id, workload_id, action, resource_id, policy_version, decision, reason, command, previous_seal, seal
                 FROM audit_events ORDER BY sequence",
            )
            .map_err(|error| trouble("read this grid's history", error))?;
        let rows = query.query_map([], event_from).map_err(|error| trouble("read this grid's history", error))?;
        Ok(Chain { events: rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this grid's history", error))? })
    }

    /// Which events one typed command caused, by sequence, in the order they were written.
    pub fn events_for_command(&self, command: &str) -> Result<Vec<u64>, String> {
        let mut query = self
            .connection
            .prepare("SELECT sequence FROM audit_events WHERE command = ?1 ORDER BY sequence")
            .map_err(|error| trouble("read this grid's history", error))?;
        let rows = query
            .query_map(params![command], |row| row.get::<_, i64>(0))
            .map_err(|error| trouble("read this grid's history", error))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this grid's history", error))?.into_iter().map(|sequence| sequence as u64).collect())
    }

    /// The events after `sequence`, for exporting.
    pub fn events_since(&self, sequence: u64) -> Result<Vec<Event>, String> {
        let mut query = self
            .connection
            .prepare(
                "SELECT sequence, id, realm_id, at, capability, principal_id, device_id, workload_id, action, resource_id, policy_version, decision, reason, command, previous_seal, seal
                 FROM audit_events WHERE sequence > ?1 ORDER BY sequence",
            )
            .map_err(|error| trouble("read this grid's history", error))?;
        let rows = query.query_map(params![sequence as i64], event_from).map_err(|error| trouble("read this grid's history", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this grid's history", error))
    }

    /// One event by its sequence, which is the table's own row identifier and therefore one
    /// descent. For checking a bundle an operator carried out against the history this realm
    /// actually holds.
    pub fn event_at(&self, sequence: u64) -> Result<Option<Event>, String> {
        let mut query = self
            .connection
            .prepare(
                "SELECT sequence, id, realm_id, at, capability, principal_id, device_id, workload_id, action, resource_id, policy_version, decision, reason, command, previous_seal, seal
                 FROM audit_events WHERE sequence = ?1",
            )
            .map_err(|error| trouble("read this grid's history", error))?;
        let mut rows = query.query_map(params![sequence as i64], event_from).map_err(|error| trouble("read this grid's history", error))?;
        rows.next().transpose().map_err(|error| trouble("read this grid's history", error))
    }

    // ---- What a connector was asked to do, and what a realm demands of a computer ----

    /// What this realm demands a computer shows before work is placed on it.
    pub fn demands_trust(&self) -> Result<Trust, String> {
        let word: String = self.connection.query_row("SELECT demands_trust FROM realms LIMIT 1", [], |row| row.get(0)).map_err(|error| trouble("read what this grid demands of a computer", error))?;
        Trust::parse(&word).ok_or_else(|| format!("This grid demands '{word}', which is not something a computer can show"))
    }

    pub fn set_demands_trust(&self, wanted: Trust) -> Result<(), String> {
        self.connection
            .execute("UPDATE realms SET demands_trust = ?1", params![wanted.word()])
            .map(|_| ())
            .map_err(|error| trouble("change what this grid demands of a computer", error))
    }

    /// Writes down what a connector is about to be asked to do, before it is asked.
    ///
    /// The identifying columns are never written again: the trigger in version 8 refuses it. What
    /// may be written later is how it ended, which is what `settle_intent` does.
    pub fn open_intent(&self, intent: &Intent) -> Result<(), String> {
        self.connection
            .execute(
                "INSERT INTO connector_intents (id, realm_id, connector, credential_id, destination, change, subject_email, subject_name, target, fingerprint, principal_id, device_id, workload_id, state, attempts, policy_version, opened_at, settled_at, note)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, NULL, '')",
                params![
                    intent.id,
                    intent.realm_id,
                    intent.connector,
                    intent.credential_id,
                    intent.destination,
                    change_word(intent.change),
                    intent.subject_email,
                    intent.subject_name,
                    intent.target,
                    intent.fingerprint,
                    intent.principal_id,
                    intent.device_id,
                    intent.workload_id,
                    intent.state.word(),
                    intent.attempts as i64,
                    intent.policy_version as i64,
                    intent.opened_at,
                ],
            )
            .map(|_| ())
            .map_err(|error| match error {
                rusqlite::Error::SqliteFailure(_, Some(ref said)) if said.contains("connector_intents.credential_id") => {
                    "This grid is already in the middle of making that same change for that person with that credential. Wait for it to finish rather than asking twice.".to_owned()
                }
                other => trouble("write down what this connector is about to be asked to do", other),
            })
    }

    /// Records how a connector task ended, in the same transaction as the account of it.
    ///
    /// The state machine is checked here and again by the database: this refuses a move the state
    /// machine does not allow, and the triggers refuse a settled row being reopened whatever any
    /// code thinks. The events go in the same transaction, so an account of one task lands whole
    /// or not at all.
    pub fn settle_intent(&self, id: &str, state: IntentState, note: &str, entries: Vec<Entry>, at: i64, key: &str) -> Result<(Intent, Vec<Event>), String> {
        let change = self.connection.unchecked_transaction().map_err(|error| trouble("begin a change", error))?;
        let (said, attempts): (String, i64) = change
            .query_row("SELECT state, attempts FROM connector_intents WHERE id = ?1", params![id], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => "No connector task with that name is in this grid".to_owned(),
                other => trouble("read this connector task", other),
            })?;
        let was = IntentState::parse(&said).ok_or_else(|| format!("This connector task says it is '{said}', which is not a state"))?;
        if !was.may_become(state) {
            return Err(format!("A connector task that is {} cannot become {}", was.describe(), state.describe()));
        }
        let note: String = note.chars().filter(|letter| !letter.is_control()).take(500).collect();
        change
            .execute(
                "UPDATE connector_intents SET state = ?2, attempts = ?3, settled_at = ?4, note = ?5 WHERE id = ?1",
                params![id, state.word(), attempts + 1, if state.settled() { Some(at) } else { None }, note],
            )
            .map_err(|error| trouble("record how this connector task ended", error))?;
        // The same chaining `append_events` uses, inside the change begun above, so a connector
        // task's ending and the notes kept about it land together or not at all.
        let written = Store::chain_onto(&change, entries, at, key)?;
        change.commit().map_err(|error| trouble("finish recording how this connector task ended", error))?;
        self.trim()?;
        Ok((self.intent(id)?.ok_or("The connector task was not written")?, written))
    }

    pub fn intent(&self, id: &str) -> Result<Option<Intent>, String> {
        Ok(self.intents_where("WHERE id = ?1", params![id])?.into_iter().next())
    }

    /// Every task that may have left a provider out of step with this realm, oldest first.
    pub fn unsettled_intents(&self) -> Result<Vec<Intent>, String> {
        self.intents_where("WHERE state IN ('opened','done','orphaned','stuck') ORDER BY opened_at, id", [])
    }

    /// Every connector task this realm has recorded, newest first, for showing somebody.
    pub fn intents(&self) -> Result<Vec<Intent>, String> {
        self.intents_where("ORDER BY opened_at DESC, id", [])
    }

    fn intents_where(&self, tail: &str, binding: impl rusqlite::Params) -> Result<Vec<Intent>, String> {
        let mut query = self
            .connection
            .prepare(&format!(
                "SELECT id, realm_id, connector, credential_id, destination, change, subject_email, subject_name, target, fingerprint, principal_id, device_id, workload_id, state, attempts, policy_version, opened_at, settled_at, note
                 FROM connector_intents {tail}"
            ))
            .map_err(|error| trouble("read this grid's connector tasks", error))?;
        let rows = query
            .query_map(binding, |row| {
                let word: String = row.get(5)?;
                let state: String = row.get(13)?;
                Ok(Intent {
                    id: row.get(0)?,
                    realm_id: row.get(1)?,
                    connector: row.get(2)?,
                    credential_id: row.get(3)?,
                    destination: row.get(4)?,
                    change: change_from(&word).ok_or_else(|| rusqlite::Error::InvalidColumnName(format!("'{word}' is not a direction a connector task can go")))?,
                    subject_email: row.get(6)?,
                    subject_name: row.get(7)?,
                    target: row.get(8)?,
                    fingerprint: row.get(9)?,
                    principal_id: row.get(10)?,
                    device_id: row.get(11)?,
                    workload_id: row.get(12)?,
                    state: IntentState::parse(&state).ok_or_else(|| rusqlite::Error::InvalidColumnName(format!("'{state}' is not a state a connector task can be in")))?,
                    attempts: row.get::<_, i64>(14)? as u32,
                    policy_version: row.get::<_, i64>(15)? as u64,
                    opened_at: row.get(16)?,
                    settled_at: row.get(17)?,
                    note: row.get(18)?,
                })
            })
            .map_err(|error| trouble("read this grid's connector tasks", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this grid's connector tasks", error))
    }

    // ---- The research profile ----
    //
    // Every one of these only ever reads or writes in a research realm, except the two about
    // imports, which only ever do so in a company realm. That is not a convention this code
    // holds: version 6 puts a trigger in front of each table saying the same thing, so a row
    // written with another tool is refused too.

    /// Writes a scope, or the editable half of a draft one. A frozen scope is refused by the
    /// database rather than by a rule here, and a generation that tried to go backwards with it.
    pub fn put_scope(&self, scope: &super::research::Scope) -> Result<(), String> {
        self.connection
            .execute(
                "INSERT INTO research_scopes (id, realm_id, name, purpose, authorisation, authorisation_digest, authorisation_approval_id, classification, limits, version, supersedes, digest, generation, created_by, created_at, frozen_at, closed_at, closed_reason)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
                 ON CONFLICT(id) DO UPDATE SET name = excluded.name, purpose = excluded.purpose, authorisation = excluded.authorisation,
                     authorisation_digest = excluded.authorisation_digest, authorisation_approval_id = excluded.authorisation_approval_id,
                     classification = excluded.classification, limits = excluded.limits, digest = excluded.digest,
                     frozen_at = excluded.frozen_at, closed_at = excluded.closed_at, closed_reason = excluded.closed_reason",
                params![
                    scope.id,
                    scope.realm_id,
                    scope.name,
                    scope.purpose,
                    scope.authorisation,
                    scope.authorisation_digest,
                    scope.authorisation_approval_id,
                    word(&scope.classification),
                    json(&scope.limits),
                    scope.version as i64,
                    scope.supersedes,
                    scope.digest,
                    scope.generation as i64,
                    scope.created_by,
                    scope.created_at,
                    scope.frozen_at,
                    scope.closed_at,
                    scope.closed_reason,
                ],
            )
            .map(|_| ())
            .map_err(|error| match error {
                rusqlite::Error::SqliteFailure(_, Some(message)) if message.contains("frozen scope") => "A frozen scope is replaced by a new version, never edited".to_owned(),
                rusqlite::Error::SqliteFailure(_, Some(message)) if message.contains("research grid of its own") => "Research belongs in a research grid of its own".to_owned(),
                other => trouble("record this research scope", other),
            })
    }

    pub fn scope(&self, id: &str) -> Result<Option<super::research::Scope>, String> {
        self.connection.query_row(&format!("{SCOPES} WHERE id = ?1"), params![id], scope_from).optional().map_err(|error| trouble("read this research scope", error))
    }

    pub fn scopes(&self) -> Result<Vec<super::research::Scope>, String> {
        let mut query = self.connection.prepare(&format!("{SCOPES} ORDER BY created_at, id")).map_err(|error| trouble("read this grid's research scopes", error))?;
        let rows = query.query_map([], scope_from).map_err(|error| trouble("read this grid's research scopes", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this grid's research scopes", error))
    }

    /// Closes a scope. Nothing is deleted; what changes is that no more work goes under it.
    /// How many scopes this realm holds, for the limit that is checked before another is written.
    pub fn scope_count(&self) -> Result<usize, String> {
        self.count("SELECT COUNT(*) FROM research_scopes", params![])
    }

    pub fn close_scope(&self, id: &str, reason: &str, now: i64) -> Result<(), String> {
        self.connection
            .execute("UPDATE research_scopes SET closed_at = COALESCE(closed_at, ?2), closed_reason = ?3 WHERE id = ?1", params![id, now, clean(reason)])
            .map(|_| ())
            .map_err(|error| trouble("close this research scope", error))
    }

    /// Raises a scope's generation, which is what makes withdrawing something bite at the moment a
    /// permission is next used. The trigger refuses a number that went backwards.
    pub fn raise_scope_generation(&self, id: &str, now: i64) -> Result<u64, String> {
        let _ = now;
        let touched = self
            .connection
            .execute("UPDATE research_scopes SET generation = generation + 1 WHERE id = ?1", params![id])
            .map_err(|error| trouble("move this research scope on", error))?;
        if touched == 0 {
            return Err("No such research scope is in this grid".into());
        }
        self.connection
            .query_row("SELECT generation FROM research_scopes WHERE id = ?1", params![id], |row| row.get::<_, i64>(0))
            .map(|generation| generation as u64)
            .map_err(|error| trouble("move this research scope on", error))
    }

    /// Writes one admission. Insert only: withdrawing one is a statement of its own, and the
    /// agreement it names is unique, so one decision lets in exactly one thing.
    pub fn put_admission(&self, admitted: &super::research::Admitted) -> Result<(), String> {
        self.connection
            .execute(
                "INSERT INTO research_admissions (id, realm_id, scope_id, kind, subject, method, path, approval_id, admitted_by, admitted_at, expires_at, withdrawn_at, withdrawn_reason)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    admitted.id,
                    admitted.realm_id,
                    admitted.scope_id,
                    word(&admitted.kind),
                    admitted.subject,
                    admitted.method,
                    admitted.path,
                    admitted.approval_id,
                    admitted.admitted_by,
                    admitted.admitted_at,
                    admitted.expires_at,
                    admitted.withdrawn_at,
                    admitted.withdrawn_reason,
                ],
            )
            .map(|_| ())
            .map_err(|error| match error {
                rusqlite::Error::SqliteFailure(_, Some(message)) if message.contains("research_admissions.approval_id") => "That agreement has already let something in".to_owned(),
                rusqlite::Error::SqliteFailure(_, Some(message)) if message.contains("research_admissions_live") => "That is already let into this scope".to_owned(),
                rusqlite::Error::SqliteFailure(_, Some(message)) if message.contains("research grid of its own") => "Research belongs in a research grid of its own".to_owned(),
                other => trouble("let this into the research scope", other),
            })
    }

    pub fn admission(&self, id: &str) -> Result<Option<super::research::Admitted>, String> {
        self.connection.query_row(&format!("{ADMISSIONS} WHERE id = ?1"), params![id], admission_from).optional().map_err(|error| trouble("read this admission", error))
    }

    pub fn admissions(&self, scope_id: &str) -> Result<Vec<super::research::Admitted>, String> {
        let mut query = self.connection.prepare(&format!("{ADMISSIONS} WHERE scope_id = ?1 ORDER BY admitted_at, id")).map_err(|error| trouble("read what was let in", error))?;
        let rows = query.query_map(params![scope_id], admission_from).map_err(|error| trouble("read what was let in", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read what was let in", error))
    }

    /// Every admission in the realm, for a backup and for the admin view.
    pub fn all_admissions(&self) -> Result<Vec<super::research::Admitted>, String> {
        let mut query = self.connection.prepare(&format!("{ADMISSIONS} ORDER BY admitted_at, id")).map_err(|error| trouble("read what was let in", error))?;
        let rows = query.query_map([], admission_from).map_err(|error| trouble("read what was let in", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read what was let in", error))
    }

    pub fn withdraw_admission(&self, id: &str, reason: &str, now: i64) -> Result<(), String> {
        let touched = self
            .connection
            .execute("UPDATE research_admissions SET withdrawn_at = ?2, withdrawn_reason = ?3 WHERE id = ?1 AND withdrawn_at IS NULL", params![id, now, clean(reason)])
            .map_err(|error| trouble("take this back out of the research scope", error))?;
        if touched == 0 {
            return Err("That was already taken back out, or is not in this grid".into());
        }
        Ok(())
    }

    /// Writes a source and its manifest in one change, so a source never exists with no manifest.
    pub fn put_source(&self, source: &super::research::Source, files: &[super::research::SourceFile]) -> Result<(), String> {
        let change = self.connection.unchecked_transaction().map_err(|error| trouble("begin a change", error))?;
        change
            .execute(
                "INSERT INTO research_sources (id, realm_id, scope_id, admission_id, origin, reference, revision, digest, bytes, file_count, retain_until, acquired_by, acquired_at, verified_at, quarantined_at, disposed_at, reason)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
                params![
                    source.id,
                    source.realm_id,
                    source.scope_id,
                    source.admission_id,
                    word(&source.origin),
                    source.reference,
                    source.revision,
                    source.digest,
                    source.bytes as i64,
                    source.file_count as i64,
                    source.retain_until,
                    source.acquired_by,
                    source.acquired_at,
                    source.verified_at,
                    source.quarantined_at,
                    source.disposed_at,
                    source.reason,
                ],
            )
            .map_err(|error| match error {
                rusqlite::Error::SqliteFailure(_, Some(message)) if message.contains("research_sources.scope_id") => "This scope already holds exactly these files".to_owned(),
                rusqlite::Error::SqliteFailure(_, Some(message)) if message.contains("research grid of its own") => "Research belongs in a research grid of its own".to_owned(),
                other => trouble("record this source", other),
            })?;
        for file in files {
            change
                .execute(
                    "INSERT INTO research_source_files (source_id, path, sha256, bytes) VALUES (?1, ?2, ?3, ?4)",
                    params![source.id, file.path, file.sha256, file.bytes as i64],
                )
                .map_err(|error| trouble("record this source's files", error))?;
        }
        change.commit().map_err(|error| trouble("finish recording this source", error))
    }

    pub fn source(&self, id: &str) -> Result<Option<super::research::Source>, String> {
        self.connection.query_row(&format!("{SOURCES} WHERE id = ?1"), params![id], source_from).optional().map_err(|error| trouble("read this source", error))
    }

    pub fn sources(&self, scope_id: &str) -> Result<Vec<super::research::Source>, String> {
        let mut query = self.connection.prepare(&format!("{SOURCES} WHERE scope_id = ?1 ORDER BY acquired_at, id")).map_err(|error| trouble("read this scope's sources", error))?;
        let rows = query.query_map(params![scope_id], source_from).map_err(|error| trouble("read this scope's sources", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this scope's sources", error))
    }

    pub fn all_sources(&self) -> Result<Vec<super::research::Source>, String> {
        let mut query = self.connection.prepare(&format!("{SOURCES} ORDER BY acquired_at, id")).map_err(|error| trouble("read this grid's sources", error))?;
        let rows = query.query_map([], source_from).map_err(|error| trouble("read this grid's sources", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this grid's sources", error))
    }

    pub fn source_files(&self, source_id: &str) -> Result<Vec<super::research::SourceFile>, String> {
        let mut query = self
            .connection
            .prepare("SELECT path, sha256, bytes FROM research_source_files WHERE source_id = ?1 ORDER BY path")
            .map_err(|error| trouble("read this source's files", error))?;
        let rows = query
            .query_map(params![source_id], |row| {
                Ok(super::research::SourceFile { path: row.get(0)?, sha256: row.get(1)?, bytes: row.get::<_, i64>(2)? as u64 })
            })
            .map_err(|error| trouble("read this source's files", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this source's files", error))
    }

    /// Every manifest in the realm, as pairs, so a backup carries them with their sources.
    pub fn all_source_files(&self) -> Result<Vec<(String, super::research::SourceFile)>, String> {
        let mut query = self
            .connection
            .prepare("SELECT source_id, path, sha256, bytes FROM research_source_files ORDER BY source_id, path")
            .map_err(|error| trouble("read this grid's manifests", error))?;
        let rows = query
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, super::research::SourceFile { path: row.get(1)?, sha256: row.get(2)?, bytes: row.get::<_, i64>(3)? as u64 }))
            })
            .map_err(|error| trouble("read this grid's manifests", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this grid's manifests", error))
    }

    pub fn verified_source(&self, id: &str, now: i64) -> Result<(), String> {
        self.connection
            .execute("UPDATE research_sources SET verified_at = ?2 WHERE id = ?1", params![id, now])
            .map(|_| ())
            .map_err(|error| trouble("record that this source was checked", error))
    }

    pub fn quarantine_source(&self, id: &str, reason: &str, now: i64) -> Result<(), String> {
        self.connection
            .execute("UPDATE research_sources SET quarantined_at = COALESCE(quarantined_at, ?2), reason = ?3 WHERE id = ?1", params![id, now, clean(reason)])
            .map(|_| ())
            .map_err(|error| trouble("take this source out of use", error))
    }

    pub fn dispose_source(&self, id: &str, reason: &str, now: i64) -> Result<(), String> {
        self.connection
            .execute("UPDATE research_sources SET disposed_at = COALESCE(disposed_at, ?2), reason = ?3 WHERE id = ?1", params![id, now, clean(reason)])
            .map(|_| ())
            .map_err(|error| trouble("let go of this source", error))
    }

    /// Writes what a source depends on, replacing what was written for the same package before.
    pub fn put_dependencies(&self, packages: &[super::research::Package]) -> Result<(), String> {
        let change = self.connection.unchecked_transaction().map_err(|error| trouble("begin a change", error))?;
        for package in packages {
            change
                .execute(
                    "INSERT INTO research_dependencies (id, source_id, ecosystem, name, version, expected, seen, state, checked_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                     ON CONFLICT(source_id, ecosystem, name, version) DO UPDATE SET expected = excluded.expected, seen = excluded.seen,
                         state = excluded.state, checked_at = excluded.checked_at",
                    params![
                        package.id,
                        package.source_id,
                        package.ecosystem,
                        package.name,
                        package.version,
                        package.expected,
                        package.seen,
                        word(&package.state),
                        package.checked_at,
                    ],
                )
                .map_err(|error| trouble("record what this source depends on", error))?;
        }
        change.commit().map_err(|error| trouble("finish recording what this source depends on", error))
    }

    pub fn dependencies(&self, source_id: &str) -> Result<Vec<super::research::Package>, String> {
        let mut query = self.connection.prepare(&format!("{PACKAGES} WHERE source_id = ?1 ORDER BY ecosystem, name, version")).map_err(|error| trouble("read what this source depends on", error))?;
        let rows = query.query_map(params![source_id], package_from).map_err(|error| trouble("read what this source depends on", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read what this source depends on", error))
    }

    pub fn all_dependencies(&self) -> Result<Vec<super::research::Package>, String> {
        let mut query = self.connection.prepare(&format!("{PACKAGES} ORDER BY source_id, ecosystem, name, version")).map_err(|error| trouble("read this grid's dependencies", error))?;
        let rows = query.query_map([], package_from).map_err(|error| trouble("read this grid's dependencies", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this grid's dependencies", error))
    }

    /// Writes one artifact record. Insert only; disposing of one is a statement of its own.
    pub fn put_artifact_record(&self, artifact: &super::research::Artifact) -> Result<(), String> {
        self.connection
            .execute(
                "INSERT INTO research_artifacts (id, realm_id, scope_id, source_id, workload_id, name, media_type, sha256, bytes, retain_until, produced_at, disposed_at, disposed_reason)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    artifact.id,
                    artifact.realm_id,
                    artifact.scope_id,
                    artifact.source_id,
                    artifact.workload_id,
                    artifact.name,
                    artifact.media_type,
                    artifact.sha256,
                    artifact.bytes as i64,
                    artifact.retain_until,
                    artifact.produced_at,
                    artifact.disposed_at,
                    artifact.disposed_reason,
                ],
            )
            .map(|_| ())
            .map_err(|error| match error {
                rusqlite::Error::SqliteFailure(_, Some(message)) if message.contains("research grid of its own") => "Research belongs in a research grid of its own".to_owned(),
                other => trouble("record this artifact", other),
            })
    }

    pub fn artifact_record(&self, id: &str) -> Result<Option<super::research::Artifact>, String> {
        self.connection.query_row(&format!("{RESEARCH_ARTIFACTS} WHERE id = ?1"), params![id], research_artifact_from).optional().map_err(|error| trouble("read this artifact", error))
    }

    pub fn artifacts_of_work(&self, workload_id: &str) -> Result<Vec<super::research::Artifact>, String> {
        let mut query = self.connection.prepare(&format!("{RESEARCH_ARTIFACTS} WHERE workload_id = ?1 ORDER BY produced_at, id")).map_err(|error| trouble("read this run's artifacts", error))?;
        let rows = query.query_map(params![workload_id], research_artifact_from).map_err(|error| trouble("read this run's artifacts", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this run's artifacts", error))
    }

    pub fn artifacts_of_scope(&self, scope_id: &str) -> Result<Vec<super::research::Artifact>, String> {
        let mut query = self.connection.prepare(&format!("{RESEARCH_ARTIFACTS} WHERE scope_id = ?1 ORDER BY produced_at, id")).map_err(|error| trouble("read this scope's artifacts", error))?;
        let rows = query.query_map(params![scope_id], research_artifact_from).map_err(|error| trouble("read this scope's artifacts", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this scope's artifacts", error))
    }

    pub fn all_research_artifacts(&self) -> Result<Vec<super::research::Artifact>, String> {
        let mut query = self.connection.prepare(&format!("{RESEARCH_ARTIFACTS} ORDER BY produced_at, id")).map_err(|error| trouble("read this grid's artifacts", error))?;
        let rows = query.query_map([], research_artifact_from).map_err(|error| trouble("read this grid's artifacts", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this grid's artifacts", error))
    }

    pub fn dispose_artifact(&self, id: &str, reason: &str, now: i64) -> Result<(), String> {
        let touched = self
            .connection
            .execute("UPDATE research_artifacts SET disposed_at = ?2, disposed_reason = ?3 WHERE id = ?1 AND disposed_at IS NULL", params![id, now, clean(reason)])
            .map_err(|error| trouble("let go of this artifact", error))?;
        if touched == 0 {
            return Err("That artifact was already let go of, or is not in this grid".into());
        }
        Ok(())
    }

    /// The next number for a verdict about this artifact. The verdicts are insert-only and the
    /// highest number is the current state, so this is what keeps them in order.
    pub fn next_look(&self, artifact_id: &str) -> Result<u64, String> {
        self.connection
            .query_row("SELECT COALESCE(MAX(sequence), 0) + 1 FROM research_artifact_scans WHERE artifact_id = ?1", params![artifact_id], |row| row.get::<_, i64>(0))
            .map(|next| next as u64)
            .map_err(|error| trouble("read what has been said about this artifact", error))
    }

    pub fn put_look(&self, look: &super::research::Look) -> Result<(), String> {
        self.connection
            .execute(
                "INSERT INTO research_artifact_scans (id, realm_id, artifact_id, verdict, looked_by, tool, reason, sequence, looked_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![look.id, look.realm_id, look.artifact_id, word(&look.verdict), look.looked_by, look.tool, look.reason, look.sequence as i64, look.looked_at],
            )
            .map(|_| ())
            .map_err(|error| trouble("record what was said about this artifact", error))
    }

    pub fn looks(&self, artifact_id: &str) -> Result<Vec<super::research::Look>, String> {
        let mut query = self.connection.prepare(&format!("{LOOKS} WHERE artifact_id = ?1 ORDER BY sequence")).map_err(|error| trouble("read what was said about this artifact", error))?;
        let rows = query.query_map(params![artifact_id], look_from).map_err(|error| trouble("read what was said about this artifact", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read what was said about this artifact", error))
    }

    pub fn all_looks(&self) -> Result<Vec<super::research::Look>, String> {
        let mut query = self.connection.prepare(&format!("{LOOKS} ORDER BY artifact_id, sequence")).map_err(|error| trouble("read what was said about this grid's artifacts", error))?;
        let rows = query.query_map([], look_from).map_err(|error| trouble("read what was said about this grid's artifacts", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read what was said about this grid's artifacts", error))
    }

    /// Writes a finding and the artifacts it rests on in one change.
    pub fn put_finding(&self, finding: &super::research::Finding) -> Result<(), String> {
        let change = self.connection.unchecked_transaction().map_err(|error| trouble("begin a change", error))?;
        change
            .execute(
                "INSERT INTO research_findings (id, realm_id, scope_id, source_id, workload_id, title, component, summary, severity, state, reported_by, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
                 ON CONFLICT(id) DO UPDATE SET title = excluded.title, component = excluded.component, summary = excluded.summary,
                     severity = excluded.severity, state = excluded.state, updated_at = excluded.updated_at",
                params![
                    finding.id,
                    finding.realm_id,
                    finding.scope_id,
                    finding.source_id,
                    finding.workload_id,
                    finding.title,
                    finding.component,
                    finding.summary,
                    word(&finding.severity),
                    word(&finding.state),
                    finding.reported_by,
                    finding.created_at,
                    finding.updated_at,
                ],
            )
            .map_err(|error| match error {
                rusqlite::Error::SqliteFailure(_, Some(message)) if message.contains("sealed finding") => "A sealed finding cannot be moved back".to_owned(),
                rusqlite::Error::SqliteFailure(_, Some(message)) if message.contains("research grid of its own") => "Research belongs in a research grid of its own".to_owned(),
                other => trouble("record this finding", other),
            })?;
        for artifact_id in &finding.artifacts {
            change
                .execute("INSERT OR IGNORE INTO research_finding_artifacts (finding_id, artifact_id) VALUES (?1, ?2)", params![finding.id, artifact_id])
                .map_err(|error| trouble("record what this finding rests on", error))?;
        }
        change.commit().map_err(|error| trouble("finish recording this finding", error))
    }

    pub fn finding(&self, id: &str) -> Result<Option<super::research::Finding>, String> {
        let found = self.connection.query_row(&format!("{FINDINGS} WHERE id = ?1"), params![id], finding_from).optional().map_err(|error| trouble("read this finding", error))?;
        match found {
            Some(mut finding) => {
                finding.artifacts = self.finding_artifacts(&finding.id)?;
                Ok(Some(finding))
            }
            None => Ok(None),
        }
    }

    fn finding_artifacts(&self, finding_id: &str) -> Result<Vec<String>, String> {
        let mut query = self
            .connection
            .prepare("SELECT artifact_id FROM research_finding_artifacts WHERE finding_id = ?1 ORDER BY artifact_id")
            .map_err(|error| trouble("read what this finding rests on", error))?;
        let rows = query.query_map(params![finding_id], |row| row.get::<_, String>(0)).map_err(|error| trouble("read what this finding rests on", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read what this finding rests on", error))
    }

    pub fn findings(&self, scope_id: &str) -> Result<Vec<super::research::Finding>, String> {
        let mut query = self.connection.prepare(&format!("{FINDINGS} WHERE scope_id = ?1 ORDER BY created_at, id")).map_err(|error| trouble("read this scope's findings", error))?;
        let rows = query.query_map(params![scope_id], finding_from).map_err(|error| trouble("read this scope's findings", error))?;
        let mut findings = rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this scope's findings", error))?;
        for finding in &mut findings {
            finding.artifacts = self.finding_artifacts(&finding.id)?;
        }
        Ok(findings)
    }

    pub fn all_findings(&self) -> Result<Vec<super::research::Finding>, String> {
        let mut query = self.connection.prepare(&format!("{FINDINGS} ORDER BY created_at, id")).map_err(|error| trouble("read this grid's findings", error))?;
        let rows = query.query_map([], finding_from).map_err(|error| trouble("read this grid's findings", error))?;
        let mut findings = rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this grid's findings", error))?;
        for finding in &mut findings {
            finding.artifacts = self.finding_artifacts(&finding.id)?;
        }
        Ok(findings)
    }

    /// Says which request belongs to which finding. The verdict is in `decisions`, where every
    /// other decision in this realm is.
    pub fn put_review(&self, finding_id: &str, request_id: &str, now: i64) -> Result<(), String> {
        let realm_id = self.realm_id()?;
        self.connection
            .execute("INSERT INTO research_reviews (finding_id, request_id, realm_id, asked_at) VALUES (?1, ?2, ?3, ?4)", params![finding_id, request_id, realm_id, now])
            .map(|_| ())
            .map_err(|error| trouble("ask for this finding to be reviewed", error))
    }

    pub fn reviews_of(&self, finding_id: &str) -> Result<Vec<Approval>, String> {
        let mut query = self
            .connection
            .prepare(&format!("{REQUESTS} JOIN research_reviews rv ON rv.request_id = r.id WHERE rv.finding_id = ?1 ORDER BY rv.asked_at, r.id"))
            .map_err(|error| trouble("read this finding's reviews", error))?;
        let rows = query.query_map(params![finding_id], approval_from).map_err(|error| trouble("read this finding's reviews", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this finding's reviews", error))
    }

    /// Every review link in the realm, as pairs, so a backup carries which request was about what.
    pub fn all_reviews(&self) -> Result<Vec<(String, String, i64)>, String> {
        let mut query = self
            .connection
            .prepare("SELECT finding_id, request_id, asked_at FROM research_reviews ORDER BY asked_at, request_id")
            .map_err(|error| trouble("read this grid's reviews", error))?;
        let rows = query
            .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?)))
            .map_err(|error| trouble("read this grid's reviews", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this grid's reviews", error))
    }

    /// Seals a crossing and marks the finding sealed in one change. The two counts come from the
    /// rows rather than from whoever asked, so a document cannot claim evidence it does not have.
    pub fn put_crossing(&self, crossing: &super::research::Crossing, finding: &super::research::Finding) -> Result<(), String> {
        let change = self.connection.unchecked_transaction().map_err(|error| trouble("begin a change", error))?;
        change
            .execute(
                "INSERT INTO research_crossings (id, realm_id, finding_id, digest, seal, bundle_version, reviews, artifacts, scope_digest, source_digest, sealed_by, sealed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6,
                     (SELECT COUNT(*) FROM research_reviews rv JOIN requests r ON r.id = rv.request_id WHERE rv.finding_id = ?3 AND r.state = 'granted'),
                     (SELECT COUNT(*) FROM research_finding_artifacts WHERE finding_id = ?3),
                     ?7, ?8, ?9, ?10)",
                params![
                    format!("crossing-{}", &crate::token()[..16]),
                    crossing.from_realm_id,
                    finding.id,
                    crossing.digest,
                    crossing.seal,
                    crossing.bundle_version as i64,
                    crossing.scope_digest,
                    crossing.source_digest,
                    crossing.sealed_by,
                    crossing.sealed_at,
                ],
            )
            .map_err(|error| match error {
                rusqlite::Error::SqliteFailure(_, Some(message)) if message.contains("found it clean") => "Somebody looks at every artifact and finds it clean before anything crosses".to_owned(),
                rusqlite::Error::SqliteFailure(_, Some(message)) if message.contains("never on its own") => "A finding crosses with the artifacts it rests on, never on its own".to_owned(),
                rusqlite::Error::SqliteFailure(_, Some(message)) if message.contains("research_crossings.reviews") => "A finding crosses once somebody else has accepted it".to_owned(),
                rusqlite::Error::SqliteFailure(_, Some(message)) if message.contains("research_crossings.finding_id") => "This finding has already been sealed".to_owned(),
                other => trouble("seal this document", other),
            })?;
        change
            .execute("UPDATE research_findings SET state = ?2, updated_at = ?3 WHERE id = ?1", params![finding.id, word(&finding.state), finding.updated_at])
            .map_err(|error| trouble("record that this finding was sealed", error))?;
        change.commit().map_err(|error| trouble("finish sealing this document", error))
    }

    pub fn crossings(&self) -> Result<Vec<super::research::SealedCrossing>, String> {
        let mut query = self.connection.prepare(&format!("{CROSSINGS} ORDER BY sealed_at, id")).map_err(|error| trouble("read this grid's sealed documents", error))?;
        let rows = query.query_map([], crossing_from).map_err(|error| trouble("read this grid's sealed documents", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this grid's sealed documents", error))
    }

    pub fn withdraw_crossing(&self, digest: &str, reason: &str, now: i64) -> Result<(), String> {
        self.connection
            .execute("UPDATE research_crossings SET withdrawn_at = ?2, withdrawn_reason = ?3 WHERE digest = ?1 AND withdrawn_at IS NULL", params![digest, now, clean(reason)])
            .map(|_| ())
            .map_err(|error| trouble("mark this document as no longer good", error))
    }

    pub fn put_import(&self, import: &super::research::Import) -> Result<(), String> {
        self.connection
            .execute(
                "INSERT INTO research_imports (id, realm_id, crossing_digest, from_realm_id, from_realm_name, from_key_fingerprint, scope_digest, source_digest, title, severity, artifacts, reviews, approval_id, accepted_by, accepted_at, note, withdrawn_at, withdrawn_reason)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
                params![
                    import.id,
                    import.realm_id,
                    import.crossing_digest,
                    import.from_realm_id,
                    import.from_realm_name,
                    import.from_key_fingerprint,
                    import.scope_digest,
                    import.source_digest,
                    import.title,
                    word(&import.severity),
                    import.artifacts as i64,
                    import.reviews as i64,
                    import.approval_id,
                    import.accepted_by,
                    import.accepted_at,
                    import.note,
                    import.withdrawn_at,
                    import.withdrawn_reason,
                ],
            )
            .map(|_| ())
            .map_err(|error| match error {
                rusqlite::Error::SqliteFailure(_, Some(message)) if message.contains("research_imports.crossing_digest") => "This grid has already accepted that document".to_owned(),
                rusqlite::Error::SqliteFailure(_, Some(message)) if message.contains("research_imports.approval_id") => "That agreement has already let a document in".to_owned(),
                rusqlite::Error::SqliteFailure(_, Some(message)) if message.contains("only a company grid") => "A research result is accepted by a company grid".to_owned(),
                other => trouble("accept this research result", other),
            })
    }

    pub fn imports(&self) -> Result<Vec<super::research::Import>, String> {
        let mut query = self.connection.prepare(&format!("{IMPORTS} ORDER BY accepted_at, id")).map_err(|error| trouble("read the research results this grid accepted", error))?;
        let rows = query.query_map([], import_from).map_err(|error| trouble("read the research results this grid accepted", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read the research results this grid accepted", error))
    }

    /// Writes a sealed crossing back exactly as it was, counts and all, for a restore.
    ///
    /// `put_crossing` derives the counts from the rows, which is right when a document is being
    /// sealed; here the rows have just been written from the same record and the counts came with
    /// it, so writing them back is what keeps a restored realm the realm that was backed up. The
    /// evidence triggers still have to pass, which is why findings, their artifacts and the
    /// verdicts about them all arrive before this.
    fn put_sealed_crossing(&self, crossing: &super::research::SealedCrossing) -> Result<(), String> {
        self.connection
            .execute(
                "INSERT INTO research_crossings (id, realm_id, finding_id, digest, seal, bundle_version, reviews, artifacts, scope_digest, source_digest, sealed_by, sealed_at, withdrawn_at, withdrawn_reason)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                params![
                    crossing.id,
                    crossing.realm_id,
                    crossing.finding_id,
                    crossing.digest,
                    crossing.seal,
                    crossing.bundle_version as i64,
                    crossing.reviews as i64,
                    crossing.artifacts as i64,
                    crossing.scope_digest,
                    crossing.source_digest,
                    crossing.sealed_by,
                    crossing.sealed_at,
                    crossing.withdrawn_at,
                    crossing.withdrawn_reason,
                ],
            )
            .map(|_| ())
            .map_err(|error| trouble("bring across a sealed document", error))
    }

    pub fn withdraw_import(&self, crossing_digest: &str, reason: &str, now: i64) -> Result<(), String> {
        let touched = self
            .connection
            .execute("UPDATE research_imports SET withdrawn_at = ?2, withdrawn_reason = ?3 WHERE crossing_digest = ?1 AND withdrawn_at IS NULL", params![crossing_digest, now, clean(reason)])
            .map_err(|error| trouble("mark this research result as no longer good", error))?;
        if touched == 0 {
            return Err("This grid has not accepted that document, or has already set it aside".into());
        }
        Ok(())
    }

    // ---- Taking the whole realm somewhere else ----

    // ---- How much a realm holds, and whether it holds any ----

    /// How many of each thing this realm holds, in one pass of counts.
    ///
    /// Every number is a `COUNT`, so this is what an operator reads instead of `snapshot`, which
    /// builds every row in the realm to answer the same question.
    pub fn counts(&self) -> Result<Counts, String> {
        self.connection
            .query_row(
                "SELECT (SELECT COUNT(*) FROM principals), (SELECT COUNT(*) FROM devices), (SELECT COUNT(*) FROM hosts),
                        (SELECT COUNT(*) FROM model_plans), (SELECT COUNT(*) FROM workspaces), (SELECT COUNT(*) FROM workspace_assignments),
                        (SELECT COUNT(*) FROM credentials), (SELECT COUNT(*) FROM credential_grants), (SELECT COUNT(*) FROM workloads),
                        (SELECT COUNT(*) FROM leases), (SELECT COUNT(*) FROM requests), (SELECT COUNT(*) FROM standing_allowances),
                        (SELECT COUNT(*) FROM audit_events), (SELECT COUNT(*) FROM credential_uses)",
                [],
                |row| {
                    let at = |index: usize| -> rusqlite::Result<usize> { Ok(row.get::<_, i64>(index)?.max(0) as usize) };
                    Ok(Counts {
                        people: at(0)?,
                        devices: at(1)?,
                        hosts: at(2)?,
                        model_plans: at(3)?,
                        workspaces: at(4)?,
                        placements: at(5)?,
                        credentials: at(6)?,
                        grants: at(7)?,
                        workloads: at(8)?,
                        leases: at(9)?,
                        requests: at(10)?,
                        allowances: at(11)?,
                        audit_events: at(12)?,
                        credential_uses: at(13)?,
                    })
                },
            )
            .map_err(|error| trouble("count what this grid holds", error))
    }

    /// How many rows have ever been written to the two tables nothing deletes from: the brokered
    /// request ledger, and the reservations.
    ///
    /// Both are `MAX(rowid)` and not `COUNT(*)`, which is the whole point of having this beside
    /// `counts`. Readiness runs on an operator's schedule and asks only whether these two are
    /// getting large; a count with no `WHERE` would walk a b-tree of half a million entries to
    /// answer that, and the largest row identifier is one descent. Both tables are insert-only,
    /// `credential_uses` because the database refuses a delete and `leases` because a reservation
    /// is released rather than removed, so the number of rows ever written is the growth the
    /// warning is about. It is not the number of rows held: that is `counts`, and it costs what a
    /// count costs.
    pub fn ever_written(&self) -> Result<(usize, usize), String> {
        self.connection
            .query_row(
                "SELECT (SELECT COALESCE(MAX(rowid), 0) FROM credential_uses), (SELECT COALESCE(MAX(rowid), 0) FROM leases)",
                [],
                |row| Ok((row.get::<_, i64>(0)?.max(0) as usize, row.get::<_, i64>(1)?.max(0) as usize)),
            )
            .map_err(|error| trouble("read how much this grid has written", error))
    }

    pub fn people_count(&self) -> Result<usize, String> {
        self.count("SELECT COUNT(*) FROM principals", params![])
    }

    pub fn device_count(&self) -> Result<usize, String> {
        self.count("SELECT COUNT(*) FROM devices", params![])
    }

    pub fn credential_count(&self) -> Result<usize, String> {
        self.count("SELECT COUNT(*) FROM credentials WHERE retired_at IS NULL", params![])
    }

    pub fn grant_count(&self) -> Result<usize, String> {
        self.count("SELECT COUNT(*) FROM credential_grants", params![])
    }

    /// How many requests are open: waiting, or granted and not yet run out.
    pub fn open_request_count(&self, now: i64) -> Result<usize, String> {
        self.count("SELECT COUNT(*) FROM requests WHERE state IN ('waiting','granted') AND ?1 < expires_at", params![now])
    }

    /// Credentials due to be rotated by `by` and not yet retired.
    pub fn credentials_due_to_rotate(&self, by: i64) -> Result<usize, String> {
        self.count("SELECT COUNT(*) FROM credentials WHERE retired_at IS NULL AND rotate_by IS NOT NULL AND rotate_by <= ?1", params![by])
    }

    /// How much work sits in each stage an operator watches.
    pub fn queue_depth(&self) -> Result<Vec<(Stage, usize)>, String> {
        let mut query = self
            .connection
            .prepare("SELECT stage, COUNT(*) FROM workloads WHERE stage IN ('queued','leased','preparing','running','draining') GROUP BY stage ORDER BY stage")
            .map_err(|error| trouble("read this grid's work", error))?;
        let rows = query
            .query_map([], |row| Ok((unword::<Stage>(&row.get::<_, String>(0)?, "a stage")?, row.get::<_, i64>(1)?.max(0) as usize)))
            .map_err(|error| trouble("read this grid's work", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this grid's work", error))
    }

    /// How many computers each model plan is on, which is what the realm decided rather than what
    /// any runner has loaded.
    pub fn plan_placements(&self) -> Result<Vec<(String, String, usize)>, String> {
        let mut query = self
            .connection
            .prepare("SELECT p.id, p.model, COUNT(a.host_id) FROM model_plans p LEFT JOIN model_assignments a ON a.plan_id = p.id GROUP BY p.id, p.model ORDER BY p.created_at, p.rowid")
            .map_err(|error| trouble("read this grid's model plans", error))?;
        let rows = query
            .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?.max(0) as usize)))
            .map_err(|error| trouble("read this grid's model plans", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this grid's model plans", error))
    }

    /// How many computers this realm has, and how many of them can take work and were heard from
    /// since `since`.
    pub fn host_availability(&self, since: i64) -> Result<(usize, usize, usize), String> {
        self.connection
            .query_row(
                "SELECT (SELECT COUNT(*) FROM hosts),
                        (SELECT COUNT(*) FROM hosts h JOIN devices d ON d.id = h.device_id
                          WHERE d.revoked_at IS NULL AND h.draining = 0 AND h.commitment <> 'none'),
                        (SELECT COUNT(*) FROM devices WHERE revoked_at IS NULL AND last_seen_at IS NOT NULL AND last_seen_at > ?1)",
                params![since],
                |row| Ok((row.get::<_, i64>(0)?.max(0) as usize, row.get::<_, i64>(1)?.max(0) as usize, row.get::<_, i64>(2)?.max(0) as usize)),
            )
            .map_err(|error| trouble("read this grid's computers", error))
    }

    /// Whether any computer in this realm can take work at all. One row, for a readiness probe.
    pub fn any_host_takes_work(&self) -> Result<bool, String> {
        self.any(
            "SELECT EXISTS(SELECT 1 FROM hosts h JOIN devices d ON d.id = h.device_id
                            WHERE d.revoked_at IS NULL AND h.draining = 0 AND h.commitment <> 'none')",
            params![],
        )
    }

    /// Whether this realm holds any computer or any model plan. Asked before an import, which used
    /// to read both tables in full only to look at whether they were empty.
    pub fn holds_any_host_or_plan(&self) -> Result<bool, String> {
        self.any("SELECT EXISTS(SELECT 1 FROM hosts) OR EXISTS(SELECT 1 FROM model_plans)", params![])
    }

    /// Whether this realm holds any workspace or any image, for the same reason.
    pub fn holds_any_workspace_or_image(&self) -> Result<bool, String> {
        self.any("SELECT EXISTS(SELECT 1 FROM workspaces) OR EXISTS(SELECT 1 FROM workspace_images)", params![])
    }

    /// Whether this realm holds any credential or any permission to use one, for the same reason.
    pub fn holds_any_credential_or_grant(&self) -> Result<bool, String> {
        self.any("SELECT EXISTS(SELECT 1 FROM credentials) OR EXISTS(SELECT 1 FROM credential_grants)", params![])
    }

    /// Whether this realm holds any research scope or any acquired source, for the same reason.
    pub fn holds_any_scope_or_source(&self) -> Result<bool, String> {
        self.any("SELECT EXISTS(SELECT 1 FROM research_scopes) OR EXISTS(SELECT 1 FROM research_sources)", params![])
    }

    /// Whether any of these credentials has been sent anywhere through the broker. The question an
    /// Access Grid import asks before it undoes itself: a credential that has been used is one
    /// somebody's work now depends on, and taking it out would leave that record naming nothing.
    pub fn any_credential_used(&self, credentials: &[String]) -> Result<bool, String> {
        for credential_id in credentials {
            if self.any("SELECT EXISTS(SELECT 1 FROM credential_uses WHERE credential_id = ?1)", params![credential_id])? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Whether any computer in this realm belongs to one of these people and is not one of these
    /// computers. The question an import asks before it undoes itself.
    pub fn any_other_device_of(&self, principals: &[String], besides: &[String]) -> Result<bool, String> {
        for principal_id in principals {
            let mut query = self
                .connection
                .prepare("SELECT id FROM devices WHERE principal_id = ?1")
                .map_err(|error| trouble("read this grid's computers", error))?;
            let rows = query.query_map(params![principal_id], |row| row.get::<_, String>(0)).map_err(|error| trouble("read this grid's computers", error))?;
            for found in rows {
                let found = found.map_err(|error| trouble("read this grid's computers", error))?;
                if !besides.contains(&found) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Every piece of work in this realm placed from one of these computers or by one of these
    /// people, by identifier. One query per computer and per person, instead of reading every
    /// workload the realm has ever held.
    pub fn work_from(&self, devices: &[String], principals: &[String]) -> Result<Vec<String>, String> {
        let mut found: Vec<String> = Vec::new();
        for (column, wanted) in [("device_id", devices), ("principal_id", principals)] {
            let sql = format!("SELECT id FROM workloads WHERE {column} = ?1");
            for one in wanted {
                let mut query = self.connection.prepare(&sql).map_err(|error| trouble("read this grid's work", error))?;
                let rows = query.query_map(params![one], |row| row.get::<_, String>(0)).map_err(|error| trouble("read this grid's work", error))?;
                for id in rows {
                    found.push(id.map_err(|error| trouble("read this grid's work", error))?);
                }
            }
        }
        found.sort();
        found.dedup();
        Ok(found)
    }

    /// Whether any work in this realm belongs to one of these computers or to this person.
    pub fn any_work_of(&self, devices: &[String], principal_id: &str) -> Result<bool, String> {
        if self.any("SELECT EXISTS(SELECT 1 FROM workloads WHERE principal_id = ?1)", params![principal_id])? {
            return Ok(true);
        }
        for device_id in devices {
            if self.any("SELECT EXISTS(SELECT 1 FROM workloads WHERE device_id = ?1)", params![device_id])? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// How much a research realm has open and how much it has found: scopes still open, findings
    /// recorded, and findings submitted and not yet accepted or rejected.
    pub fn research_shape(&self) -> Result<(usize, usize, usize), String> {
        self.connection
            .query_row(
                "SELECT (SELECT COUNT(*) FROM research_scopes WHERE closed_at IS NULL),
                        (SELECT COUNT(*) FROM research_findings),
                        (SELECT COUNT(*) FROM research_findings WHERE state = 'submitted')",
                [],
                |row| Ok((row.get::<_, i64>(0)?.max(0) as usize, row.get::<_, i64>(1)?.max(0) as usize, row.get::<_, i64>(2)?.max(0) as usize)),
            )
            .map_err(|error| trouble("read this grid's research", error))
    }

    /// An exact copy of this realm's database, taken while it is open.
    ///
    /// SQLite's own `VACUUM INTO`, so the copy is consistent without stopping the realm and
    /// without a new dependency. It holds a read lock while it runs, so on a large realm the one
    /// writer waits for it; that is why it belongs in upkeep rather than on anybody's request
    /// path. The copy is the same shape as the original, which is the point and also the limit: it
    /// survives a crash and a bad write, and it does not survive a bad migration, because it would
    /// be migrated the same way. It is also plain readable SQLite, exactly as the realm's own file
    /// is, so wherever it is written is as sensitive as the realm's folder.
    pub fn copy_to(&self, path: &Path) -> Result<(), String> {
        if path.exists() {
            return Err("There is already a file where that copy would go".into());
        }
        if let Some(folder) = path.parent() {
            if !folder.as_os_str().is_empty() {
                std::fs::create_dir_all(folder).map_err(|error| format!("Cannot open the folder for the copy: {error}"))?;
            }
        }
        // A copy is the largest single write a realm ever makes, and the one in
        // `upgrade_with_a_copy` is the only way back out of a version that has none. Half a copy
        // is worse than no copy, because it looks like one.
        room::enough_for(path, std::fs::metadata(&self.path).map(|about| about.len()).unwrap_or(0), "for a copy of this grid")?;
        self.connection
            .execute("VACUUM INTO ?1", params![path.to_string_lossy()])
            .map(|_| ())
            .map_err(|error| trouble("take a copy of the grid", error))
    }

    // ---- What a bridge's import created ----

    /// Writes down what an import created, so that it can still be undone after a restart.
    pub fn put_bridge_import(&self, row: &super::compat::BridgeImport) -> Result<(), String> {
        self.connection
            .execute(
                "INSERT INTO bridge_imports (id, realm_id, bridge, grid_id, at, undo) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![row.id, row.realm_id, row.undo.word(), row.grid_id, row.at, json(&row.undo)],
            )
            .map(|_| ())
            .map_err(|error| trouble("write down what this import created", error))
    }

    /// Every import this realm still holds, oldest first.
    pub fn bridge_imports(&self) -> Result<Vec<super::compat::BridgeImport>, String> {
        let mut query = self
            .connection
            .prepare("SELECT id, realm_id, grid_id, at, undo FROM bridge_imports ORDER BY at")
            .map_err(|error| trouble("read what has been brought across", error))?;
        let rows = query
            .query_map([], |row| {
                Ok(super::compat::BridgeImport {
                    id: row.get(0)?,
                    realm_id: row.get(1)?,
                    grid_id: row.get(2)?,
                    at: row.get(3)?,
                    undo: unjson(&row.get::<_, String>(4)?, "what an import created")?,
                })
            })
            .map_err(|error| trouble("read what has been brought across", error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read what has been brought across", error))
    }

    /// Takes the record of an import out once the import itself has been undone.
    ///
    /// The evidence that it happened is the history, which records the import and the undoing of
    /// it and is never rewritten. Keeping the row as well would mean a realm that came back clean
    /// still differed from the realm before the import.
    pub fn forget_bridge_import(&self, id: &str) -> Result<(), String> {
        self.connection
            .execute("DELETE FROM bridge_imports WHERE id = ?1", params![id])
            .map(|_| ())
            .map_err(|error| trouble("take out the record of an import", error))
    }

    /// Every table in this realm, with how many rows it holds and a digest of their contents.
    ///
    /// This exists so that a rollback can be checked mechanically instead of by reasoning about
    /// which rows a bridge writes. A snapshot is not enough for that job: it is the portable
    /// shape, and the portable shape deliberately leaves out sign-ins, spent permissions,
    /// brokered uses, withdrawals, what each computer last said about itself and every
    /// generation number. A rollback that bumped a generation or left a withdrawal behind would
    /// pass a snapshot comparison and fail this one.
    ///
    /// Three tables are left out, each for a reason rather than for convenience. `audit_events`
    /// and `audit_chain` grow legitimately: the history records the import and the undoing of it
    /// and is never rewritten, so a realm that came back clean still has two more events than it
    /// started with. `migrations` is the record of which versions have run, which an import does
    /// not touch and a rollback must not.
    pub fn tally(&self) -> Result<std::collections::BTreeMap<String, (usize, String)>, String> {
        use sha2::{Digest, Sha256};
        let left_out = ["audit_events", "audit_chain", "migrations"];
        let mut names: Vec<String> = self
            .connection
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
            .map_err(|error| trouble("read the grid's tables", error))?
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|error| trouble("read the grid's tables", error))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|error| trouble("read the grid's tables", error))?;
        names.sort();
        let mut tally = std::collections::BTreeMap::new();
        for name in names.into_iter().filter(|name| !left_out.contains(&name.as_str())) {
            let mut query = self.connection.prepare(&format!("SELECT * FROM \"{name}\"")).map_err(|error| trouble("read a table", error))?;
            let columns = query.column_count();
            let mut rows = query.query([]).map_err(|error| trouble("read a table", error))?;
            let mut lines: Vec<String> = Vec::new();
            while let Some(row) = rows.next().map_err(|error| trouble("read a table", error))? {
                let mut line = String::new();
                for index in 0..columns {
                    let value = row.get_ref(index).map_err(|error| trouble("read a row", error))?;
                    line.push_str(&match value {
                        rusqlite::types::ValueRef::Null => "null".to_owned(),
                        rusqlite::types::ValueRef::Integer(number) => number.to_string(),
                        rusqlite::types::ValueRef::Real(number) => number.to_string(),
                        rusqlite::types::ValueRef::Text(text) => String::from_utf8_lossy(text).to_string(),
                        rusqlite::types::ValueRef::Blob(bytes) => hex::encode(bytes),
                    });
                    line.push('\u{1f}');
                }
                lines.push(line);
            }
            // Sorted, because the order rows happen to come back in is not part of what a realm
            // holds and would make a comparison report a difference that is not one.
            lines.sort();
            let mut hasher = Sha256::new();
            for line in &lines {
                hasher.update(line.as_bytes());
            }
            tally.insert(name, (lines.len(), hex::encode(hasher.finalize())));
        }
        Ok(tally)
    }

    /// Everything in the realm, in the portable shape.
    pub fn snapshot(&self) -> Result<Record, String> {
        Ok(Record {
            version: VERSION,
            realm: self.realm()?,
            policy_version: self.policy_version()?,
            principals: self.principals()?,
            devices: self.devices()?,
            hosts: self.hosts()?,
            leases: self.leases()?,
            workloads: self.workloads()?,
            approvals: self.requests()?,
            allowances: self.allowances()?,
            credentials: self.credentials()?,
            grants: self.grants()?,
            model_plans: self.model_plans()?,
            model_assignments: self.model_assignments()?,
            images: self.images()?,
            workspaces: self.workspaces()?,
            assignments: self.assignments()?,
            artifacts: self.artifacts()?,
            commitments: self.all_commitments()?,
            // The research profile. A backup that carried the realm row and none of this would
            // restore a research grid with no record of what it had been allowed to study, what
            // was let in or what it found, and it would look like a working restore.
            scopes: self.scopes()?,
            admissions: self.all_admissions()?,
            sources: self.all_sources()?,
            source_files: self.all_source_files()?,
            dependencies: self.all_dependencies()?,
            research_artifacts: self.all_research_artifacts()?,
            looks: self.all_looks()?,
            findings: self.all_findings()?,
            reviews: self.all_reviews()?,
            crossings: self.crossings()?,
            imports: self.imports()?,
            // What a bridge's import created, so a restored realm can still undo one.
            bridge_imports: self.bridge_imports()?,
            // Sign-ins are deliberately absent. Each one names a permission, and a record carries
            // no permissions at all, so a restored realm would hold sign-ins pointing at nothing
            // and hand somebody a workspace on the strength of them. A restored realm hands
            // nobody a live workspace, and leaving these out is what keeps the shape honest.
            audit: self.chain()?,
        })
    }

    /// Builds a realm's database from the portable shape, keeping every seal as it was: the
    /// history is carried across, not re-sealed, so it still verifies with the realm's key.
    pub fn import(path: &Path, record: &Record, reference: &KeyReference, now: i64) -> Result<Store, String> {
        if path.exists() {
            return Err("This computer already holds a grid of that name".into());
        }
        let mut store = Store::connect(path)?;
        store.migrate()?;
        store.put_realm(&record.realm, reference, now)?;
        store.fill(record)?;
        Ok(store)
    }

    /// Writes the body of a record into an empty database. Things arrive in the order they depend
    /// on one another: people, then their computers, then what runs on them, then what was
    /// decided, and the history last.
    fn fill(&self, record: &Record) -> Result<(), String> {
        self.connection
            .execute("UPDATE realms SET policy_version = ?1", params![record.policy_version as i64])
            .map_err(|error| trouble("bring across the policy version", error))?;
        // An account or a computer that was withdrawn comes across withdrawn, and at a generation
        // above the one it started at.
        //
        // The record carries no generation numbers, and it does not need to: it carries no
        // permissions either, so nothing a restored realm handed out before is remembered and
        // everything presented to it is refused as unknown. What it must not do is bring a
        // suspended account back at the generation an active one starts at, because withdrawal
        // works by comparing generations and a restored realm would then be one where the record
        // and the generation disagree. If a record is ever made to carry permissions, the
        // generations have to come with them and this becomes the wrong answer.
        for principal in &record.principals {
            self.add_principal(principal, "import", principal.created_at)?;
            if let Some(at) = principal.suspended_at {
                self.connection
                    .execute("UPDATE principals SET suspended_at = ?2, generation = generation + 1 WHERE id = ?1", params![principal.id, at])
                    .map_err(|error| trouble("bring across an account", error))?;
            }
        }
        for device in &record.devices {
            self.enrol_device(device)?;
            if device.revoked_at.is_some() {
                self.connection
                    .execute("UPDATE devices SET generation = generation + 1 WHERE id = ?1", params![device.id])
                    .map_err(|error| trouble("bring across a computer", error))?;
            }
        }
        for host in &record.hosts {
            self.put_host(host)?;
        }
        for work in &record.workloads {
            self.put_workload(work)?;
        }
        for lease in &record.leases {
            self.put_lease(lease)?;
        }
        for request in &record.approvals {
            // Every request arrives waiting, and its decision moves it on, so the one path that
            // writes a decision is the one that ran when it was first made.
            let mut waiting = request.clone();
            waiting.state = State::Waiting;
            self.put_request(&waiting)?;
            if request.state != State::Waiting {
                let verdict = if request.state == State::Granted { "approve_once" } else { "deny" };
                let allowance = record.allowances.iter().find(|allowance| allowance.approval_id == request.id);
                let verdict = if allowance.is_some() { "approve_until" } else { verdict };
                if request.decided_by.is_some() {
                    self.record_decision(request, verdict, allowance.map(|allowance| allowance.expires_at), allowance)?;
                } else {
                    // It lapsed rather than being decided: the state moves, and no decision is
                    // invented for it.
                    self.connection
                        .execute("UPDATE requests SET state = ?2 WHERE id = ?1", params![request.id, word(&request.state)])
                        .map_err(|error| trouble("bring across a request", error))?;
                }
            }
        }
        for allowance in &record.allowances {
            if !record.approvals.iter().any(|request| request.id == allowance.approval_id && request.decided_by.is_some()) {
                continue;
            }
            self.connection
                .execute(
                    "INSERT OR IGNORE INTO standing_allowances (id, realm_id, principal_id, resource_id, method, path, approver_id, request_id, created_at, expires_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    params![
                        allowance.id,
                        allowance.realm_id,
                        allowance.principal_id,
                        allowance.resource_id,
                        allowance.method,
                        allowance.path,
                        allowance.approved_by,
                        allowance.approval_id,
                        allowance.granted_at,
                        allowance.expires_at,
                    ],
                )
                .map_err(|error| trouble("bring across a standing allowance", error))?;
        }
        for credential in &record.credentials {
            self.put_credential(credential)?;
        }
        for grant in &record.grants {
            self.put_grant(grant)?;
        }
        self.replace_model_state(&record.model_plans, &record.model_assignments)?;
        // An image arrives with the digest it already had, because this is a fresh database and
        // the insert carries it; pinning is for the moment a computer first hashes the bytes.
        for image in &record.images {
            self.put_image(image)?;
        }
        for workspace in &record.workspaces {
            self.put_workspace(workspace)?;
        }
        // Placements come back in the order they were made, because the database refuses a
        // placement number below one this workspace has already used, and a record says nothing
        // about the order its rows happen to be in.
        let mut placements: Vec<&Assignment> = record.assignments.iter().collect();
        placements.sort_by(|left, right| left.workspace_id.cmp(&right.workspace_id).then(left.generation.cmp(&right.generation)));
        for assignment in placements {
            self.put_assignment(assignment)?;
        }
        for artifact in &record.artifacts {
            self.put_artifact(artifact)?;
        }
        for pledge in &record.commitments {
            self.put_pledge(pledge)?;
        }
        self.fill_research(record)?;
        for import in &record.bridge_imports {
            self.put_bridge_import(import)?;
        }
        self.put_events(&record.audit)?;
        Ok(())
    }

    /// Brings the research profile across, in the order the rows depend on one another: what may
    /// be studied, then what was let in, then the material, then what a run produced, then who
    /// looked at it, then the findings and the one document that was sealed.
    ///
    /// The order matters more here than elsewhere, because a sealed crossing is refused by the
    /// database unless the finding it names already rests on artifacts somebody has called clean.
    fn fill_research(&self, record: &Record) -> Result<(), String> {
        let mut scopes: Vec<&super::research::Scope> = record.scopes.iter().collect();
        scopes.sort_by_key(|scope| scope.version);
        for scope in scopes {
            self.put_scope(scope)?;
        }
        for admitted in &record.admissions {
            self.put_admission(admitted)?;
        }
        for source in &record.sources {
            let files: Vec<super::research::SourceFile> =
                record.source_files.iter().filter(|(id, _)| id == &source.id).map(|(_, file)| file.clone()).collect();
            self.put_source(source, &files)?;
        }
        self.put_dependencies(&record.dependencies)?;
        for artifact in &record.research_artifacts {
            self.put_artifact_record(artifact)?;
        }
        for look in &record.looks {
            self.put_look(look)?;
        }
        for finding in &record.findings {
            self.put_finding(finding)?;
        }
        for (finding_id, request_id, asked_at) in &record.reviews {
            self.put_review(finding_id, request_id, *asked_at)?;
        }
        for crossing in &record.crossings {
            self.put_sealed_crossing(crossing)?;
        }
        for import in &record.imports {
            self.put_import(import)?;
        }
        Ok(())
    }

    /// Writes a history exactly as it was, seals and all, and points the head at its end.
    fn put_events(&self, chain: &Chain) -> Result<(), String> {
        let change = self.connection.unchecked_transaction().map_err(|error| trouble("begin a change", error))?;
        for event in &chain.events {
            change
                .execute(
                    "INSERT INTO audit_events (sequence, id, realm_id, at, capability, principal_id, device_id, workload_id, action, resource_id, policy_version, decision, reason, command, previous_seal, seal)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
                    params![
                        event.sequence as i64,
                        event.id,
                        event.realm_id,
                        event.at,
                        event.capability.map(|capability| word(&capability)),
                        event.principal_id,
                        event.device_id,
                        event.workload_id,
                        event.action,
                        event.resource_id,
                        event.policy_version as i64,
                        word(&event.decision),
                        event.reason,
                        event.command,
                        event.previous_seal,
                        event.seal,
                    ],
                )
                .map_err(|error| trouble("bring across this grid's history", error))?;
        }
        if let Some(last) = chain.events.last() {
            change
                .execute("UPDATE audit_chain SET head_sequence = ?1, head_seal = ?2, updated_at = ?3", params![last.sequence as i64, last.seal, last.at])
                .map_err(|error| trouble("bring across this grid's history", error))?;
        }
        change.commit().map_err(|error| trouble("finish bringing across this grid's history", error))
    }

    /// Closes the database, flushing the journal back into the file so a copy taken afterwards is
    /// the whole realm.
    pub fn close(self) -> Result<(), String> {
        let _ = self.connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)");
        self.connection.close().map_err(|(_, error)| trouble("close the grid", error))
    }
}

/// How many of each thing a realm holds. Counts and nothing else: no name, no path, no value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Counts {
    pub people: usize,
    pub devices: usize,
    pub hosts: usize,
    pub model_plans: usize,
    pub workspaces: usize,
    pub placements: usize,
    pub credentials: usize,
    pub grants: usize,
    pub workloads: usize,
    pub leases: usize,
    pub requests: usize,
    pub allowances: usize,
    pub audit_events: usize,
    pub credential_uses: usize,
}

/// The columns of a computer that offers resources.
const HOSTS: &str = "SELECT id, realm_id, device_id, name, capacity, offered, gpu_isolation, commitment, draining, joined_at FROM hosts";

/// The columns of a piece of work.
const WORKLOADS: &str = "SELECT id, realm_id, capability, kind, principal_id, device_id, stage, needs, policy_version, lease_id, note, created_at, updated_at, expires_at
 FROM workloads";

/// The columns of a reservation.
const LEASES: &str = "SELECT id, realm_id, host_id, workload_id, resources, generation, granted_at, expires_at, released_at FROM leases";

/// The stages nothing more happens in, as the database spells them. This is `Stage::finished` in
/// SQL, and the one place those words are written for a query; `the_words_for_a_finished_stage_are_the_ones_the_code_means`
/// fails if the two ever disagree.
const UNFINISHED: &str = "stage NOT IN ('completed','rejected','cancelled','expired','failed','quarantined')";

/// The columns of a request, with whatever decision it has.
const REQUESTS: &str = "SELECT r.id, r.realm_id, r.action, r.resource_id, r.method, r.path, r.requested_by, r.requested_at, r.expires_at, r.every_time, r.state,
        d.decided_by, d.decided_at, d.self_issued, d.reason
 FROM requests r LEFT JOIN decisions d ON d.request_id = r.id";

/// The columns of a credential. There is no value among them.
const CREDENTIALS: &str = "SELECT id, realm_id, name, kind, vault_id, vault_version, fingerprint, destination, methods, paths, maximum_bytes, owner_id, every_time,
        created_at, rotated_at, rotate_by, retired_at, presentation, field, generation, settings, query_allowed_by, query_allowed_at
 FROM credentials";

/// The columns of one brokered request. There is no value among them, and no query, because a
/// query credential's value travels in one.
const USES: &str = "SELECT id, realm_id, credential_id, capability_id, approval_id, principal_id, device_id, workload_id, destination, method, path,
        request_bytes, answer_bytes, status, vault_id, vault_version, outcome, reason, policy_version, started_at, finished_at
 FROM credential_uses";

const GRANTS: &str = "SELECT id, realm_id, credential_id, principal_id, methods, paths, granted_by, granted_at, expires_at FROM credential_grants";

/// The columns of an image. There is nothing among them that is a place on one computer.
const IMAGES: &str = "SELECT id, realm_id, name, version, description, kind, digest, source, bytes, shape, applications, published_by, published_at, verified_at, retired_at
 FROM workspace_images";

/// The columns of a workspace. There is nothing among them that could hold what is inside it.
const WORKSPACES: &str = "SELECT id, realm_id, name, owner_id, image_id, image_digest, shape, access, quota, state, note, generation, attempts, reset_count, ordered_by,
        created_at, updated_at, archived_at
 FROM workspaces";

const ASSIGNMENTS: &str = "SELECT id, realm_id, workspace_id, host_id, generation, workspace_gen, workload_id, placement_ref, placed_at, ready_at, released_at, release_reason
 FROM workspace_assignments";

const ARTIFACTS: &str = "SELECT id, realm_id, workspace_id, workspace_gen, store, destination, object_key, bytes, sha256, packed_by, packed_at, taken_at, removed_at
 FROM workspace_artifacts";

const SESSIONS: &str = "SELECT capability_id, realm_id, workspace_id, principal_id, device_id, host_id, workspace_gen, assignment_gen, opened_at, expires_at, ended_at, ended_reason
 FROM workspace_sessions";

const PLEDGES: &str = "SELECT id, realm_id, host_id, commitment, offered, idle_only, wording, committed_by, committed_at, withdrawn_by, withdrawn_at FROM host_commitments";

/// The columns of the research profile. There is no source byte and no artifact byte among any of
/// them, and no column that could hold one.
const SCOPES: &str = "SELECT id, realm_id, name, purpose, authorisation, authorisation_digest, authorisation_approval_id, classification, limits, version,
        supersedes, digest, generation, created_by, created_at, frozen_at, closed_at, closed_reason
 FROM research_scopes";

const ADMISSIONS: &str = "SELECT id, realm_id, scope_id, kind, subject, method, path, approval_id, admitted_by, admitted_at, expires_at, withdrawn_at, withdrawn_reason
 FROM research_admissions";

const SOURCES: &str = "SELECT id, realm_id, scope_id, admission_id, origin, reference, revision, digest, bytes, file_count, retain_until, acquired_by, acquired_at,
        verified_at, quarantined_at, disposed_at, reason
 FROM research_sources";

const PACKAGES: &str = "SELECT id, source_id, ecosystem, name, version, expected, seen, state, checked_at FROM research_dependencies";

const RESEARCH_ARTIFACTS: &str = "SELECT id, realm_id, scope_id, source_id, workload_id, name, media_type, sha256, bytes, retain_until, produced_at, disposed_at, disposed_reason
 FROM research_artifacts";

const LOOKS: &str = "SELECT id, realm_id, artifact_id, verdict, looked_by, tool, reason, sequence, looked_at FROM research_artifact_scans";

const FINDINGS: &str = "SELECT id, realm_id, scope_id, source_id, workload_id, title, component, summary, severity, state, reported_by, created_at, updated_at
 FROM research_findings";

const CROSSINGS: &str = "SELECT id, realm_id, finding_id, digest, seal, bundle_version, reviews, artifacts, scope_digest, source_digest, sealed_by, sealed_at,
        withdrawn_at, withdrawn_reason
 FROM research_crossings";

const IMPORTS: &str = "SELECT id, realm_id, crossing_digest, from_realm_id, from_realm_name, from_key_fingerprint, scope_digest, source_digest, title, severity,
        artifacts, reviews, approval_id, accepted_by, accepted_at, note, withdrawn_at, withdrawn_reason
 FROM research_imports";

fn fresh(what: &str) -> String {
    format!("{what}-{}", &crate::token()[..16])
}

fn clean(text: &str) -> String {
    text.chars().filter(|letter| !letter.is_control()).take(500).collect()
}

fn principal_without_roles(row: &Row<'_>) -> rusqlite::Result<Principal> {
    Ok(Principal {
        id: row.get(0)?,
        realm_id: row.get(1)?,
        kind: unword::<PrincipalKind>(&row.get::<_, String>(2)?, "what this account is")?,
        name: row.get(3)?,
        email: row.get(4)?,
        roles: Vec::new(),
        created_at: row.get(5)?,
        suspended_at: row.get(6)?,
    })
}

fn device_from(row: &Row<'_>) -> rusqlite::Result<Device> {
    Ok(Device {
        id: row.get(0)?,
        realm_id: row.get(1)?,
        principal_id: row.get(2)?,
        name: row.get(3)?,
        platform: row.get(4)?,
        token_hash: row.get(5)?,
        attestation: unjson(&row.get::<_, String>(6)?, "what this computer proved")?,
        enrolled_at: row.get(7)?,
        last_seen_at: row.get(8)?,
        revoked_at: row.get(9)?,
    })
}

fn host_from(row: &Row<'_>) -> rusqlite::Result<Host> {
    Ok(Host {
        id: row.get(0)?,
        realm_id: row.get(1)?,
        device_id: row.get(2)?,
        name: row.get(3)?,
        capacity: unjson::<Resources>(&row.get::<_, String>(4)?, "what this computer has")?,
        offered: unjson::<Resources>(&row.get::<_, String>(5)?, "what this computer offers")?,
        gpu_isolation: unword::<GpuIsolation>(&row.get::<_, String>(6)?, "how this card is shared")?,
        commitment: unword::<Commitment>(&row.get::<_, String>(7)?, "how this computer was committed")?,
        draining: row.get::<_, i64>(8)? != 0,
        joined_at: row.get(9)?,
    })
}

fn workload_from(row: &Row<'_>) -> rusqlite::Result<Workload> {
    Ok(Workload {
        id: row.get(0)?,
        realm_id: row.get(1)?,
        capability: unword::<Capability>(&row.get::<_, String>(2)?, "what this work is")?,
        kind: unword::<Kind>(&row.get::<_, String>(3)?, "what kind of work this is")?,
        principal_id: row.get(4)?,
        device_id: row.get(5)?,
        stage: unword::<Stage>(&row.get::<_, String>(6)?, "where this work has got to")?,
        needs: unjson::<Resources>(&row.get::<_, String>(7)?, "what this work needs")?,
        policy_version: row.get::<_, i64>(8)? as u64,
        lease_id: row.get(9)?,
        note: row.get(10)?,
        created_at: row.get(11)?,
        updated_at: row.get(12)?,
        expires_at: row.get(13)?,
    })
}

fn lease_from(row: &Row<'_>) -> rusqlite::Result<Lease> {
    Ok(Lease {
        id: row.get(0)?,
        realm_id: row.get(1)?,
        host_id: row.get(2)?,
        workload_id: row.get(3)?,
        resources: unjson::<Resources>(&row.get::<_, String>(4)?, "what this reservation holds")?,
        generation: row.get::<_, i64>(5)? as u64,
        granted_at: row.get(6)?,
        expires_at: row.get(7)?,
        released_at: row.get(8)?,
    })
}

fn approval_from(row: &Row<'_>) -> rusqlite::Result<Approval> {
    Ok(Approval {
        id: row.get(0)?,
        realm_id: row.get(1)?,
        action: row.get(2)?,
        resource_id: row.get(3)?,
        method: row.get(4)?,
        path: row.get(5)?,
        requested_by: row.get(6)?,
        requested_at: row.get(7)?,
        expires_at: row.get(8)?,
        every_time: row.get::<_, i64>(9)? != 0,
        state: unword::<State>(&row.get::<_, String>(10)?, "where this request has got to")?,
        decided_by: row.get(11)?,
        decided_at: row.get(12)?,
        self_issued: row.get::<_, Option<i64>>(13)?.unwrap_or(0) != 0,
        reason: row.get::<_, Option<String>>(14)?.unwrap_or_default(),
    })
}

fn allowance_from(row: &Row<'_>) -> rusqlite::Result<Allowance> {
    Ok(Allowance {
        id: row.get(0)?,
        realm_id: row.get(1)?,
        principal_id: row.get(2)?,
        resource_id: row.get(3)?,
        method: row.get(4)?,
        path: row.get(5)?,
        approval_id: row.get(6)?,
        approved_by: row.get(7)?,
        granted_at: row.get(8)?,
        expires_at: row.get(9)?,
    })
}

fn credential_from(row: &Row<'_>) -> rusqlite::Result<Credential> {
    Ok(Credential {
        id: row.get(0)?,
        realm_id: row.get(1)?,
        name: row.get(2)?,
        kind: unword::<Secret>(&row.get::<_, String>(3)?, "what kind of credential this is")?,
        vault: Vault { id: row.get(4)?, version: row.get::<_, i64>(5)? as u32 },
        fingerprint: row.get(6)?,
        destination: row.get(7)?,
        methods: unjson(&row.get::<_, String>(8)?, "which methods this credential allows")?,
        paths: unjson(&row.get::<_, String>(9)?, "which paths this credential allows")?,
        maximum_bytes: row.get::<_, Option<i64>>(10)?.map(|bytes| bytes as u64),
        owner_id: row.get(11)?,
        every_time: row.get::<_, i64>(12)? != 0,
        created_at: row.get(13)?,
        rotated_at: row.get(14)?,
        rotate_by: row.get(15)?,
        retired_at: row.get(16)?,
        presentation: unword::<super::credential::Kind>(&row.get::<_, String>(17)?, "how this credential travels")?,
        field: row.get(18)?,
        generation: row.get::<_, i64>(19)? as u32,
        settings: unjson(&row.get::<_, String>(20)?, "what this credential needs to make a token")?,
        query_allowed_by: row.get(21)?,
        query_allowed_at: row.get(22)?,
        // The places it may be sent are rows of their own; whoever read this credential fills
        // them in, because a credential with no list is refused rather than sent anywhere.
        destinations: Vec::new(),
    })
}

/// One brokered request, as it was recorded.
fn use_from(row: &Row<'_>) -> rusqlite::Result<Use> {
    Ok(Use {
        id: row.get(0)?,
        realm_id: row.get(1)?,
        credential_id: row.get(2)?,
        capability_id: row.get(3)?,
        approval_id: row.get(4)?,
        principal_id: row.get(5)?,
        device_id: row.get(6)?,
        workload_id: row.get(7)?,
        destination: row.get(8)?,
        method: row.get(9)?,
        path: row.get(10)?,
        request_bytes: row.get::<_, i64>(11)? as u64,
        answer_bytes: row.get::<_, Option<i64>>(12)?.map(|bytes| bytes as u64),
        status: row.get::<_, Option<i64>>(13)?.map(|status| status as u16),
        vault_id: row.get(14)?,
        vault_version: row.get::<_, i64>(15)? as u32,
        outcome: row.get(16)?,
        reason: row.get(17)?,
        policy_version: row.get::<_, i64>(18)? as u64,
        started_at: row.get(19)?,
        finished_at: row.get(20)?,
    })
}

fn grant_from(row: &Row<'_>) -> rusqlite::Result<Grant> {
    Ok(Grant {
        id: row.get(0)?,
        realm_id: row.get(1)?,
        credential_id: row.get(2)?,
        principal_id: row.get(3)?,
        methods: unjson(&row.get::<_, String>(4)?, "which methods this allows")?,
        paths: unjson(&row.get::<_, String>(5)?, "which paths this allows")?,
        granted_by: row.get(6)?,
        granted_at: row.get(7)?,
        expires_at: row.get(8)?,
    })
}

fn model_plan_from(row: &Row<'_>) -> rusqlite::Result<ModelPlan> {
    Ok(ModelPlan {
        id: row.get(0)?,
        realm_id: row.get(1)?,
        model: row.get(2)?,
        quant: row.get(3)?,
        percent: row.get::<_, i64>(4)? as u8,
        policy: unjson(&row.get::<_, String>(5)?, "the model's idle policy")?,
        target: unjson(&row.get::<_, String>(6)?, "the model's target")?,
        created_at: row.get(7)?,
    })
}

fn model_assignment_from(row: &Row<'_>) -> rusqlite::Result<ModelAssignment> {
    Ok(ModelAssignment { plan_id: row.get(0)?, host_id: row.get(1)?, assigned_at: row.get(2)? })
}

fn image_from(row: &Row<'_>) -> rusqlite::Result<Image> {
    Ok(Image {
        id: row.get(0)?,
        realm_id: row.get(1)?,
        name: row.get(2)?,
        version: row.get(3)?,
        description: row.get(4)?,
        kind: unword::<WorkspaceKind>(&row.get::<_, String>(5)?, "what kind of workspace this image builds")?,
        digest: row.get(6)?,
        source: unjson::<ImageSource>(&row.get::<_, String>(7)?, "where this image comes from")?,
        bytes: row.get::<_, Option<i64>>(8)?.map(|bytes| bytes as u64),
        shape: unjson::<Resources>(&row.get::<_, String>(9)?, "what this image needs")?,
        applications: unjson(&row.get::<_, String>(10)?, "what is installed in this image")?,
        published_by: row.get(11)?,
        published_at: row.get(12)?,
        verified_at: row.get(13)?,
        retired_at: row.get(14)?,
    })
}

fn workspace_from(row: &Row<'_>) -> rusqlite::Result<Workspace> {
    Ok(Workspace {
        id: row.get(0)?,
        realm_id: row.get(1)?,
        name: row.get(2)?,
        owner_id: row.get(3)?,
        image_id: row.get(4)?,
        image_digest: row.get(5)?,
        shape: unjson::<Resources>(&row.get::<_, String>(6)?, "what this workspace needs")?,
        access: unword::<Access>(&row.get::<_, String>(7)?, "how much this workspace may reach")?,
        quota: unjson::<Quota>(&row.get::<_, String>(8)?, "what this workspace may grow to")?,
        state: unword::<WorkspaceState>(&row.get::<_, String>(9)?, "where this workspace has got to")?,
        note: row.get(10)?,
        generation: row.get::<_, i64>(11)? as u64,
        attempts: row.get::<_, i64>(12)? as u32,
        reset_count: row.get::<_, i64>(13)? as u32,
        ordered_by: row.get(14)?,
        created_at: row.get(15)?,
        updated_at: row.get(16)?,
        archived_at: row.get(17)?,
    })
}

fn assignment_from(row: &Row<'_>) -> rusqlite::Result<Assignment> {
    Ok(Assignment {
        id: row.get(0)?,
        realm_id: row.get(1)?,
        workspace_id: row.get(2)?,
        host_id: row.get(3)?,
        generation: row.get::<_, i64>(4)? as u64,
        workspace_generation: row.get::<_, i64>(5)? as u64,
        workload_id: row.get(6)?,
        placement_ref: row.get(7)?,
        placed_at: row.get(8)?,
        ready_at: row.get(9)?,
        released_at: row.get(10)?,
        release_reason: row.get(11)?,
    })
}

fn artifact_from(row: &Row<'_>) -> rusqlite::Result<Artifact> {
    Ok(Artifact {
        id: row.get(0)?,
        realm_id: row.get(1)?,
        workspace_id: row.get(2)?,
        workspace_generation: row.get::<_, i64>(3)? as u64,
        store: unword::<ArtifactStore>(&row.get::<_, String>(4)?, "where this packed copy is kept")?,
        destination: row.get(5)?,
        object_key: row.get(6)?,
        bytes: row.get::<_, i64>(7)? as u64,
        sha256: row.get(8)?,
        packed_by: row.get(9)?,
        packed_at: row.get(10)?,
        taken_at: row.get(11)?,
        removed_at: row.get(12)?,
    })
}

fn session_from(row: &Row<'_>) -> rusqlite::Result<Session> {
    Ok(Session {
        capability_id: row.get(0)?,
        realm_id: row.get(1)?,
        workspace_id: row.get(2)?,
        principal_id: row.get(3)?,
        device_id: row.get(4)?,
        host_id: row.get(5)?,
        workspace_generation: row.get::<_, i64>(6)? as u64,
        assignment_generation: row.get::<_, i64>(7)? as u64,
        opened_at: row.get(8)?,
        expires_at: row.get(9)?,
        ended_at: row.get(10)?,
        ended_reason: row.get(11)?,
    })
}

fn pledge_from(row: &Row<'_>) -> rusqlite::Result<Pledge> {
    Ok(Pledge {
        id: row.get(0)?,
        realm_id: row.get(1)?,
        host_id: row.get(2)?,
        commitment: unword::<Commitment>(&row.get::<_, String>(3)?, "how this computer was committed")?,
        offered: unjson::<Resources>(&row.get::<_, String>(4)?, "what this computer offered")?,
        idle_only: row.get::<_, i64>(5)? != 0,
        wording: row.get(6)?,
        committed_by: row.get(7)?,
        committed_at: row.get(8)?,
        withdrawn_by: row.get(9)?,
        withdrawn_at: row.get(10)?,
    })
}

fn condition_from(row: &Row<'_>) -> rusqlite::Result<Condition> {
    Ok(Condition {
        host_id: row.get(0)?,
        on_battery: row.get::<_, i64>(1)? != 0,
        free_disk_gb: row.get(2)?,
        in_use: row.get::<_, i64>(3)? != 0,
        going_away: row.get::<_, i64>(4)? != 0,
        reported_at: row.get(5)?,
    })
}

fn event_from(row: &Row<'_>) -> rusqlite::Result<Event> {
    Ok(Event {
        sequence: row.get::<_, i64>(0)? as u64,
        id: row.get(1)?,
        realm_id: row.get(2)?,
        at: row.get(3)?,
        capability: match row.get::<_, Option<String>>(4)? {
            Some(text) => Some(unword::<Capability>(&text, "what this was about")?),
            None => None,
        },
        principal_id: row.get(5)?,
        device_id: row.get(6)?,
        workload_id: row.get(7)?,
        action: row.get(8)?,
        resource_id: row.get(9)?,
        policy_version: row.get::<_, i64>(10)? as u64,
        decision: unword::<Decision>(&row.get::<_, String>(11)?, "what was decided")?,
        reason: row.get::<_, Option<String>>(12)?.unwrap_or_default(),
        command: row.get::<_, Option<String>>(13)?,
        previous_seal: row.get(14)?,
        seal: row.get(15)?,
    })
}

fn scope_from(row: &Row<'_>) -> rusqlite::Result<super::research::Scope> {
    Ok(super::research::Scope {
        id: row.get(0)?,
        realm_id: row.get(1)?,
        name: row.get(2)?,
        purpose: row.get(3)?,
        authorisation: row.get(4)?,
        authorisation_digest: row.get(5)?,
        authorisation_approval_id: row.get(6)?,
        classification: unword::<super::research::Classification>(&row.get::<_, String>(7)?, "how sensitive this material is")?,
        limits: unjson::<super::research::Limits>(&row.get::<_, String>(8)?, "this scope's limits")?,
        version: row.get::<_, i64>(9)? as u32,
        supersedes: row.get(10)?,
        digest: row.get(11)?,
        generation: row.get::<_, i64>(12)? as u64,
        created_by: row.get(13)?,
        created_at: row.get(14)?,
        frozen_at: row.get(15)?,
        closed_at: row.get(16)?,
        closed_reason: row.get::<_, Option<String>>(17)?.unwrap_or_default(),
    })
}

fn admission_from(row: &Row<'_>) -> rusqlite::Result<super::research::Admitted> {
    Ok(super::research::Admitted {
        id: row.get(0)?,
        realm_id: row.get(1)?,
        scope_id: row.get(2)?,
        kind: unword::<super::research::Admission>(&row.get::<_, String>(3)?, "what was let in")?,
        subject: row.get(4)?,
        method: row.get(5)?,
        path: row.get(6)?,
        approval_id: row.get(7)?,
        admitted_by: row.get(8)?,
        admitted_at: row.get(9)?,
        expires_at: row.get(10)?,
        withdrawn_at: row.get(11)?,
        withdrawn_reason: row.get::<_, Option<String>>(12)?.unwrap_or_default(),
    })
}

fn source_from(row: &Row<'_>) -> rusqlite::Result<super::research::Source> {
    Ok(super::research::Source {
        id: row.get(0)?,
        realm_id: row.get(1)?,
        scope_id: row.get(2)?,
        admission_id: row.get(3)?,
        origin: unword::<super::research::Origin>(&row.get::<_, String>(4)?, "where this came from")?,
        reference: row.get(5)?,
        revision: row.get::<_, Option<String>>(6)?.unwrap_or_default(),
        digest: row.get(7)?,
        bytes: row.get::<_, i64>(8)? as u64,
        file_count: row.get::<_, i64>(9)? as u64,
        retain_until: row.get(10)?,
        acquired_by: row.get(11)?,
        acquired_at: row.get(12)?,
        verified_at: row.get(13)?,
        quarantined_at: row.get(14)?,
        disposed_at: row.get(15)?,
        reason: row.get::<_, Option<String>>(16)?.unwrap_or_default(),
    })
}

fn package_from(row: &Row<'_>) -> rusqlite::Result<super::research::Package> {
    Ok(super::research::Package {
        id: row.get(0)?,
        source_id: row.get(1)?,
        ecosystem: row.get(2)?,
        name: row.get(3)?,
        version: row.get(4)?,
        expected: row.get(5)?,
        seen: row.get(6)?,
        state: unword::<super::research::Dependency>(&row.get::<_, String>(7)?, "how this dependency checked out")?,
        checked_at: row.get(8)?,
    })
}

fn research_artifact_from(row: &Row<'_>) -> rusqlite::Result<super::research::Artifact> {
    Ok(super::research::Artifact {
        id: row.get(0)?,
        realm_id: row.get(1)?,
        scope_id: row.get(2)?,
        source_id: row.get(3)?,
        workload_id: row.get(4)?,
        name: row.get(5)?,
        media_type: row.get(6)?,
        sha256: row.get(7)?,
        bytes: row.get::<_, i64>(8)? as u64,
        retain_until: row.get(9)?,
        produced_at: row.get(10)?,
        disposed_at: row.get(11)?,
        disposed_reason: row.get::<_, Option<String>>(12)?.unwrap_or_default(),
    })
}

fn look_from(row: &Row<'_>) -> rusqlite::Result<super::research::Look> {
    Ok(super::research::Look {
        id: row.get(0)?,
        realm_id: row.get(1)?,
        artifact_id: row.get(2)?,
        verdict: unword::<super::research::Scan>(&row.get::<_, String>(3)?, "what was said about this artifact")?,
        looked_by: row.get(4)?,
        tool: row.get::<_, Option<String>>(5)?.unwrap_or_default(),
        reason: row.get::<_, Option<String>>(6)?.unwrap_or_default(),
        sequence: row.get::<_, i64>(7)? as u64,
        looked_at: row.get(8)?,
    })
}

fn finding_from(row: &Row<'_>) -> rusqlite::Result<super::research::Finding> {
    Ok(super::research::Finding {
        id: row.get(0)?,
        realm_id: row.get(1)?,
        scope_id: row.get(2)?,
        source_id: row.get(3)?,
        workload_id: row.get(4)?,
        title: row.get(5)?,
        component: row.get::<_, Option<String>>(6)?.unwrap_or_default(),
        summary: row.get::<_, Option<String>>(7)?.unwrap_or_default(),
        severity: unword::<super::research::Severity>(&row.get::<_, String>(8)?, "how serious this is")?,
        state: unword::<super::research::FindingState>(&row.get::<_, String>(9)?, "where this finding has got to")?,
        artifacts: Vec::new(),
        reported_by: row.get(10)?,
        created_at: row.get(11)?,
        updated_at: row.get(12)?,
    })
}

fn crossing_from(row: &Row<'_>) -> rusqlite::Result<super::research::SealedCrossing> {
    Ok(super::research::SealedCrossing {
        id: row.get(0)?,
        realm_id: row.get(1)?,
        finding_id: row.get(2)?,
        digest: row.get(3)?,
        seal: row.get(4)?,
        bundle_version: row.get::<_, i64>(5)? as u32,
        reviews: row.get::<_, i64>(6)? as u32,
        artifacts: row.get::<_, i64>(7)? as u32,
        scope_digest: row.get(8)?,
        source_digest: row.get(9)?,
        sealed_by: row.get(10)?,
        sealed_at: row.get(11)?,
        withdrawn_at: row.get(12)?,
        withdrawn_reason: row.get::<_, Option<String>>(13)?.unwrap_or_default(),
    })
}

fn import_from(row: &Row<'_>) -> rusqlite::Result<super::research::Import> {
    Ok(super::research::Import {
        id: row.get(0)?,
        realm_id: row.get(1)?,
        crossing_digest: row.get(2)?,
        from_realm_id: row.get(3)?,
        from_realm_name: row.get(4)?,
        from_key_fingerprint: row.get(5)?,
        scope_digest: row.get(6)?,
        source_digest: row.get(7)?,
        title: row.get(8)?,
        severity: unword::<super::research::Severity>(&row.get::<_, String>(9)?, "how serious this is")?,
        artifacts: row.get::<_, i64>(10)? as u32,
        reviews: row.get::<_, i64>(11)? as u32,
        approval_id: row.get(12)?,
        accepted_by: row.get(13)?,
        accepted_at: row.get(14)?,
        note: row.get::<_, Option<String>>(15)?.unwrap_or_default(),
        withdrawn_at: row.get(16)?,
        withdrawn_reason: row.get::<_, Option<String>>(17)?.unwrap_or_default(),
    })
}

// ---- Backups ----

/// Everything needed to put a realm back on another computer: its record, which key must be
/// supplied with it, and a check value for that key. The key itself is never in a backup.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Backup {
    pub taken_at: i64,
    pub version: u32,
    #[serde(default = "first")]
    pub schema_version: u32,
    pub key_fingerprint: String,
    /// Which vault entry holds the key, and which version of it. Not the key.
    #[serde(default)]
    pub key_id: String,
    #[serde(default = "first")]
    pub key_version: u32,
    /// The state below, sealed with the realm's key, exactly as each event is sealed.
    ///
    /// Without this a backup's history is sealed and its state is not, so anybody who can edit
    /// the file can add themselves as an administrator, leave the chain alone, and have the
    /// restore accept both. The seal is over the record as it is written here, so changing one
    /// character of one row breaks it and nobody without the key can put it back.
    #[serde(default)]
    pub record_seal: String,
    pub record: Record,
}

fn first() -> u32 {
    1
}

/// The seal over a backup's header and its state, under the realm's key.
///
/// The header is inside it because a restored realm's record of where its key lives is read back
/// and trusted, and a field nobody checks is a field anybody may edit. `key_id` and `key_version`
/// travel beside the record rather than in it, so sealing the record alone left them open to
/// whoever held the file.
fn seal_of(taken_at: i64, key_id: &str, key_version: u32, record: &Record, key: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.as_bytes()).expect("HMAC takes any key length");
    mac.update(format!("{taken_at}\n{key_id}\n{key_version}\n").as_bytes());
    mac.update(json(record).as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// The seal a build before the header was sealed would have written. Here only so that such a
/// backup is refused with a sentence that says what is wrong with it, rather than with the one
/// that means somebody edited it.
fn seal_of_record_alone(record: &Record, key: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.as_bytes()).expect("HMAC takes any key length");
    mac.update(json(record).as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Takes a backup of a realm, sealing its state with the realm's key. The key itself is never
/// written to the backup; only what it proves.
pub fn backup(record: &Record, reference: &KeyReference, key: &str, now: i64) -> Backup {
    Backup {
        taken_at: now,
        version: VERSION,
        schema_version: SCHEMA_VERSION,
        key_fingerprint: record.realm.key_fingerprint.clone(),
        key_id: reference.id.clone(),
        key_version: reference.version,
        record_seal: seal_of(now, &reference.id, reference.version, record, key),
        record: record.clone(),
    }
}

/// Checks a backup against the realm's key. The key must be the one the backup was taken under,
/// the state must be the state that was taken, and the history must still verify, or the restore
/// is refused.
pub fn restore(backup: Backup, key: &str) -> Result<(Record, KeyReference), String> {
    if backup.version > VERSION || backup.schema_version > SCHEMA_VERSION {
        return Err("This backup was taken by a newer Yougori; update Yougori to restore it".into());
    }
    if !backup.record.realm.keyed_by(key) || backup.key_fingerprint != backup.record.realm.key_fingerprint {
        return Err("That is not this grid's key; the backup cannot be restored with it".into());
    }
    // A missing seal is a refusal, not a pass. Treating an absent field as nothing to check would
    // mean an attacker closes this door by deleting one line of the file.
    if !crate::desks::same_hash(&backup.record_seal, &seal_of(backup.taken_at, &backup.key_id, backup.key_version, &backup.record, key)) {
        // A backup from a build that sealed the record alone is refused in its own words, because
        // "somebody edited this" would be the wrong thing to tell the person holding it. There is
        // no path here that accepts the older shape: the whole point of the change is that the
        // header a restored realm trusts is covered.
        if crate::desks::same_hash(&backup.record_seal, &seal_of_record_alone(&backup.record, key)) {
            return Err("This backup was taken before a backup's header was sealed, so where it says this grid's key is kept cannot be trusted. Take a fresh backup with this build.".into());
        }
        return Err("This backup's contents do not match its seal; it has been altered since it was taken".into());
    }
    backup.record.audit.verify(key).map_err(|error| format!("This backup's history does not verify: {error}"))?;
    let reference = if backup.key_id.is_empty() {
        KeyReference::for_realm(&backup.record.realm.id)
    } else {
        KeyReference { id: backup.key_id.clone(), version: backup.key_version }
    };
    Ok((backup.record, reference))
}
