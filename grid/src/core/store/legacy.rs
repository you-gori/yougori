//! The shape a realm was written in before it had a database, and how it is brought across.
//!
//! The core's first landing kept a realm in one JSON file. That shape is still the portable one:
//! it is what a backup carries, what an export writes, and what a record written by an earlier
//! build looks like on disk. Opening such a file builds the database from it and keeps the
//! original beside it, so a migration can be undone by hand.
use crate::core::{
    approval::{Allowance, Approval},
    audit::Chain,
    credential::{Credential, Grant},
    identity::{Device, Principal},
    model::{ModelAssignment, ModelPlan},
    realm::Realm,
    research::{Admitted, Artifact as ResearchArtifact, Finding, Import, Look, Package, Scope, SealedCrossing, Source, SourceFile},
    work::{Host, Lease, Workload},
    workspace::{Artifact, Assignment, Image, Pledge, Workspace},
};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// The version of this shape. Raised when the portable shape itself changes.
pub const VERSION: u32 = 1;

/// Everything one realm holds, apart from secrets, which live in the operating system's vault.
///
/// This is also what `Core::snapshot` hands back, so anything written against the first core
/// still reads the same fields.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Record {
    pub version: u32,
    pub realm: Realm,
    /// Raised whenever a policy changes, and carried by every piece of work admitted under it.
    #[serde(default = "one")]
    pub policy_version: u64,
    #[serde(default)]
    pub principals: Vec<Principal>,
    #[serde(default)]
    pub devices: Vec<Device>,
    #[serde(default)]
    pub hosts: Vec<Host>,
    #[serde(default)]
    pub leases: Vec<Lease>,
    #[serde(default)]
    pub workloads: Vec<Workload>,
    #[serde(default)]
    pub approvals: Vec<Approval>,
    /// Standing agreements an approver gave for a few hours.
    #[serde(default)]
    pub allowances: Vec<Allowance>,
    /// Credentials the realm holds on someone's behalf. Each one says where its value is kept.
    /// None of them carries a value, here or anywhere else in this shape.
    #[serde(default)]
    pub credentials: Vec<Credential>,
    /// Who may use which credential, for what.
    #[serde(default)]
    pub grants: Vec<Grant>,
    /// Model serving decisions and their sticky host placements.
    #[serde(default)]
    pub model_plans: Vec<ModelPlan>,
    #[serde(default)]
    pub model_assignments: Vec<ModelAssignment>,
    /// The prepared images workspaces are built from.
    #[serde(default)]
    pub images: Vec<Image>,
    /// The workspaces themselves: who owns each one, what it is built from and where it stands.
    /// Never what is inside one.
    #[serde(default)]
    pub workspaces: Vec<Workspace>,
    /// Where each workspace has been placed, which is also the trail back to the computers that
    /// have held its data.
    #[serde(default)]
    pub assignments: Vec<Assignment>,
    /// Where a workspace's packed-up data waits: a key and a checksum, never the data.
    #[serde(default)]
    pub artifacts: Vec<Artifact>,
    /// How each computer was committed to the realm, in the words that were agreed.
    #[serde(default)]
    pub commitments: Vec<Pledge>,
    // The research profile. These are added as fields that default to empty rather than as a new
    // version of this shape: a record written before they existed reads back with them empty, and
    // a record written now is read by a build that does not know them without complaint. A version
    // bump would have had to be owned by one profile, and three profiles cannot each own one.
    /// What each research realm was allowed to study, and under what limits.
    #[serde(default)]
    pub scopes: Vec<Scope>,
    /// Everything explicitly let into a research scope, and the agreement each came from.
    #[serde(default)]
    pub admissions: Vec<Admitted>,
    /// The material acquired for a scope. Never a byte of it; where it came from and what it
    /// hashed to.
    #[serde(default)]
    pub sources: Vec<Source>,
    /// Each source's manifest, as (source id, file) pairs.
    #[serde(default)]
    pub source_files: Vec<(String, SourceFile)>,
    #[serde(default)]
    pub dependencies: Vec<Package>,
    /// What research runs produced: names, digests and sizes.
    #[serde(default)]
    pub research_artifacts: Vec<ResearchArtifact>,
    /// Who looked at each artifact and what they said.
    #[serde(default)]
    pub looks: Vec<Look>,
    #[serde(default)]
    pub findings: Vec<Finding>,
    /// Which request was asked about which finding, and when.
    #[serde(default)]
    pub reviews: Vec<(String, String, i64)>,
    /// The documents sealed to be carried out of a research realm.
    #[serde(default)]
    pub crossings: Vec<SealedCrossing>,
    /// The research results a company realm accepted, on its own decision.
    #[serde(default)]
    pub imports: Vec<Import>,
    /// What a bridge's import created, so that a backup carries the only thing that can undo one.
    /// Added as a field that defaults to empty rather than as a new version of this shape, the
    /// way the research vectors were: a record written before it existed reads back with it
    /// empty, and a record written now is read by a build that does not know it without
    /// complaint.
    #[serde(default)]
    pub bridge_imports: Vec<crate::core::compat::BridgeImport>,
    #[serde(default)]
    pub audit: Chain,
}

fn one() -> u64 {
    1
}

impl Record {
    pub fn new(realm: Realm) -> Record {
        Record {
            version: VERSION,
            realm,
            policy_version: 1,
            principals: Vec::new(),
            devices: Vec::new(),
            hosts: Vec::new(),
            leases: Vec::new(),
            workloads: Vec::new(),
            approvals: Vec::new(),
            allowances: Vec::new(),
            credentials: Vec::new(),
            grants: Vec::new(),
            model_plans: Vec::new(),
            model_assignments: Vec::new(),
            images: Vec::new(),
            workspaces: Vec::new(),
            assignments: Vec::new(),
            artifacts: Vec::new(),
            commitments: Vec::new(),
            scopes: Vec::new(),
            admissions: Vec::new(),
            sources: Vec::new(),
            source_files: Vec::new(),
            dependencies: Vec::new(),
            research_artifacts: Vec::new(),
            looks: Vec::new(),
            findings: Vec::new(),
            reviews: Vec::new(),
            crossings: Vec::new(),
            imports: Vec::new(),
            bridge_imports: Vec::new(),
            audit: Chain::default(),
        }
    }
}

/// Writes `record` so that a crash can never leave a partial file in its place.
pub fn save(path: &Path, record: &Record) -> Result<(), String> {
    use std::io::Write;
    if let Some(folder) = path.parent() {
        std::fs::create_dir_all(folder).map_err(|error| format!("Cannot open the grid's folder: {error}"))?;
    }
    let bytes = serde_json::to_vec_pretty(record).map_err(|error| error.to_string())?;
    let temporary = path.with_extension("writing");
    {
        let mut file = std::fs::File::create(&temporary).map_err(|error| format!("Cannot write the grid's record: {error}"))?;
        file.write_all(&bytes).map_err(|error| format!("Cannot write the grid's record: {error}"))?;
        file.sync_all().map_err(|error| format!("Cannot flush the grid's record: {error}"))?;
    }
    std::fs::rename(&temporary, path).map_err(|error| format!("Cannot replace the grid's record: {error}"))?;
    Ok(())
}

/// Reads a record, bringing it up to this build's shape if it was written by an older one. The
/// file is read only; the caller decides what to do with what comes back.
pub fn load(path: &Path) -> Result<Record, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("Cannot read the grid's record: {error}"))?;
    read(&bytes)
}

/// The same, from bytes already in hand.
pub fn read(bytes: &[u8]) -> Result<Record, String> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| "The grid's record is damaged".to_owned())?;
    let found = found_version(&value);
    if found > VERSION {
        return Err(format!("This grid's record was written by a newer Yougori (version {found}); update Yougori to open it"));
    }
    if found == VERSION {
        return serde_json::from_value(value).map_err(|error| format!("The grid's record is damaged: {error}"));
    }
    let migrated = migrate(value, found)?;
    serde_json::from_value(migrated).map_err(|error| format!("The grid's record could not be migrated: {error}"))
}

/// The version a file says it was written in.
pub fn found_version(value: &serde_json::Value) -> u32 {
    value["version"].as_u64().unwrap_or(0) as u32
}

/// Applies every step from `from` up to this build's shape, on a copy. A step that fails leaves
/// the file on disk untouched, because nothing is written here at all.
fn migrate(mut value: serde_json::Value, from: u32) -> Result<serde_json::Value, String> {
    let mut at = from;
    while at < VERSION {
        value = step(value, at)?;
        at += 1;
        value["version"] = serde_json::json!(at);
    }
    Ok(value)
}

/// One step: from version `at` to `at + 1`.
fn step(value: serde_json::Value, at: u32) -> Result<serde_json::Value, String> {
    match at {
        // Version 0 is anything written before the core existed; there is nothing to carry yet,
        // and the profiles' own migrations bring their records across.
        0 => Ok(value),
        other => Err(format!("No migration from version {other}")),
    }
}

/// Whether these bytes are a database rather than a record. SQLite files start with a fixed
/// string, so the two are told apart without guessing from the file's name.
pub fn is_database(bytes: &[u8]) -> bool {
    bytes.starts_with(b"SQLite format 3\0")
}

/// What opening a record would bring across, counted without writing anything.
#[derive(Clone, Debug)]
pub struct Rehearsal {
    pub version: u32,
    pub realm_id: String,
    pub realm_name: String,
    pub principals: usize,
    pub devices: usize,
    pub hosts: usize,
    pub workloads: usize,
    pub leases: usize,
    pub requests: usize,
    pub decided: usize,
    pub allowances: usize,
    pub credentials: usize,
    pub workspaces: usize,
    pub images: usize,
    pub events: usize,
    /// Where the database would be built, and where the record would be kept afterwards.
    pub database: std::path::PathBuf,
    pub keeping: std::path::PathBuf,
    /// Anything worth saying before it is run. Never a reason to run it blindly.
    pub notes: Vec<String>,
}

impl Rehearsal {
    /// A short report for a person about to run it.
    pub fn describe(&self) -> String {
        let mut lines = vec![
            format!("{} (version {}) would be brought into {}", self.realm_name, self.version, self.database.display()),
            format!("{} people, {} computers, {} offering resources", self.principals, self.devices, self.hosts),
            format!("{} pieces of work and {} reservations", self.workloads, self.leases),
            format!("{} requests, {} of them decided, and {} standing allowances", self.requests, self.decided, self.allowances),
            format!("{} credentials, none of which carries a value", self.credentials),
            format!("{} workspaces built from {} images, none of which carries anybody's files", self.workspaces, self.images),
            format!("{} events, carried across sealed as they are", self.events),
            format!("the record would be kept at {}", self.keeping.display()),
        ];
        lines.extend(self.notes.iter().cloned());
        lines.join("\n")
    }
}

/// Reads a record and says what opening it would do, writing nothing at all. The key is checked
/// here as well, so a rehearsal with the wrong key fails in the same way the migration would.
pub fn rehearse(path: &Path, key: &str, database: &Path) -> Result<Rehearsal, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("Cannot read the grid's record: {error}"))?;
    if is_database(&bytes) {
        return Err("That is already a grid's database; there is nothing to bring across".into());
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| "The grid's record is damaged".to_owned())?;
    let version = found_version(&value);
    let record = read(&bytes)?;
    if !record.realm.keyed_by(key) {
        return Err("That is not this grid's key".into());
    }
    record.audit.verify(key).map_err(|error| format!("This record's history does not verify: {error}"))?;
    let decided = record.approvals.iter().filter(|request| request.decided_by.is_some()).count();
    let mut notes = Vec::new();
    if database.exists() {
        notes.push("A database of that name is already here; opening the record would use that instead".to_owned());
    }
    let lapsed = record.approvals.len() - decided - record.approvals.iter().filter(|request| request.state == crate::core::approval::State::Waiting).count();
    if lapsed > 0 {
        notes.push(format!("{lapsed} requests ran out without an answer; they come across as they are, with nobody named"));
    }
    Ok(Rehearsal {
        version,
        realm_id: record.realm.id.clone(),
        realm_name: record.realm.name.clone(),
        principals: record.principals.len(),
        devices: record.devices.len(),
        hosts: record.hosts.len(),
        workloads: record.workloads.len(),
        leases: record.leases.len(),
        requests: record.approvals.len(),
        decided,
        allowances: record.allowances.len(),
        credentials: record.credentials.len(),
        workspaces: record.workspaces.len(),
        images: record.images.len(),
        events: record.audit.events.len(),
        database: database.to_owned(),
        keeping: path.with_extension(format!("v{version}.backup")),
        notes,
    })
}
