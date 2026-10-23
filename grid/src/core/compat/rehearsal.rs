//! The whole move, run on copies, so what it would do is known before anybody does it.
//!
//! A counting rehearsal says how many accounts, computers and workspaces an import would create.
//! That is useful and it is not enough: it never runs the import, so it never finds the name a
//! label check refuses, the checksum that is not one, the quota that will not fit, or the
//! rollback that takes out a row the import did not put in. This runs the real thing against
//! copies and then undoes it, and compares the realm table by table before and after.
//!
//! What it copies, and how:
//!
//! - a product's record is one JSON file, so it is copied with the file system;
//! - a realm is a SQLite database in write-ahead logging with every commit flushed, so it is
//!   copied with SQLite's own `VACUUM INTO`, which gives one consistent file with no journal
//!   beside it and does not stop the live database. Reading the file instead would take a torn
//!   page out from under a writer.
//!
//! What has not been measured, and is therefore not claimed: how long any of this takes on a
//! grid with a real number of computers and desks, and whether taking a consistent copy of a
//! realm that is under write load contends with the writers. No realm in this repository is under
//! load, and the runbook keeps both as open questions rather than quoting a number.
use super::{
    backup::Manifest,
    frozen::{self, Product},
    AccessRehearsal, BountyRehearsal, Sources,
};
use crate::core::{realm::Capability, realm::RealmKind, Core};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The version of the report's own shape. Version 2 adds what a realm will not let an undo
/// delete, which a report that only said "did not come back" could not tell from a defect.
pub const VERSION: u32 = 2;

/// A copy of everything one deployment holds, taken without stopping anything.
#[derive(Clone, Debug)]
pub struct Copies {
    pub folder: PathBuf,
    pub records: Vec<(Product, PathBuf)>,
    pub realms: Vec<PathBuf>,
    pub taken_at: i64,
}

impl Copies {
    fn record(&self, product: Product) -> Option<&Path> {
        self.records.iter().find(|(known, _)| *known == product).map(|(_, path)| path.as_path())
    }
}

/// Copies every record and every realm database the caller named into `into`.
///
/// A record is copied with the file system. A realm is copied with `VACUUM INTO`, which never
/// migrates it and never changes what it holds, so what comes out the other side is the realm at
/// the version it was at.
///
/// What is not claimed, because it is not true: the connection that takes the copy is read-write,
/// as `VACUUM INTO` has to be, and on a realm in write-ahead logging SQLite check-points when the
/// last connection closes, folding frames a crashed writer left in the journal into the main file
/// and removing the two files beside it. The realm's contents are untouched by that; its bytes
/// are not necessarily. `Store::copy_of` says the same thing where it happens.
pub fn take_copies(sources: &Sources, into: &Path, now: i64) -> Result<Copies, String> {
    std::fs::create_dir_all(into).map_err(|error| format!("Cannot open the folder for the copies: {error}"))?;
    let mut records = Vec::new();
    for (product, from) in sources.present() {
        let name = format!("{}.json", product.word());
        let to = into.join(&name);
        std::fs::copy(from, &to).map_err(|error| format!("Cannot copy {}'s record: {error}", product.name()))?;
        records.push((product, to));
    }
    let mut realms = Vec::new();
    for (index, realm) in sources.realms.iter().enumerate() {
        let to = into.join(format!("realm-{index}.db"));
        crate::core::store::Store::copy_of(realm, &to)?;
        realms.push(to);
    }
    Ok(Copies { folder: into.to_owned(), records, realms, taken_at: now })
}

/// One record checked against what the register says it should be.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FrozenCheck {
    pub product: String,
    pub path: String,
    pub expected_version: u32,
    pub found_version: Option<u32>,
    /// What the bytes themselves said they are.
    pub shape: Option<String>,
    pub reads: bool,
    pub notes: Vec<String>,
}

impl FrozenCheck {
    pub fn agrees(&self) -> bool {
        self.reads && self.found_version == Some(self.expected_version)
    }
}

/// An import run on a copy and then undone, with what it wrote and whether the realm came back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Trial {
    pub product: String,
    /// What the import created, by kind.
    pub wrote: Vec<(String, usize)>,
    /// The realm's own history still verified after the import.
    pub audit_verified: bool,
    /// Every table of the realm, apart from the history and anything in `kept`, held exactly what
    /// it held before.
    pub returned_clean: bool,
    /// The tables that did not, with what changed, when it did not come back clean.
    pub differences: Vec<String>,
    /// Tables the realm's own rules will not let an undo delete, named before the trial ran. A
    /// research realm closes a scope, withdraws an admission and disposes of a source, and never
    /// deletes any of them, so a research import is undone by deleting the realm it created. A
    /// trial that counted those as differences would read as a defect, and a trial that compared
    /// them silently would read as though they had come back.
    #[serde(default)]
    pub kept: Vec<String>,
    pub refusal: Option<String>,
}

/// What a rehearsal found.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub rehearsal: u32,
    pub taken_at: i64,
    pub app_version: String,
    pub frozen: Vec<FrozenCheck>,
    pub neo: Option<super::Rehearsal>,
    pub desks: Option<super::DeskRehearsal>,
    pub swarm: Option<BountyRehearsal>,
    pub access: Option<AccessRehearsal>,
    pub trials: Vec<Trial>,
    /// What would have stopped the move, in the exact words it would use.
    pub refusals: Vec<String>,
    /// What this rehearsal could not do at all, and why not.
    pub not_rehearsed: Vec<String>,
    pub notes: Vec<String>,
    /// The backup this rehearsal was run beside, when the caller took one.
    pub backup: Option<Manifest>,
}

impl Report {
    /// No refusal, every frozen record as the register says, every trial back where it started.
    ///
    /// A table in a trial's `kept` is not a trial that failed: it is a table the realm's own rules
    /// will not let an undo delete, named before the trial ran. What a bridge cannot carry at all
    /// is in `not_rehearsed`, and neither of those makes a report dirty, because not carrying
    /// something is not the same as having tried and failed.
    pub fn clean(&self) -> bool {
        self.refusals.is_empty() && self.frozen.iter().all(FrozenCheck::agrees) && self.trials.iter().all(|trial| trial.returned_clean && trial.audit_verified && trial.refusal.is_none())
    }

    pub fn describe(&self) -> String {
        let mut lines = vec![format!("rehearsed on copies at {}, by {}", self.taken_at, self.app_version)];
        for check in &self.frozen {
            lines.push(match (check.agrees(), check.found_version) {
                (true, Some(version)) => format!("{} at {} is version {version}, as the register says", check.product, check.path),
                (_, found) => format!("{} at {} is version {:?} and the register says {}", check.product, check.path, found, check.expected_version),
            });
        }
        if let Some(neo) = &self.neo {
            lines.push(neo.describe());
        }
        if let Some(desks) = &self.desks {
            lines.push(desks.describe());
        }
        if let Some(swarm) = &self.swarm {
            lines.push(swarm.describe());
        }
        if let Some(access) = &self.access {
            lines.push(access.describe());
        }
        for trial in &self.trials {
            let wrote: Vec<String> = trial.wrote.iter().map(|(what, how_many)| format!("{how_many} {what}")).collect();
            lines.push(match &trial.refusal {
                Some(refusal) => format!("{}: the import refused: {refusal}", trial.product),
                None => format!(
                    "{}: wrote {}, the history {}, and the realm {} after it was undone",
                    trial.product,
                    wrote.join(", "),
                    if trial.audit_verified { "verified" } else { "DID NOT VERIFY" },
                    if trial.returned_clean { "came back exactly as it was" } else { "DID NOT COME BACK AS IT WAS" }
                ),
            });
            if !trial.kept.is_empty() {
                lines.push(format!("  what this realm's own rules will not let an undo delete, and which was not compared: {}", trial.kept.join(", ")));
            }
            lines.extend(trial.differences.iter().map(|line| format!("  {line}")));
        }
        lines.extend(self.refusals.iter().map(|line| format!("would stop the move: {line}")));
        lines.extend(self.not_rehearsed.iter().map(|line| format!("not rehearsed: {line}")));
        lines.extend(self.notes.iter().cloned());
        lines.join("\n")
    }
}

/// Runs the whole move against the copies and reports what it did.
///
/// Every failure becomes a line in the report rather than ending it, so one bad desk does not
/// hide the state of the other three products. The only things that end it are a folder that
/// cannot be made and a copy that is not there.
pub fn rehearse_all(copies: &Copies, app_version: &str, now: i64) -> Result<Report, String> {
    let mut report = Report {
        rehearsal: VERSION,
        taken_at: now,
        app_version: app_version.chars().filter(|letter| letter.is_ascii_alphanumeric() || *letter == '.' || *letter == '-').take(32).collect(),
        frozen: Vec::new(),
        neo: None,
        desks: None,
        swarm: None,
        access: None,
        trials: Vec::new(),
        refusals: Vec::new(),
        not_rehearsed: Vec::new(),
        notes: vec![
            "nothing here touched the records this was copied from: every read was of a copy, and every write was inside the rehearsal's own folder".to_owned(),
            "how long each of these takes on a grid with a real number of computers and desks is not measured here, and neither is whether taking a copy of a realm under write load contends with its writers".to_owned(),
        ],
        backup: None,
    };

    for (product, path) in &copies.records {
        report.frozen.push(check(*product, path));
    }

    if let Some(path) = copies.record(Product::NeoGrid) {
        match crate::hub::load(path) {
            Ok(record) => {
                report.neo = Some(super::neo::rehearse(&record));
                report.trials.push(trial_neo(&record, &copies.folder.join("trial-neo"), now));
            }
            Err(refusal) => report.refusals.push(format!("the Closed Neo Grid's record: {refusal}")),
        }
    }
    if let Some(path) = copies.record(Product::SandboxGrid) {
        match crate::hub::load(path) {
            Ok(record) => {
                match super::desks::rehearse(&record, now) {
                    Ok(rehearsal) => report.desks = Some(rehearsal),
                    Err(refusal) => report.refusals.push(format!("the Sandbox Grid's record: {refusal}")),
                }
                report.trials.push(trial_desks(&record, &copies.folder.join("trial-desks"), now));
            }
            Err(refusal) => report.refusals.push(format!("the Sandbox Grid's record: {refusal}")),
        }
    }
    if let Some(path) = copies.record(Product::SwarmMining) {
        match crate::bounty::load(path) {
            Ok(record) => {
                match super::bounty::rehearse(&record, now) {
                    Ok(rehearsal) => report.swarm = Some(rehearsal),
                    Err(refusal) => report.refusals.push(format!("the bounty host's record: {refusal}")),
                }
                report.trials.push(trial_bounty(&record, &copies.folder.join("trial-bounty"), now));
                report.not_rehearsed.extend(super::bounty::missing().iter().map(|line| format!("Swarm Mining: {line}")));
            }
            Err(refusal) => report.refusals.push(format!("the bounty host's record: {refusal}")),
        }
    }
    if let Some(path) = copies.record(Product::AccessGrid) {
        match crate::access::hub::load(path) {
            Ok(record) => {
                // A rehearsal is run against copies of the products' records, and the Access
                // Grid's activity log is a file of its own that nothing copies here. So the
                // decisions in it are neither counted nor rehearsed, which is what the lines below
                // say; an import that carries them is the one an undo cannot reach, and it is not
                // the one rehearsed.
                match super::access::rehearse(&record, &[], now) {
                    Ok(rehearsal) => report.access = Some(rehearsal),
                    Err(refusal) => report.refusals.push(format!("the Access Grid's record: {refusal}")),
                }
                report.trials.push(trial_access(&record, &copies.folder.join("trial-access"), now));
                report.not_rehearsed.extend(super::access::missing().iter().map(|line| format!("the Access Grid: {line}")));
                report
                    .not_rehearsed
                    .push("the Access Grid: its activity log is a file of its own, which a rehearsal does not copy, so the decisions in it are neither counted here nor brought across in this trial".to_owned());
            }
            Err(refusal) => report.refusals.push(format!("the Access Grid's record: {refusal}")),
        }
    }
    for realm in &copies.realms {
        if let Err(refusal) = crate::core::store::Store::open_for_reading(realm).and_then(|store| store.version()) {
            report.refusals.push(format!("a realm's database: {refusal}"));
        }
    }
    Ok(report)
}

/// One record against the register.
fn check(product: Product, path: &Path) -> FrozenCheck {
    let contract = frozen::contracts().iter().find(|contract| contract.product == product).expect("every shipped product has a frozen contract");
    let mut check = FrozenCheck {
        product: product.word().to_owned(),
        path: contract.path.to_owned(),
        expected_version: contract.version,
        found_version: None,
        shape: None,
        reads: false,
        notes: Vec::new(),
    };
    let Ok(bytes) = std::fs::read(path) else {
        check.notes.push("the copy could not be read".to_owned());
        return check;
    };
    check.shape = frozen::recognise(&bytes).map(|shape| shape.name().to_owned());
    match product {
        Product::NeoGrid | Product::SandboxGrid => match crate::hub::read(&bytes) {
            Ok(record) => {
                check.reads = true;
                check.found_version = Some(u32::from(record.version));
            }
            Err(refusal) => check.notes.push(refusal),
        },
        Product::SwarmMining => match crate::bounty::read(&bytes) {
            Ok(record) => {
                check.reads = true;
                check.found_version = Some(u32::from(record.version));
            }
            Err(refusal) => check.notes.push(refusal),
        },
        Product::AccessGrid => match serde_json::from_slice::<crate::access::hub::Record>(&bytes) {
            Ok(record) => {
                check.reads = true;
                check.found_version = Some(u32::from(record.version));
            }
            Err(_) => check.notes.push("The Access Grid's settings are damaged".to_owned()),
        },
        Product::Core => match crate::core::store::legacy::read(&bytes) {
            Ok(record) => {
                check.reads = true;
                check.found_version = Some(record.version);
            }
            Err(refusal) => check.notes.push(refusal),
        },
    }
    check
}

/// A throwaway realm for one trial, in a folder this owns and empties.
///
/// Research is the one that needs a realm of its own kind: `Capability::allowed_in` refuses it in
/// a company realm and the realm's own database says the same, so a trial of the bounty bridge in
/// a company realm would be a trial of the refusal and not of the bridge.
fn scratch(folder: &Path, capability: Capability, now: i64) -> Result<Core, String> {
    let _ = std::fs::remove_dir_all(folder);
    std::fs::create_dir_all(folder).map_err(|error| format!("Cannot open the folder for the rehearsal: {error}"))?;
    let kind = if capability == Capability::Research { RealmKind::Research } else { RealmKind::Primary };
    Core::create(&folder.join("rehearsal.db"), "rehearsal", kind, &[capability], &"a".repeat(64), now)
}

/// Brings the Closed Neo Grid across on a copy, checks the history, takes it out again, and says
/// whether the realm came back exactly as it was.
fn trial_neo(record: &crate::hub::Record, folder: &Path, now: i64) -> Trial {
    let mut trial = Trial {
        product: Product::NeoGrid.word().to_owned(),
        wrote: Vec::new(),
        audit_verified: false,
        returned_clean: false,
        differences: Vec::new(),
        kept: Vec::new(),
        refusal: None,
    };
    let mut core = match scratch(folder, Capability::Models, now) {
        Ok(core) => core,
        Err(refusal) => {
            trial.refusal = Some(refusal);
            return trial;
        }
    };
    let before = core.store.tally().unwrap_or_default();
    match super::neo::import(&mut core, "owner", record, now) {
        Ok(imported) => {
            trial.wrote = vec![
                ("accounts".to_owned(), 1),
                ("computers".to_owned(), imported.computers.len()),
                ("model plans".to_owned(), imported.plans.len()),
                ("computers keeping the model they had".to_owned(), imported.assignments),
            ];
            trial.audit_verified = core.verify_audit().is_ok();
            if let Err(refusal) = super::neo::roll_back(&mut core, "owner", &imported, now + 1) {
                trial.refusal = Some(refusal);
            }
        }
        Err(refusal) => trial.refusal = Some(refusal),
    }
    settle(&mut trial, &core, &before);
    drop(core);
    let _ = std::fs::remove_dir_all(folder);
    trial
}

/// The same for the Sandbox Grid.
fn trial_desks(record: &crate::hub::Record, folder: &Path, now: i64) -> Trial {
    let mut trial = Trial {
        product: Product::SandboxGrid.word().to_owned(),
        wrote: Vec::new(),
        audit_verified: false,
        returned_clean: false,
        differences: Vec::new(),
        kept: Vec::new(),
        refusal: None,
    };
    let mut core = match scratch(folder, Capability::Workspaces, now) {
        Ok(core) => core,
        Err(refusal) => {
            trial.refusal = Some(refusal);
            return trial;
        }
    };
    let before = core.store.tally().unwrap_or_default();
    match super::desks::import(&mut core, "owner", record, now) {
        Ok(imported) => {
            trial.wrote = vec![
                ("accounts".to_owned(), imported.people.len() + usize::from(imported.principal_id.is_some())),
                ("computers".to_owned(), imported.computers.len()),
                ("commitments".to_owned(), imported.commitments.len()),
                ("images".to_owned(), imported.images.len()),
                ("workspaces".to_owned(), imported.workspaces.len()),
            ];
            trial.audit_verified = core.verify_audit().is_ok();
            if let Err(refusal) = super::desks::roll_back(&mut core, "owner", &imported, now + 1) {
                trial.refusal = Some(refusal);
            }
        }
        Err(refusal) => trial.refusal = Some(refusal),
    }
    settle(&mut trial, &core, &before);
    drop(core);
    let _ = std::fs::remove_dir_all(folder);
    trial
}

/// The same for the Access Grid, with no line of the hub's own log carried.
///
/// The log is not in the copies a rehearsal takes, and an import that carried a decision out of it
/// could not be taken back out again, so the trial is of the import an administrator can undo.
fn trial_access(record: &crate::access::hub::Record, folder: &Path, now: i64) -> Trial {
    let mut trial = Trial {
        product: Product::AccessGrid.word().to_owned(),
        wrote: Vec::new(),
        audit_verified: false,
        returned_clean: false,
        differences: Vec::new(),
        kept: Vec::new(),
        refusal: None,
    };
    let mut core = match scratch(folder, Capability::Credentials, now) {
        Ok(core) => core,
        Err(refusal) => {
            trial.refusal = Some(refusal);
            return trial;
        }
    };
    let before = core.store.tally().unwrap_or_default();
    match super::access::import(&mut core, "owner", record, &[], now) {
        Ok(imported) => {
            trial.wrote = vec![
                ("accounts".to_owned(), imported.people.len() + usize::from(imported.principal_id.is_some())),
                ("computers".to_owned(), imported.devices.len()),
                ("credentials".to_owned(), imported.credentials.len()),
                ("permissions to use one".to_owned(), imported.grants.len()),
            ];
            trial.audit_verified = core.verify_audit().is_ok();
            if let Err(refusal) = super::access::roll_back(&mut core, "owner", &imported, now + 1) {
                trial.refusal = Some(refusal);
            }
        }
        Err(refusal) => trial.refusal = Some(refusal),
    }
    settle(&mut trial, &core, &before);
    drop(core);
    let _ = std::fs::remove_dir_all(folder);
    trial
}

/// The same for Swarm Mining, into a research realm of its own.
///
/// Nothing here starts a worker, offers work or reaches a network. The only thing done with the
/// published files is decoding and hashing them, through the product's own snapshot.
fn trial_bounty(record: &crate::bounty::Record, folder: &Path, now: i64) -> Trial {
    let mut trial = Trial {
        product: Product::SwarmMining.word().to_owned(),
        wrote: Vec::new(),
        audit_verified: false,
        returned_clean: false,
        differences: Vec::new(),
        kept: super::bounty::kept_by_the_realm().iter().map(|table| (*table).to_owned()).collect(),
        refusal: None,
    };
    let mut core = match scratch(folder, Capability::Research, now) {
        Ok(core) => core,
        Err(refusal) => {
            trial.refusal = Some(refusal);
            return trial;
        }
    };
    let before = core.store.tally().unwrap_or_default();
    match super::bounty::import(&mut core, "owner", record, now) {
        Ok(imported) => {
            trial.wrote = vec![
                ("accounts".to_owned(), imported.members.len() + 1),
                ("computers".to_owned(), imported.computers.len()),
                ("draft research scopes".to_owned(), 1),
                ("findings".to_owned(), imported.findings.len()),
            ];
            trial.audit_verified = core.verify_audit().is_ok();
            if let Err(refusal) = super::bounty::roll_back(&mut core, "owner", &imported, now + 1) {
                trial.refusal = Some(refusal);
            }
        }
        Err(refusal) => trial.refusal = Some(refusal),
    }
    settle(&mut trial, &core, &before);
    drop(core);
    let _ = std::fs::remove_dir_all(folder);
    trial
}

/// Compares the realm after the undo with the realm before the import, table by table.
///
/// This is the check that catches what counting cannot: a rollback that leaves a row behind, or
/// takes out one the import never put in. The history is left out of the comparison because it
/// legitimately grows, which `Store::tally` says in its own words.
fn settle(trial: &mut Trial, core: &Core, before: &std::collections::BTreeMap<String, (usize, String)>) {
    let after = match core.store.tally() {
        Ok(after) => after,
        Err(refusal) => {
            trial.differences.push(refusal);
            return;
        }
    };
    let kept = trial.kept.clone();
    for (table, (rows, digest)) in after.iter().filter(|(table, _)| !kept.contains(table)) {
        match before.get(table) {
            Some((was_rows, was_digest)) if was_rows == rows && was_digest == digest => {}
            Some((was_rows, _)) if was_rows != rows => trial.differences.push(format!("{table} held {was_rows} rows before the import and holds {rows} now")),
            // The same number of rows and not the same rows, which is the case this check exists
            // for: a rollback that bumped a generation, flipped a time or rewrote a computer's row
            // leaves the counts alone. Saying the same number twice would hide exactly that.
            Some(_) => trial.differences.push(format!("{table} holds the same {rows} rows it held before the import, but their contents are not the same")),
            None => trial.differences.push(format!("{table} is a table the realm did not have before")),
        }
    }
    for table in before.keys().filter(|table| !kept.contains(table)) {
        if !after.contains_key(table) {
            trial.differences.push(format!("{table} is a table the realm no longer has"));
        }
    }
    trial.returned_clean = trial.differences.is_empty() && trial.refusal.is_none();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::realm::Capability;

    fn trial() -> Trial {
        Trial { product: "neo".to_owned(), wrote: Vec::new(), audit_verified: true, returned_clean: false, differences: Vec::new(), kept: Vec::new(), refusal: None }
    }

    /// PROVES that a rollback which rewrote a row without changing how many there are is reported
    /// as what it was. That is the case this whole check exists for: a generation bumped, a time
    /// flipped, a computer's row rewritten. The counts are equal in every one of them, and a
    /// sentence built out of the counts would say the same number twice and name nothing.
    ///
    /// DOES NOT PROVE which row differs or how. `Store::tally` keeps a count and a digest per
    /// table, deliberately, because keeping the rows would put a copy of the realm in a report
    /// somebody carries off the computer. The report says which table to look in.
    #[test]
    fn a_rollback_that_changed_a_row_without_changing_how_many_says_so() {
        let folder = tempfile::tempdir().unwrap();
        let now = 1_000;
        let key = "e".repeat(64);
        let mut core = Core::create(&folder.path().join("realm.db"), "Acme", RealmKind::Primary, &[Capability::Models], &key, now).unwrap();
        let person = core
            .add_principal("owner", crate::core::identity::PrincipalKind::Person, "Ada", &[crate::core::identity::Role::Operator], now)
            .unwrap();
        let before = core.store.tally().unwrap();

        // Nothing is added or removed: the account that was there is still there, rewritten.
        core.suspend_principal("owner", &person.id, "on leave", now + 1).unwrap();
        let mut rewritten = trial();
        settle(&mut rewritten, &core, &before);
        assert!(!rewritten.returned_clean);
        assert!(
            rewritten.differences.iter().any(|said| said.contains("principals holds the same 1 rows it held before the import, but their contents are not the same")),
            "a row rewritten has to read as a row rewritten: {:?}",
            rewritten.differences
        );

        // And a row added still reads as a count that moved, which is the other sentence.
        core.add_principal("owner", crate::core::identity::PrincipalKind::Person, "Grace", &[crate::core::identity::Role::Operator], now + 2).unwrap();
        let mut added = trial();
        settle(&mut added, &core, &before);
        assert!(
            added.differences.iter().any(|said| said.contains("principals held 1 rows before the import and holds 2 now")),
            "{:?}",
            added.differences
        );

        // A realm nothing touched comes back clean, which is what a trial is looking for.
        let settled = core.store.tally().unwrap();
        let mut clean = trial();
        settle(&mut clean, &core, &settled);
        assert!(clean.returned_clean && clean.differences.is_empty(), "{:?}", clean.differences);
        core.close().unwrap();
    }
}
