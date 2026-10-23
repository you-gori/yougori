//! The stages a product moves in, what undoes each one, how long the old record is kept, and the
//! reading tools that never go away.
//!
//! Eight stages, one profile at a time, each one undone by something written down beside it. Two
//! properties already true of the bridges are what make the last four reversible at all, and they
//! are quoted here because they are the whole argument:
//!
//! - **no bridge ever writes a hub's record.** `rehearse`, `import`, `roll_back` and `compare`
//!   all take `&hub::Record`, and the comparisons run the hub's own placement on a copy. So after
//!   a cutover the grid on the hub is still byte for byte the grid it was, and going back is a
//!   setting rather than a restore;
//! - **an import records exactly what it created**, including the case where it reused something
//!   another bridge had already brought in, so taking it out takes out what it put in and nothing
//!   else.
//!
//! Both of those are properties of the bridges, and neither is reachable from a command line
//! today. Nothing in `src-tauri` or `cli` calls any of the four imports, any of their roll backs
//! or `compat::undo_for`: the only thing that runs them is the rehearsal, on copies. So recording
//! the import stage says where an administrator stands and moves nothing, and the undo quoted
//! above is a property of code nobody can yet run rather than a verb anybody can type.
//! `Stage::changed` and `Stage::undone_by` say so in the sentences the engine prints.
//!
//! Two of the four carry something an undo cannot reach, and both say so where they are written.
//! An Access Grid import that carried a decision out of the hub's own log refuses to roll back,
//! because a realm writes a decision once and never withdraws one. A bounty host import refuses
//! once its scope has been frozen, because a frozen scope is what a second person agreed to.
//!
//! What a rollback cannot undo is the history. `audit_events` refuses an update and refuses a
//! delete until the events have been exported, so a pilot that goes wrong leaves permanent
//! evidence that it happened. That is the intent, and somebody should be told before they start
//! rather than after.
//!
//! **Nothing here deletes a customer's record on a timer.** There is no cleanup on upgrade, no
//! cleanup on uninstall and no sweep. `forget` is the only function in this phase that deletes
//! anything at all, it is never called by anything, and it refuses until the retention has run
//! out. The absence of a feature is a promise that is easy to lose, so it is written down.
use super::{
    frozen::{self, Product},
    observe::Profile,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The version of the rollout file's own shape.
pub const VERSION: u32 = 1;

/// How long the legacy record is kept after a cutover before anything may delete it.
pub const KEEP_DAYS: u32 = super::backup::KEEP_DAYS;

/// The eight stages, in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Stage {
    /// The shapes are written down and the loaders refuse a record from a newer build.
    Freeze,
    /// The administrator takes an inventory of their own deployment.
    Survey,
    /// Every product's records are copied and read back.
    Backup,
    /// The whole move is run on the copies and undone again.
    Rehearsal,
    /// A realm is built beside the hub. The hub still owns everything.
    Import,
    /// Both paths answer the same questions and every difference is written down.
    Observation,
    /// The product reads the realm instead of the hub. This is the only stage that changes what
    /// the shipped product does.
    Cutover,
    /// The legacy record is moved aside, with its retention running.
    Retire,
}

impl Stage {
    pub fn all() -> &'static [Stage] {
        &[Stage::Freeze, Stage::Survey, Stage::Backup, Stage::Rehearsal, Stage::Import, Stage::Observation, Stage::Cutover, Stage::Retire]
    }

    pub fn number(self) -> usize {
        Stage::all().iter().position(|stage| *stage == self).expect("every stage is in the list")
    }

    pub fn word(self) -> &'static str {
        match self {
            Stage::Freeze => "freeze",
            Stage::Survey => "survey",
            Stage::Backup => "backup",
            Stage::Rehearsal => "rehearsal",
            Stage::Import => "import",
            Stage::Observation => "observation",
            Stage::Cutover => "cutover",
            Stage::Retire => "retire",
        }
    }

    pub fn from_word(word: &str) -> Option<Stage> {
        Stage::all().iter().copied().find(|stage| stage.word() == word)
    }

    /// What this stage changed.
    pub fn changed(self) -> &'static str {
        match self {
            Stage::Freeze => "a document, and a version check in the Closed Neo Grid, Sandbox Grid and Swarm Mining loaders; the Access Grid's loader has none, so a record from a newer build is read and what it does not know is lost",
            Stage::Survey => "one file under the operations folder",
            Stage::Backup => "one stamped folder of copies",
            Stage::Rehearsal => "a scratch folder, which is deleted when it passes",
            Stage::Import => "nothing yet: no command in this build performs an import, so this stage records where the administrator stands and moves nothing",
            Stage::Observation => "lines in an append-only ledger",
            Stage::Cutover => "which of the two the product reads",
            Stage::Retire => "where the legacy record sits",
        }
    }

    /// How it is undone.
    pub fn undone_by(self) -> &'static str {
        match self {
            Stage::Freeze => "nothing has to be undone: the version check only ever refuses, and refusing to read a record from a newer build is the behaviour, not a change to one",
            Stage::Survey => "delete the file",
            Stage::Backup => "delete the stamped folder, once its retention has run out",
            Stage::Rehearsal => "delete the scratch folder; it is kept only when something failed, so that the failure can be read",
            Stage::Import => "take the import back out with the bridge's own roll back, then delete the realm's database and its key from this computer's vault. No command in this build does either half: the four imports and their roll backs are library functions the rehearsal runs against copies, and nothing a person can type calls one",
            Stage::Observation => "stop the comparator; if the pilot is ending, undo the import as well",
            Stage::Cutover => "point the product back at its hub, which is still exactly the grid it was because no bridge has ever written to it",
            Stage::Retire => "put the record back where it was, which is what unretire does",
        }
    }

    /// How long that undo stays available.
    pub fn available_for(self) -> &'static str {
        match self {
            Stage::Freeze | Stage::Survey => "for ever",
            Stage::Backup => "until the backup's own retention runs out",
            Stage::Rehearsal => "not applicable: a rehearsal changed nothing to undo",
            Stage::Import | Stage::Observation => "until the cutover",
            Stage::Cutover | Stage::Retire => "for the retention period, which is ninety days unless the administrator asked for longer",
        }
    }
}

/// Where one profile stands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileState {
    pub profile: Profile,
    pub stage: Stage,
    pub since: i64,
    /// When the legacy record may be deleted at the earliest. Set at the cutover.
    pub kept_until: Option<i64>,
    pub notes: Vec<String>,
}

// There is deliberately no `realm_id` here. One was carried, documented as the realm a profile's
// import went into, and nothing ever wrote it: no command performs an import, so it was null in
// every file this build could produce and made `status` read as though it could name what a
// rollback would target. It comes back with the command that writes it.

/// Where every profile stands, which is the whole of the rollout's own state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rollout {
    pub rollout: u32,
    pub updated_at: i64,
    pub profiles: Vec<ProfileState>,
}

impl Rollout {
    /// A rollout that has not started: every profile frozen, which is where they all are the day
    /// this lands, because the freeze is the only stage that is not optional.
    pub fn new(now: i64) -> Rollout {
        Rollout {
            rollout: VERSION,
            updated_at: now,
            profiles: Profile::all()
                .iter()
                .map(|profile| ProfileState { profile: *profile, stage: Stage::Freeze, since: now, kept_until: None, notes: Vec::new() })
                .collect(),
        }
    }

    pub fn read(path: &Path) -> Result<Rollout, String> {
        let bytes = std::fs::read(path).map_err(|error| format!("Cannot read how far the rollout has come: {error}"))?;
        let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| "The rollout's own record is damaged".to_owned())?;
        let found = value["rollout"].as_u64().unwrap_or(0);
        if found > u64::from(VERSION) {
            return Err(format!("This rollout was recorded by a newer Yougori (version {found}); update Yougori to read it"));
        }
        serde_json::from_value(value).map_err(|error| format!("The rollout's own record is damaged: {error}"))
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(folder) = path.parent() {
            std::fs::create_dir_all(folder).map_err(|error| format!("Cannot open the folder for the rollout: {error}"))?;
        }
        let bytes = serde_json::to_vec_pretty(self).map_err(|error| error.to_string())?;
        std::fs::write(path, bytes).map_err(|error| format!("Cannot write how far the rollout has come: {error}"))
    }

    pub fn state(&self, profile: Profile) -> Option<&ProfileState> {
        self.profiles.iter().find(|state| state.profile == profile)
    }

    fn state_mut(&mut self, profile: Profile) -> Option<&mut ProfileState> {
        self.profiles.iter_mut().find(|state| state.profile == profile)
    }

    /// Moves one profile on by exactly one stage, or says why it may not move.
    ///
    /// One stage at a time, and one profile at a time, which is three rules and no judgement:
    ///
    /// - a profile whose product has no bridge cannot reach the import, because there is nothing
    ///   to import it with. The refusal is the register's own sentence about what is missing. No
    ///   shipped product is in that state today; the rule is kept so that one added later without
    ///   a bridge is refused on the day it is added rather than quietly let through;
    /// - a profile cannot reach the import until every profile before it in the order has
    ///   reached the cutover, so the order in `docs/grid-core/rollout.md` is enforced rather than
    ///   recommended;
    /// - only one profile may be in observation at a time, because a stop in one pilot has to be
    ///   understood before another one starts producing lines. For the order the four shipped
    ///   products move in, the rule above already gives this: a later profile cannot reach the
    ///   import until the one before it has reached the cutover. It is checked in its own right
    ///   so that changing the order cannot quietly take it away.
    pub fn advance(&mut self, profile: Profile, now: i64) -> Result<Stage, String> {
        let at = self.state(profile).ok_or("That is not a profile of this rollout")?.stage;
        let next = Stage::all().get(at.number() + 1).copied().ok_or("This profile has finished its rollout")?;
        if next >= Stage::Import && !has_a_bridge(profile) {
            return Err(format!("{} cannot be brought across: {}", profile.word(), why_no_bridge(profile)));
        }
        if next == Stage::Observation {
            if let Some(watching) = self.profiles.iter().find(|state| state.stage == Stage::Observation && state.profile != profile) {
                return Err(format!("{} is already being observed; one profile is watched at a time", watching.profile.word()));
            }
        }
        if next >= Stage::Import {
            if let Some(behind) = self.behind(profile) {
                return Err(format!("{} moves before {}: it is still at the {} stage", behind.word(), profile.word(), self.state(behind).expect("a profile of this rollout").stage.word()));
            }
        }
        if next == Stage::Retire {
            let kept = self.state(profile).and_then(|state| state.kept_until);
            if let Some(until) = kept.filter(|until| now < *until) {
                return Err(format!("This grid's old record is kept until {until}; it cannot be retired before then"));
            }
        }
        let keep_from = now + i64::from(KEEP_DAYS) * 86_400;
        let state = self.state_mut(profile).expect("a profile of this rollout");
        state.stage = next;
        state.since = now;
        if next == Stage::Cutover {
            state.kept_until = Some(keep_from);
        }
        self.updated_at = now;
        Ok(next)
    }

    /// Takes one profile back by exactly one stage. The sentence saying what has to be done to
    /// the world as well is `Stage::undone_by`, because this only records where things stand.
    pub fn go_back(&mut self, profile: Profile, now: i64) -> Result<(Stage, &'static str), String> {
        let at = self.state(profile).ok_or("That is not a profile of this rollout")?.stage;
        if at == Stage::Freeze {
            return Err("This profile has not started, so there is nothing to take back".into());
        }
        let back = Stage::all()[at.number() - 1];
        let state = self.state_mut(profile).expect("a profile of this rollout");
        state.stage = back;
        state.since = now;
        self.updated_at = now;
        Ok((back, at.undone_by()))
    }

    /// The first profile before this one in the order that has not reached the cutover.
    fn behind(&self, profile: Profile) -> Option<Profile> {
        let order = Profile::all().iter().position(|known| *known == profile)?;
        Profile::all()[..order]
            .iter()
            .find(|earlier| {
                has_a_bridge(**earlier) && self.state(**earlier).is_some_and(|state| state.stage < Stage::Cutover)
            })
            .copied()
    }

    pub fn describe(&self) -> String {
        let mut lines = Vec::new();
        for state in &self.profiles {
            let kept = match state.kept_until {
                Some(until) => format!(", old record kept until {until}"),
                None => String::new(),
            };
            lines.push(format!("{}: {} since {}{}", state.profile.word(), state.stage.word(), state.since, kept));
            if !has_a_bridge(state.profile) {
                lines.push(format!("  {} cannot go past the rehearsal: {}", state.profile.word(), why_no_bridge(state.profile)));
            }
        }
        lines.join("\n")
    }
}

/// Whether anything can actually bring this profile across today.
pub fn has_a_bridge(profile: Profile) -> bool {
    frozen::contracts()
        .iter()
        .find(|contract| contract.product == profile.product())
        .is_some_and(|contract| contract.bridge.imports())
}

/// Why nothing can, in the register's own words.
///
/// Every shipped product has a bridge today, so nothing reaches this but a product added later
/// without one. It reads the register rather than naming products, so a product added with
/// `Bridge::None` is refused with its own sentence on the day it is added.
pub fn why_no_bridge(profile: Profile) -> &'static str {
    match frozen::contracts().iter().find(|contract| contract.product == profile.product()).map(|contract| contract.bridge) {
        Some(frozen::Bridge::None(why)) => why,
        _ => "it has a bridge",
    }
}

// -------------------------------------------------------------------------------------------
// Retiring the legacy record, and putting it back
// -------------------------------------------------------------------------------------------

/// Where one retired record went, and when it may be deleted at the earliest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Retired {
    pub retired: u32,
    pub product: String,
    pub at: i64,
    /// Where it is inside the stamped folder.
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
    pub kept_until: i64,
    pub notes: Vec<String>,
}

/// Moves a product's record out of the product's own folder and into a stamped one.
///
/// Nothing is deleted here. The record is copied, the copy is read back with the product's own
/// loader, and only then is the original removed; a loader that refuses the copy leaves both
/// files where they are and says so.
///
/// It is handed two paths and cannot tell whether the product has stopped writing the first of
/// them, so it trusts its caller to have asked the stage machine first. `Rollout::advance` is
/// where that question is answered, and the engine's retire verb asks it before calling this:
/// a product with no bridge, a profile whose turn it is not, and a profile whose old record is
/// still inside its retention are all refused there, in `advance`'s own words.
pub fn retire(from: &Path, product: Product, into: &Path, keep_for_days: u32, now: i64) -> Result<Retired, String> {
    if keep_for_days < super::backup::LEAST_KEEP_DAYS {
        return Err(format!("A retired record is kept for at least {} days; {keep_for_days} is too few", super::backup::LEAST_KEEP_DAYS));
    }
    let name = Path::new(frozen::contracts().iter().find(|contract| contract.product == product).map(|contract| contract.path).unwrap_or("record.json"))
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "record.json".to_owned());
    let inside = format!("{}/{name}", product.word());
    let to = into.join(&inside);
    // The manifest is the thing a folder can only hold one of: `retired`, `unretire` and `forget`
    // all read `retired.json` at the folder's root, and `forget` deletes the whole folder after
    // checking the one retention that manifest names. So the guard is on the manifest as well as
    // on this product's own file. Two products retired inside the same second would otherwise
    // land in one stamped folder, the second manifest would replace the first, and the first
    // record would become unreachable by `unretire` and be deleted on the second one's clock.
    if to.exists() || into.join("retired.json").exists() {
        return Err("There is already a retired record in that folder; retire each one into a folder of its own".into());
    }
    if let Some(folder) = to.parent() {
        std::fs::create_dir_all(folder).map_err(|error| format!("Cannot open the folder for the retired record: {error}"))?;
    }
    std::fs::copy(from, &to).map_err(|error| format!("Cannot move the record aside: {error}"))?;
    let bytes = std::fs::read(&to).map_err(|error| format!("Cannot read the record that was just moved aside: {error}"))?;
    if frozen::recognise(&bytes).is_none() {
        let _ = std::fs::remove_file(&to);
        return Err("The copy of that record is not a shape this build knows, so nothing was moved".into());
    }
    let retired = Retired {
        retired: VERSION,
        product: product.word().to_owned(),
        at: now,
        path: inside,
        sha256: frozen::digest(&bytes),
        bytes: bytes.len() as u64,
        kept_until: now + i64::from(keep_for_days) * 86_400,
        notes: vec![
            "the product stopped writing this record at the cutover; retiring it only moves it".to_owned(),
            "nothing deletes this on a timer: there is no cleanup on upgrade, none on uninstall and no sweep".to_owned(),
        ],
    };
    let manifest = serde_json::to_vec_pretty(&retired).map_err(|error| error.to_string())?;
    std::fs::write(into.join("retired.json"), manifest).map_err(|error| format!("Cannot write what was retired: {error}"))?;
    std::fs::remove_file(from).map_err(|error| format!("The record was copied aside and the original could not be removed: {error}"))?;
    Ok(retired)
}

/// What a stamped folder says it holds.
pub fn retired(stamp: &Path) -> Result<Retired, String> {
    let bytes = std::fs::read(stamp.join("retired.json")).map_err(|error| format!("Cannot read what was retired: {error}"))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("The record of what was retired is damaged: {error}"))
}

/// Puts a retired record back where it came from. Refuses to write over one that is there.
pub fn unretire(stamp: &Path, back_to: &Path) -> Result<PathBuf, String> {
    let retired = retired(stamp)?;
    let from = stamp.join(&retired.path);
    let bytes = std::fs::read(&from).map_err(|error| format!("Cannot read the retired record: {error}"))?;
    if frozen::digest(&bytes) != retired.sha256 {
        return Err("The retired record is not the one that was retired; it has changed since".into());
    }
    if back_to.exists() {
        return Err("There is already a record at that path; move it out of the way before putting the retired one back".into());
    }
    if let Some(folder) = back_to.parent() {
        std::fs::create_dir_all(folder).map_err(|error| format!("Cannot open the folder for the record: {error}"))?;
    }
    std::fs::write(back_to, &bytes).map_err(|error| format!("Cannot put the retired record back: {error}"))?;
    Ok(back_to.to_owned())
}

/// Deletes a retired record. The only function in this phase that deletes anything.
///
/// It refuses while the retention is still running. `force` is the override, it exists because an
/// administrator who has to delete something on a legal deadline should not have to edit a file
/// to do it, and whoever uses it is expected to record why in the realm's own history, which this
/// crate cannot do for them because it is handed no realm here.
pub fn forget(stamp: &Path, now: i64, force: bool) -> Result<Retired, String> {
    let retired = retired(stamp)?;
    if now < retired.kept_until && !force {
        return Err(format!("This record is kept until {}; it cannot be forgotten before then", retired.kept_until));
    }
    std::fs::remove_dir_all(stamp).map_err(|error| format!("Cannot delete the retired record: {error}"))?;
    Ok(retired)
}

// -------------------------------------------------------------------------------------------
// The reading tools that never go away
// -------------------------------------------------------------------------------------------

/// What one record on a disk is, read without a hub and without changing anything.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Reading {
    pub shape: Option<String>,
    /// Which products write this shape. Two products keep one type, so this is sometimes two.
    pub products: Vec<String>,
    pub version: Option<u32>,
    pub grid_id: Option<String>,
    pub counts: BTreeMap<String, u64>,
    pub sha256: String,
    pub bytes: u64,
    pub notes: Vec<String>,
}

impl Reading {
    pub fn describe(&self) -> String {
        let mut lines = vec![match &self.shape {
            Some(shape) => format!("{} ({} bytes), written by {}", shape, self.bytes, self.products.join(" or ")),
            None => format!("{} bytes that are not a shape this build knows", self.bytes),
        }];
        if let Some(version) = self.version {
            lines.push(format!("version {version}"));
        }
        if let Some(id) = &self.grid_id {
            lines.push(format!("the grid's own identifier is {id}"));
        }
        for (what, how_many) in &self.counts {
            lines.push(format!("{how_many} {what}"));
        }
        lines.extend(self.notes.iter().cloned());
        lines.join("\n")
    }
}

/// Reads one record found on a disk and says what is in it.
///
/// This is the tool that has to still work years from now, when nothing on the computer runs the
/// product that wrote the file. It opens exactly the path it is given and nothing else, it never
/// writes, and it reads through each product's own loader so that a shape this build does not
/// understand is refused in words rather than guessed at.
pub fn read_record(path: &Path) -> Result<Reading, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("Cannot read that record: {error}"))?;
    let shape = frozen::recognise(&bytes);
    let mut reading = Reading {
        shape: shape.map(|shape| shape.name().to_owned()),
        products: shape.map(|shape| shape.products().iter().map(|product| product.name().to_owned()).collect()).unwrap_or_default(),
        version: None,
        grid_id: None,
        counts: BTreeMap::new(),
        sha256: frozen::digest(&bytes),
        bytes: bytes.len() as u64,
        notes: vec!["nothing was written: this read the file and closed it".to_owned()],
    };
    let Some(shape) = shape else {
        return Err("That is not a record this build knows how to read".into());
    };
    match shape {
        frozen::Shape::Hub => {
            let record = crate::hub::read(&bytes)?;
            reading.version = Some(u32::from(record.version));
            reading.grid_id = Some(record.id.clone());
            reading.counts.insert("computers".to_owned(), record.members.len() as u64);
            reading.counts.insert("model plans".to_owned(), record.plans.len() as u64);
            reading.counts.insert("desks".to_owned(), record.desks.len() as u64);
            reading.counts.insert("people".to_owned(), record.people.len() as u64);
            reading.counts.insert("images".to_owned(), record.enterprise.images.len() as u64);
            reading.notes.push("both grids keep one type in two files, so which product this belongs to is said by the file it was found in and not by what is in it".to_owned());
        }
        // The counts are read straight off each record rather than through its bridge. This is the
        // tool that has to still work when nothing on the computer runs the product that wrote the
        // file, and a bridge can refuse a record it will not translate; a reading says what is in
        // the bytes whether or not anything would bring them across.
        frozen::Shape::BountyHost => {
            let record = crate::bounty::read(&bytes)?;
            reading.version = Some(u32::from(record.version));
            reading.grid_id = Some(record.id.clone());
            reading.counts.insert("computers".to_owned(), record.members.len() as u64);
            reading.counts.insert("findings".to_owned(), record.findings.len() as u64);
            reading.counts.insert("source files".to_owned(), record.bounty.files.len() as u64);
        }
        frozen::Shape::AccessHub => {
            let record: crate::access::hub::Record = serde_json::from_slice(&bytes).map_err(|_| "The Access Grid's settings are damaged".to_owned())?;
            reading.version = Some(u32::from(record.version));
            reading.grid_id = Some(record.id.clone());
            reading.counts.insert("people".to_owned(), record.people.len() as u64);
            reading.counts.insert("credentials".to_owned(), record.credentials.len() as u64);
            reading.counts.insert("rules".to_owned(), record.rules.len() as u64);
            reading.notes.push("every credential in this record holds its value, sealed with the key in that computer's vault; nothing here unseals one and nothing here could".to_owned());
        }
        frozen::Shape::CoreRecord => {
            let record = crate::core::store::legacy::read(&bytes)?;
            reading.version = Some(record.version);
            reading.grid_id = Some(record.realm.id.clone());
            reading.counts.insert("people".to_owned(), record.principals.len() as u64);
            reading.counts.insert("computers".to_owned(), record.devices.len() as u64);
            reading.counts.insert("workspaces".to_owned(), record.workspaces.len() as u64);
            reading.counts.insert("credentials".to_owned(), record.credentials.len() as u64);
            reading.counts.insert("events".to_owned(), record.audit.events.len() as u64);
            reading.notes.push("whether this record's history verifies is not asked here: that needs the realm's key".to_owned());
        }
    }
    Ok(reading)
}
