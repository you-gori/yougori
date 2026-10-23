//! Bridges from a product's own hub onto Grid Core.
//!
//! A bridge reads a hub's record and says what that grid looks like as a realm. It is additive
//! and it is reversible: the hub's record is never changed by anything here, so the grid goes on
//! running on the hub that still owns it while the realm beside it is built, checked and, if it
//! was a mistake, taken out again.
//!
//! Three questions have to be answerable before anyone trusts a bridge with a company's grid, and
//! there is a function for each:
//!
//! - what would an import create, without creating any of it: `rehearse`;
//! - what did it create, in a shape that can be undone: `import` and `roll_back`;
//! - would the core place the computers exactly as the hub does, computer by computer: `compare`.
//!
//! The last one is the one that runs beside a live grid. The hub keeps deciding; the core decides
//! alongside it; every computer the two would treat differently is reported rather than quietly
//! applied. A difference that is deliberate is still reported, with the reason, because a bridge
//! that hides its own disagreements is worth nothing.
//!
//! All four shipped products have a bridge of that shape. Each one still says what it cannot
//! carry: `access.rs` cannot carry a credential's value, because a realm refuses to hold one, and
//! `bounty.rs` cannot freeze the research scope it builds, because freezing one needs a second
//! person to agree. Both of those are notes on a rehearsal rather than silence, because the whole
//! rollout is built on knowing what a move would do before making it.
/// The Access Grid's people, computers, credentials and rules, onto a company realm.
pub mod access;
/// Copying each product's records somewhere safe before anything moves.
pub mod backup;
/// Swarm Mining's members, source and findings, onto a research realm of its own.
pub mod bounty;
pub mod desks;
/// The on-disk shapes the shipped products write, frozen so they cannot drift by accident.
pub mod frozen;
pub mod neo;
/// Running both paths side by side and writing down where they disagree.
pub mod observe;
/// Running the whole move on copies, so what it would do is known before it is done.
pub mod rehearsal;
/// The stages a product moves in, what undoes each one, and how long the old record is kept.
pub mod rollout;
/// What one computer can say about its own deployment, because nobody can enumerate them.
pub mod survey;

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Where one deployment's records are on this computer.
///
/// The grid crate never decides where anything lives. The application knows its own data folder
/// and this crate does not, so every path arrives here from the caller, and nothing in this
/// module opens a path it was not given. A product that is not installed on this computer is
/// `None`, which is a different thing from a product whose record is empty.
#[derive(Clone, Debug, Default)]
pub struct Sources {
    pub neo_hub: Option<PathBuf>,
    pub desks_hub: Option<PathBuf>,
    pub bounty_host: Option<PathBuf>,
    pub access_hub: Option<PathBuf>,
    /// Realm databases already on this computer, in whatever order the caller found them.
    pub realms: Vec<PathBuf>,
}

impl Sources {
    /// Each product whose record is named and actually there, in the rollout's own order.
    pub fn present(&self) -> Vec<(frozen::Product, &Path)> {
        let named = [
            (frozen::Product::NeoGrid, self.neo_hub.as_deref()),
            (frozen::Product::SandboxGrid, self.desks_hub.as_deref()),
            (frozen::Product::SwarmMining, self.bounty_host.as_deref()),
            (frozen::Product::AccessGrid, self.access_hub.as_deref()),
        ];
        named.into_iter().filter_map(|(product, path)| path.filter(|path| path.exists()).map(|path| (product, path))).collect()
    }
}

/// What one import created, kept in the realm it created it in.
///
/// Until this existed, the only thing that could undo an import was a value in memory, so a
/// rollback was impossible after a restart, a crash or a reboot. Keeping it in the realm rather
/// than in a file beside it gives three things a file cannot: it travels with `Core::backup`, it
/// is covered by the realm's own history, and it cannot be separated from the realm it describes.
///
/// It holds identifiers and counts, under the names the realm gave them, and nothing else.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeImport {
    pub id: String,
    pub realm_id: String,
    pub grid_id: String,
    pub at: i64,
    pub undo: Undone,
}

/// Which bridge ran, and exactly what it created.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "bridge", rename_all = "camelCase")]
pub enum Undone {
    Neo(Imported),
    Desks(DesksImported),
    Access(AccessImported),
    Research(ResearchImported),
}

impl Undone {
    /// The word the database keeps, which is also the word a person reads.
    pub fn word(&self) -> &'static str {
        match self {
            Undone::Neo(_) => "neo",
            Undone::Desks(_) => "desks",
            Undone::Access(_) => "access",
            Undone::Research(_) => "research",
        }
    }
}

impl BridgeImport {
    /// The name this record takes in the realm. It is made from the bridge and the moment, so the
    /// same import looked up twice is the same row and a rollback does not have to be handed an
    /// identifier it was never given.
    pub fn name(bridge: &str, at: i64) -> String {
        format!("import-{bridge}-{at}")
    }

    pub fn describe(&self) -> String {
        match &self.undo {
            Undone::Neo(imported) => format!("a Closed Neo Grid brought across at {}: {} computers and {} model plans", self.at, imported.computers.len(), imported.plans.len()),
            Undone::Desks(imported) => format!(
                "a Sandbox Grid brought across at {}: {} accounts, {} computers and {} workspaces",
                self.at,
                imported.people.len(),
                imported.computers.len(),
                imported.workspaces.len()
            ),
            Undone::Access(imported) => format!(
                "an Access Grid brought across at {}: {} accounts, {} computers, {} credentials and {} permissions",
                self.at,
                imported.people.len(),
                imported.devices.len(),
                imported.credentials.len(),
                imported.grants.len()
            ),
            Undone::Research(imported) => format!(
                "a bounty host brought across at {}: {} accounts, {} computers, one research scope and {} findings",
                self.at,
                imported.members.len(),
                imported.computers.len(),
                imported.findings.len()
            ),
        }
    }
}

/// Whether a realm has room for what an import carries, counting what it already holds.
///
/// Every number in `limits` names the door that enforces it, and every one of those doors is on
/// `Core`. A bridge writes through the store, which is the layer underneath them and enforces
/// none, so without this an import is the one way into a realm that walks around all of them —
/// and an import is also the one act that grows a realm by hundreds at once, which makes it the
/// worst place to be missing the check rather than the least important.
///
/// Called with the collision checks, before anything is written, so a refusal leaves nothing
/// half brought across.
/// The refusal is `limits::reached`, the same sentence every other door in the core refuses with,
/// and then says what this grid holds and what the import carries, because the useful question
/// after being refused an import is which of the two to make smaller.
pub(super) fn room_for(what: &str, held: usize, carrying: usize, most: usize) -> Result<(), String> {
    if held + carrying > most {
        return Err(format!("{}; this one has {held} and the import carries {carrying} more", super::limits::reached(what, most)));
    }
    Ok(())
}

/// Every import this realm still holds, newest last. What a rollback is run from after a restart.
pub fn undo_for(core: &super::Core) -> Result<Vec<BridgeImport>, String> {
    core.store.bridge_imports()
}

/// One thing the hub had, under the name the realm gives it. The same idea as `Moved`, for the
/// records that are one thing rather than three.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Renamed {
    pub was: String,
    pub now: String,
}

/// What an import would create in a realm, counted without writing anything.
///
/// The same idea as `store::legacy::Rehearsal`, which says what opening an older record would
/// bring across. A rehearsal that passes is an import that will run.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rehearsal {
    /// The hub's own identifier and name, so a person can see which grid this is.
    pub grid_id: String,
    pub grid_name: String,
    /// One account stands for the computers: they join a hub with the company password, and there
    /// is no person behind any of them to name.
    pub principals: usize,
    pub devices: usize,
    pub hosts: usize,
    /// How many of those computers reported that they can run models.
    pub model_capable: usize,
    /// How many the admin has left out of the grid's work.
    pub left_out: usize,
    pub plans: usize,
    /// Computers that already have a model, and keep it.
    pub assignments: usize,
    /// Anything worth saying before it is run. Never a reason to run it blindly.
    pub notes: Vec<String>,
}

impl Rehearsal {
    /// A short report for a person about to run it.
    pub fn describe(&self) -> String {
        let mut lines = vec![
            format!("{} ({}) would become one account, {} computers and {} model plans", self.grid_name, self.grid_id, self.devices, self.plans),
            format!("{} of the computers can run models, and {} are left out of the grid's work", self.model_capable, self.left_out),
            format!("{} computers already have a model, and keep the one they have", self.assignments),
        ];
        lines.extend(self.notes.iter().cloned());
        lines.join("\n")
    }
}

/// What bringing a Sandbox Grid's desks across would create, counted without creating any of it.
///
/// The same shape as the model grid's `Rehearsal`: counts a person can check against what they
/// can see in the product, and notes that say what will be different afterwards. A rehearsal
/// that passes is an import that will run.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeskRehearsal {
    pub grid_id: String,
    pub grid_name: String,
    /// The people who sign in, one account each, plus one that stands for the computers.
    pub principals: usize,
    pub devices: usize,
    pub hosts: usize,
    /// How computers were committed, carried across in the words the admin had already agreed.
    pub commitments: usize,
    pub images: usize,
    /// Images invented for desks that were ordered without one from the catalogue.
    pub images_for_desks: usize,
    /// Images whose bytes nobody has hashed, which are recorded unpinned and pinned on first use.
    pub unpinned: usize,
    pub workspaces: usize,
    /// Desks that are on a computer now, and come across placed on the same one.
    pub placed: usize,
    /// Desks that belong to somebody.
    pub owned: usize,
    /// Desks whose data is packed up and waiting for a computer.
    pub parcels: usize,
    pub notes: Vec<String>,
}

impl DeskRehearsal {
    /// A short report for a person about to run it.
    pub fn describe(&self) -> String {
        let mut lines = vec![
            format!("{} ({}) would become {} accounts, {} computers and {} workspaces", self.grid_name, self.grid_id, self.principals, self.devices, self.workspaces),
            format!("{} of those workspaces belong to somebody and {} are on a computer now", self.owned, self.placed),
            format!("{} images, {} of them made for desks ordered without one, and {} whose bytes nobody has hashed yet", self.images, self.images_for_desks, self.unpinned),
            format!("{} computers arrive with the share their admin had already set, under this grid's own wording for it", self.commitments),
            format!("{} workspaces have their data packed up and waiting; the data itself is not touched", self.parcels),
        ];
        lines.extend(self.notes.iter().cloned());
        lines.join("\n")
    }
}

/// What a desk import did create, and everything needed to take it out again.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesksImported {
    pub realm_id: String,
    pub grid_id: String,
    pub at: i64,
    /// Each person on the hub, and the account they became. Only the ones this import created.
    pub people: Vec<Renamed>,
    /// Each computer this import had to create, and what it became.
    pub computers: Vec<Moved>,
    /// Each commitment this import recorded, whether on a computer it created or on one another
    /// bridge had already brought in. A computer that was already here keeps everything else it
    /// had, so the commitment is the only thing an undo has to take off it.
    pub commitments: Vec<String>,
    /// Each desk, and the workspace it became.
    pub workspaces: Vec<Renamed>,
    /// Each image this import created.
    pub images: Vec<Renamed>,
    /// The account that stands for this grid's computers, when this import created it.
    pub principal_id: Option<String>,
}

/// What bringing an Access Grid across would create, counted without creating any of it.
///
/// The same shape as the other three rehearsals: counts a person can check against what they can
/// see in the product, and notes saying what will be different afterwards. Counts and identifiers
/// only: no person's name, no username, no email, no credential name, no destination, no hint and
/// no sealed value.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessRehearsal {
    pub grid_id: String,
    pub people: usize,
    /// People who could administer the grid, approve a request, or read its record.
    pub administrators: usize,
    pub approvers: usize,
    pub auditors: usize,
    pub credentials: usize,
    /// How many of those a realm will hold. A credential the hub mints a short-lived one from
    /// does not cross, because a realm sends a credential as it is.
    pub credentials_carried: usize,
    pub rules: usize,
    /// Rules that send a person to an approver rather than deciding by themselves.
    pub rules_that_ask: usize,
    /// Rules that forbid outright. A realm says that by granting nobody, so these cross as the
    /// absence of a permission rather than as a rule of their own.
    pub rules_that_forbid: usize,
    /// Remembered computers across every person, each of which becomes a computer in the realm.
    pub remembered_computers: usize,
    /// Of those, the ones that had already stopped being accepted, which arrive withdrawn.
    pub lapsed_computers: usize,
    /// People with two-step sign-in set up. The secret itself is sealed and is never read here.
    pub with_two_step: usize,
    pub has_identity_provider: bool,
    /// One account per person, plus one that stands for the grid itself.
    pub principals: usize,
    /// Permissions to use a credential, one per person per credential the rules cover.
    pub grants: usize,
    /// Credentials every use of which will need an approver, because a rule said ask.
    pub every_time: usize,
    /// Decisions read out of the Access Grid's own activity log, when the caller handed one in.
    pub decisions: usize,
    /// Other lines of that log, which cross as events in the realm's own history.
    pub events: usize,
    pub notes: Vec<String>,
}

impl AccessRehearsal {
    pub fn describe(&self) -> String {
        let mut lines = vec![
            format!("{} would become {} accounts, {} computers, {} of its {} credentials and {} permissions", self.grid_id, self.principals, self.remembered_computers, self.credentials_carried, self.credentials, self.grants),
            format!("{} administrators, {} approvers and {} auditors", self.administrators, self.approvers, self.auditors),
            format!("{} of its {} rules send somebody to an approver and {} forbid outright", self.rules_that_ask, self.rules, self.rules_that_forbid),
            format!("{} credentials arrive needing an approver every time, and no value comes across at all", self.every_time),
            format!("{} remembered computers, {} of which had already stopped being accepted, and {} people with two-step sign-in", self.remembered_computers, self.lapsed_computers, self.with_two_step),
            format!("{} decisions and {} other lines of the grid's own log would cross", self.decisions, self.events),
        ];
        if self.has_identity_provider {
            lines.push("this grid signs people in through a company identity provider, which is a live tenant and is never reached from here".to_owned());
        }
        lines.extend(self.notes.iter().cloned());
        lines.join("\n")
    }
}

/// What an Access Grid import did create, and everything needed to take it out again.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessImported {
    pub realm_id: String,
    pub grid_id: String,
    pub at: i64,
    /// Each person on the hub, and the account they became.
    pub people: Vec<Renamed>,
    /// Each remembered computer, and the computer in the realm it became.
    pub devices: Vec<Renamed>,
    /// Each credential, and the credential in the realm it became. The value stayed where it was.
    pub credentials: Vec<Renamed>,
    /// Each permission to use a credential this import wrote, by name.
    pub grants: Vec<String>,
    /// Each decided request this import wrote, by name. A realm never withdraws a decision, so an
    /// import that wrote one of these cannot be taken back out, and `roll_back` says so.
    pub approvals: Vec<String>,
    /// The account that stands for the grid itself, when this import created it.
    pub principal_id: Option<String>,
}

/// What bringing a bounty host across would create, counted without creating any of it.
///
/// Counts and identifiers only: no title, no instruction, no authorisation sentence, no file
/// path, no finding text and no member name.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BountyRehearsal {
    pub host_id: String,
    pub members: usize,
    /// How many of the joined computers chose a model to work with.
    pub working: usize,
    pub findings: usize,
    pub source_files: usize,
    pub source_bytes: u64,
    /// What the bounty asks a worker to build and run from its source: `source` is the files
    /// alone, `web` and `api` also start the project in its own sandbox. Nothing here starts any
    /// of them, and nothing in this phase reaches a network.
    pub target_kind: String,
    /// One account per joined computer, plus one that stands for the host.
    pub principals: usize,
    pub devices: usize,
    pub hosts: usize,
    /// Pieces of work the findings are recorded against, one per computer that reported any.
    pub work: usize,
    /// Always one: a bounty is one authorisation over one set of files.
    pub scopes: usize,
    /// Whether that scope would arrive frozen. It never does, and `notes` says why.
    pub scope_frozen: bool,
    pub notes: Vec<String>,
}

impl BountyRehearsal {
    pub fn describe(&self) -> String {
        let mut lines = vec![
            format!("{} has {} joined computers, {} of them working, and {} findings", self.host_id, self.members, self.working, self.findings),
            format!("its source is {} files and {} bytes, worked as {}", self.source_files, self.source_bytes, self.target_kind),
            format!("it would become a research realm of its own: {} accounts, {} computers, {} scopes and {} findings", self.principals, self.devices, self.scopes, self.findings),
            format!("the scope would arrive {}", if self.scope_frozen { "frozen" } else { "a draft, so nothing can be placed under it until somebody freezes it with an approver" }),
        ];
        lines.extend(self.notes.iter().cloned());
        lines.join("\n")
    }
}

/// What a bounty host import did create, and everything needed to take it out again.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResearchImported {
    pub realm_id: String,
    pub grid_id: String,
    pub at: i64,
    /// Each joined computer, and the account it became.
    pub members: Vec<Renamed>,
    /// Each joined computer, and the computer and offer it became.
    pub computers: Vec<Moved>,
    /// The scope this bounty became, and the source acquired under it.
    pub scope_id: String,
    pub source_id: String,
    pub admission_id: String,
    /// The request that would let this source in, which nobody has decided.
    pub approval_id: String,
    /// Each piece of work the findings were recorded against.
    pub work: Vec<String>,
    /// Each finding, and the finding in the realm it became.
    pub findings: Vec<Renamed>,
    /// The account that stands for the host itself.
    pub principal_id: String,
}

/// What the hub and the core each say about one thing, both put in the realm's own words.
///
/// The same idea as `Placement` and `DeskPlacement`, for the two profiles whose question is not
/// where something was put. A reader should be able to put the two columns side by side without
/// translating anything in their head.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Decided {
    pub subject: String,
    pub hub: String,
    pub core: String,
}

impl Decided {
    pub fn agrees(&self) -> bool {
        self.hub == self.core
    }
}

/// What the hub and the core each decide about using a credential, person by person.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessComparison {
    pub grid_id: String,
    pub decisions: Vec<Decided>,
    /// Differences that are there on purpose, each with the reason.
    pub notes: Vec<String>,
}

impl AccessComparison {
    pub fn agrees(&self) -> bool {
        self.decisions.iter().all(Decided::agrees)
    }

    pub fn differences(&self) -> Vec<&Decided> {
        self.decisions.iter().filter(|decided| !decided.agrees()).collect()
    }

    pub fn describe(&self) -> String {
        let mut lines = Vec::new();
        if self.agrees() {
            lines.push(format!("the hub and the core answer all {} of these the same way", self.decisions.len()));
        } else {
            lines.push(format!("{} of {} answers differ", self.differences().len(), self.decisions.len()));
            for difference in self.differences() {
                lines.push(format!("  {}: the hub says {}, the core says {}", difference.subject, difference.hub, difference.core));
            }
        }
        lines.extend(self.notes.iter().cloned());
        lines.join("\n")
    }
}

/// What the bounty host holds and what the research realm would hold, thing by thing.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResearchComparison {
    pub host_id: String,
    pub carried: Vec<Decided>,
    pub notes: Vec<String>,
}

impl ResearchComparison {
    pub fn agrees(&self) -> bool {
        self.carried.iter().all(Decided::agrees)
    }

    pub fn differences(&self) -> Vec<&Decided> {
        self.carried.iter().filter(|decided| !decided.agrees()).collect()
    }

    pub fn describe(&self) -> String {
        let mut lines = Vec::new();
        if self.agrees() {
            lines.push(format!("the realm would hold all {} of these exactly as the host does", self.carried.len()));
        } else {
            lines.push(format!("{} of {} would be held differently", self.differences().len(), self.carried.len()));
            for difference in self.differences() {
                lines.push(format!("  {}: the host says {}, the realm would say {}", difference.subject, difference.hub, difference.core));
            }
        }
        lines.extend(self.notes.iter().cloned());
        lines.join("\n")
    }
}

/// What an import did create, and everything needed to take it out again.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Imported {
    pub realm_id: String,
    pub grid_id: String,
    pub at: i64,
    /// Each computer in the hub, and the account, computer and offer it became.
    pub computers: Vec<Moved>,
    /// Each plan in the hub, and the model plan it became.
    pub plans: Vec<Named>,
    /// The one account the computers belong to.
    pub principal_id: String,
    pub assignments: usize,
}

/// One of the hub's computers, and what it became in the realm.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Moved {
    pub member_id: String,
    pub device_id: String,
    pub host_id: String,
}

/// One of the hub's plans, and the model plan it became.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Named {
    pub plan_id: String,
    pub model_plan_id: String,
}

/// Where one computer was put, by the hub and by the core, for the same grid at the same moment.
///
/// Both are named by the hub's own plan identifiers, so the two columns can be read side by side
/// without translating anything in your head.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Placement {
    pub member_id: String,
    pub hub: Option<String>,
    pub core: Option<String>,
}

impl Placement {
    pub fn agrees(&self) -> bool {
        self.hub == self.core
    }
}

/// What the hub and the core each decided, computer by computer.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Comparison {
    pub grid_id: String,
    pub computers: Vec<Placement>,
    /// Differences that are there on purpose, each with the reason. A reader should be able to
    /// tell a decision from a defect without reading the code.
    pub notes: Vec<String>,
}

impl Comparison {
    /// Whether the two agreed about every computer.
    pub fn agrees(&self) -> bool {
        self.computers.iter().all(Placement::agrees)
    }

    /// Only the computers they treated differently.
    pub fn differences(&self) -> Vec<&Placement> {
        self.computers.iter().filter(|placement| !placement.agrees()).collect()
    }

    pub fn describe(&self) -> String {
        let mut lines = Vec::new();
        if self.agrees() {
            lines.push(format!("the hub and the core place all {} computers the same way", self.computers.len()));
        } else {
            lines.push(format!("{} of {} computers are placed differently", self.differences().len(), self.computers.len()));
            for difference in self.differences() {
                lines.push(format!(
                    "  {}: the hub says {}, the core says {}",
                    difference.member_id,
                    difference.hub.as_deref().unwrap_or("no model"),
                    difference.core.as_deref().unwrap_or("no model")
                ));
            }
        }
        lines.extend(self.notes.iter().cloned());
        lines.join("\n")
    }
}

/// Where one desk was put, by the hub and by the core, for the same grid at the same moment.
///
/// Both sides are named by the hub's own member identifiers, so the two columns read side by side
/// without translating anything in your head, exactly as `Placement` does for models.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeskPlacement {
    pub desk_id: String,
    /// The hub's member identifier, or none when the hub left the desk waiting.
    pub hub: Option<String>,
    /// The core's answer, translated back to the hub's member identifier.
    pub core: Option<String>,
    /// Where each side says the desk is, in its own word for it.
    pub hub_state: String,
    pub core_state: String,
}

impl DeskPlacement {
    /// Whether both sides put this desk in the same place. The state words are reported but not
    /// compared here: the two vocabularies are deliberately different, and `observe` is where a
    /// difference between them is judged against the bridge's own notes.
    pub fn agrees(&self) -> bool {
        self.hub == self.core
    }
}

/// What the hub and the core each decided, desk by desk.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeskComparison {
    pub grid_id: String,
    pub desks: Vec<DeskPlacement>,
    /// Differences that are there on purpose, each with the reason. A reader should be able to
    /// tell a decision from a defect without reading the code.
    pub notes: Vec<String>,
}

impl DeskComparison {
    pub fn agrees(&self) -> bool {
        self.desks.iter().all(DeskPlacement::agrees)
    }

    pub fn differences(&self) -> Vec<&DeskPlacement> {
        self.desks.iter().filter(|placement| !placement.agrees()).collect()
    }

    pub fn describe(&self) -> String {
        let mut lines = Vec::new();
        if self.agrees() {
            lines.push(format!("the hub and the core place all {} desks the same way", self.desks.len()));
        } else {
            lines.push(format!("{} of {} desks are placed differently", self.differences().len(), self.desks.len()));
            for difference in self.differences() {
                lines.push(format!(
                    "  {}: the hub says {}, the core says {}",
                    difference.desk_id,
                    difference.hub.as_deref().unwrap_or("no computer"),
                    difference.core.as_deref().unwrap_or("no computer")
                ));
            }
        }
        lines.extend(self.notes.iter().cloned());
        lines.join("\n")
    }
}

/// A plan as both sides can be compared: what it serves and which computers it names. Identifiers
/// are left out because the two sides mint their own, and comparing those would only ever differ.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanShape {
    pub model: String,
    pub quant: Option<String>,
    pub percent: u8,
    /// `all`, `remaining` or `computers`.
    pub scope: &'static str,
    /// The hub's own computer identifiers, in the order the plan holds them.
    pub picked: Vec<String>,
}

/// What the hub and the core each made of the same new plan.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PlanComparison {
    pub hub: Vec<PlanShape>,
    pub core: Vec<PlanShape>,
    /// What each said when it refused. The words differ where the hub names a command line flag
    /// and the core has no command line, so only the refusal itself is compared.
    pub hub_refused: Option<String>,
    pub core_refused: Option<String>,
    pub notes: Vec<String>,
}

impl PlanComparison {
    pub fn agrees(&self) -> bool {
        self.hub_refused.is_some() == self.core_refused.is_some() && self.hub == self.core
    }

    pub fn describe(&self) -> String {
        let mut lines = vec![if self.agrees() {
            format!("the hub and the core both end with {} plans, the same way", self.hub.len())
        } else {
            format!("the hub ends with {} plans and the core with {}", self.hub.len(), self.core.len())
        }];
        if let (Some(hub), Some(core)) = (&self.hub_refused, &self.core_refused) {
            lines.push(format!("both refused: the hub said \"{hub}\", the core said \"{core}\""));
        }
        lines.extend(self.notes.iter().cloned());
        lines.join("\n")
    }
}

#[cfg(test)]
mod tests;
