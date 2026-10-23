//! What one computer can say about its own deployment, because nobody else can.
//!
//! This software runs on customers' own computers. The only calls it makes out of a company's
//! network are two HTTPS GETs for static release files, which carry no identity and no counts,
//! and the Yougori Network and the Swarm website, which know a signed-in account and its nodes
//! and know nothing about which grids that account runs or how large they are. So there is no
//! fleet-wide view of anything, there is no switch anybody can throw from here, and an install
//! nobody has ever heard of is protected by the version gate in the two loaders that have one,
//! `hub::read` and `bounty::read`, and by nothing else. The Access Grid's loader has no gate at
//! all: its record is **Dropped** in the register, so an older build reads a newer one and loses
//! what it does not know.
//!
//! The rule that follows is the important part and it shapes every stage of the rollout: **no
//! stage may depend on the vendor knowing that a deployment exists.** Every stage is local,
//! started by the administrator at the hub, and reversible.
//!
//! An inventory is therefore something a customer takes of their own grid and keeps. This module
//! is what produces it: it reads the records the caller names, counts them, and hands back one
//! value. It sends nothing. The caller writes the file and tells the person where it is, and
//! whether to send it to anybody, over whatever channel they already use, is their decision and
//! not a feature.
//!
//! **What a survey never carries**, enforced by a test and not by care: a person's name, a
//! username, an email address, a model's name, a bounty's title, a source file's path, a
//! credential's name or destination, an address, a hostname, a tunnel domain, a certificate, a
//! salt, a token hash, a sealed value, or any absolute path. Every path in a survey is the fixed
//! relative one from the frozen-contract register, which is the same on every computer. There is
//! no flag that adds any of these, and adding one would be a change to what this product is.
//!
//! **What an inventory can never be is complete.** A hub knows its own members, because they
//! enrolled; that is the only true enumeration anywhere, and it is exactly the one the migration
//! needs, because the question a rollout has to answer is not how many customers there are but
//! what moves in this grid. Everything outside this computer is invisible here.
use super::{
    frozen::{self, Product},
    Sources,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The version of the survey's own shape.
pub const VERSION: u32 = 1;

/// Everything one computer can say about itself without naming anybody.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Survey {
    pub survey: u32,
    pub taken_at: i64,
    /// The build that took it. The caller supplies it; this crate does not know the application's
    /// version.
    pub app_version: String,
    pub os: String,
    pub arch: String,
    pub products: Vec<Seen>,
    pub realms: Vec<RealmSeen>,
    pub notes: Vec<String>,
}

impl Survey {
    /// A short reading for the person who ran it.
    pub fn describe(&self) -> String {
        let mut lines = vec![format!("taken by {} on {} {}", self.app_version, self.os, self.arch)];
        for product in &self.products {
            lines.push(product.describe());
        }
        for realm in &self.realms {
            lines.push(realm.describe());
        }
        lines.extend(self.notes.iter().cloned());
        lines.join("\n")
    }

    /// Which products are actually on this computer.
    pub fn installed(&self) -> Vec<&Seen> {
        self.products.iter().filter(|seen| seen.present).collect()
    }
}

/// One product, as far as its record on this computer says.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Seen {
    pub product: String,
    pub present: bool,
    /// The fixed path from the frozen-contract register, relative to the application's data
    /// folder. Never the caller's own path, which would be one person's computer.
    pub path: String,
    pub record_version: Option<u32>,
    /// The grid's own random identifier, which names no person and no company.
    pub grid_id: Option<String>,
    pub record_sha256: Option<String>,
    pub record_bytes: Option<u64>,
    /// Counts, and only counts. Every value here is a number.
    pub counts: BTreeMap<String, u64>,
    /// Which frozen record this matched, or that it matched none.
    pub shape: Option<String>,
    pub notes: Vec<String>,
}

impl Seen {
    pub fn describe(&self) -> String {
        if !self.present {
            return format!("{}: not on this computer", self.product);
        }
        let counted: Vec<String> = self.counts.iter().map(|(what, how_many)| format!("{how_many} {what}")).collect();
        format!("{} at {} (version {}): {}", self.product, self.path, self.record_version.unwrap_or(0), counted.join(", "))
    }
}

/// One realm's database, as far as it can be read without its key.
///
/// A realm's key is in the operating system's vault and this crate never holds one, so a survey
/// cannot open the realm itself: what it can read is the version the database is at and the steps
/// it has been through, which is what tells an operator whether a migration is owed. Whether the
/// realm's history verifies is a question only something holding the key can ask, and the survey
/// says so rather than leaving a reader to assume it was checked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RealmSeen {
    /// The database's file name without its folder, so no absolute path is carried.
    pub file: String,
    pub schema_version: u32,
    pub steps: Vec<u32>,
    pub bytes: u64,
    pub notes: Vec<String>,
}

impl RealmSeen {
    pub fn describe(&self) -> String {
        format!("a realm in {} at version {}, through {} steps", self.file, self.schema_version, self.steps.len())
    }
}

/// Reads what the caller named, counts it, and hands back one value. Writes nothing and sends
/// nothing.
pub fn survey(sources: &Sources, app_version: &str, now: i64) -> Survey {
    let mut products = Vec::new();
    for product in [Product::NeoGrid, Product::SandboxGrid, Product::SwarmMining, Product::AccessGrid] {
        let path = match product {
            Product::NeoGrid => sources.neo_hub.as_deref(),
            Product::SandboxGrid => sources.desks_hub.as_deref(),
            Product::SwarmMining => sources.bounty_host.as_deref(),
            _ => sources.access_hub.as_deref(),
        };
        products.push(look(product, path, now));
    }
    let mut realms = Vec::new();
    for path in &sources.realms {
        realms.push(look_at_realm(path));
    }
    let mut notes = vec![
        "this is one computer's account of itself: nothing was sent anywhere, and nothing outside this computer is in it".to_owned(),
        "a hub knows its own members because they enrolled, and that is the only complete list of anything there is".to_owned(),
    ];
    if realms.iter().any(|realm| realm.schema_version < super::super::store::schema::VERSION) {
        notes.push("a realm here is at an older version than this build writes; opening it brings it forward, and nothing in this survey did".to_owned());
    }
    Survey {
        survey: VERSION,
        taken_at: now,
        app_version: app_version.chars().filter(|letter| letter.is_ascii_alphanumeric() || *letter == '.' || *letter == '-').take(32).collect(),
        os: std::env::consts::OS.to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
        products,
        realms,
        notes,
    }
}

/// One product's record, counted. A path that is not there is a product that is not installed,
/// which is a different thing from a product with nothing in it, and both are reported.
fn look(product: Product, path: Option<&std::path::Path>, now: i64) -> Seen {
    let contract = frozen::contracts().iter().find(|contract| contract.product == product).expect("every shipped product has a frozen contract");
    let mut seen = Seen {
        product: product.word().to_owned(),
        present: false,
        path: contract.path.to_owned(),
        record_version: None,
        grid_id: None,
        record_sha256: None,
        record_bytes: None,
        counts: BTreeMap::new(),
        shape: None,
        notes: Vec::new(),
    };
    let Some(path) = path.filter(|path| path.exists()) else { return seen };
    seen.present = true;
    let Ok(bytes) = std::fs::read(path) else {
        seen.notes.push("the record is there and could not be read".to_owned());
        return seen;
    };
    seen.record_bytes = Some(bytes.len() as u64);
    seen.record_sha256 = Some(frozen::digest(&bytes));
    seen.shape = frozen::recognise(&bytes).map(|shape| shape.name().to_owned());
    if seen.shape.is_none() {
        seen.notes.push("these bytes are not a shape this build knows".to_owned());
    }
    match product {
        Product::NeoGrid | Product::SandboxGrid => match crate::hub::read(&bytes) {
            Ok(record) => {
                seen.record_version = Some(u32::from(record.version));
                seen.grid_id = Some(record.id.clone());
                count_hub(&mut seen.counts, &record, product);
            }
            Err(refusal) => seen.notes.push(refusal),
        },
        Product::SwarmMining => match crate::bounty::read(&bytes) {
            Ok(record) => {
                seen.record_version = Some(u32::from(record.version));
                seen.grid_id = Some(record.id.clone());
                // Counted straight off the record. A survey is an inventory of what is on this
                // computer, so it says what is in the bytes whether or not a bridge would carry
                // them; `rehearsal` is where a record is put through its bridge and can refuse.
                seen.counts.insert("computers".to_owned(), record.members.len() as u64);
                seen.counts.insert("computers working".to_owned(), record.members.iter().filter(|member| member.model.is_some()).count() as u64);
                seen.counts.insert("findings".to_owned(), record.findings.len() as u64);
                seen.counts.insert("source files".to_owned(), record.bounty.files.len() as u64);
                seen.notes.push("this is a count and not a rehearsal: Swarm Mining is brought across into a research grid of its own, and the rehearsal is what runs that on a copy".to_owned());
            }
            Err(refusal) => seen.notes.push(refusal),
        },
        Product::AccessGrid => match serde_json::from_slice::<crate::access::hub::Record>(&bytes) {
            Ok(record) => {
                seen.record_version = Some(u32::from(record.version));
                seen.grid_id = Some(record.id.clone());
                use crate::access::policy::{Decision, Permission};
                let holding = |wanted: Permission| record.people.iter().filter(|person| person.permission == wanted).count() as u64;
                seen.counts.insert("people".to_owned(), record.people.len() as u64);
                seen.counts.insert("administrators".to_owned(), holding(Permission::Admin));
                seen.counts.insert("approvers".to_owned(), holding(Permission::Approver));
                seen.counts.insert("auditors".to_owned(), holding(Permission::Auditor));
                seen.counts.insert("credentials".to_owned(), record.credentials.len() as u64);
                seen.counts.insert("rules".to_owned(), record.rules.len() as u64);
                seen.counts.insert("rules that ask an approver".to_owned(), record.rules.iter().filter(|rule| rule.decision == Decision::Ask).count() as u64);
                seen.counts.insert("remembered computers".to_owned(), record.people.iter().map(|person| person.devices.len()).sum::<usize>() as u64);
                seen.notes.push("this is a count and not a rehearsal: no credential value is ever carried onto the core, and the rehearsal is what runs the move on a copy".to_owned());
            }
            Err(_) => seen.notes.push("The Access Grid's settings are damaged".to_owned()),
        },
        Product::Core => {}
    }
    let _ = now;
    seen
}

/// The counts for a grid hub's record, which both grids share one type for.
///
/// The counts a bridge's own rehearsal produces are not recounted here: `neo::rehearse` and
/// `desks::rehearse` already write nothing and already say how many accounts, computers,
/// commitments, images and workspaces an import would create, so the survey asks them rather
/// than keeping a second set of numbers that could disagree with theirs.
fn count_hub(counts: &mut BTreeMap<String, u64>, record: &crate::hub::Record, product: Product) {
    counts.insert("computers".to_owned(), record.members.len() as u64);
    counts.insert("computers left out".to_owned(), record.members.iter().filter(|member| member.excluded).count() as u64);
    if product == Product::NeoGrid {
        let rehearsal = super::neo::rehearse(record);
        counts.insert("computers that can run models".to_owned(), rehearsal.model_capable as u64);
        counts.insert("model plans".to_owned(), rehearsal.plans as u64);
        counts.insert("computers with a model".to_owned(), rehearsal.assignments as u64);
        counts.insert("api keys".to_owned(), record.keys.len() as u64);
        counts.insert("teams of models".to_owned(), record.harnesses.len() as u64);
        return;
    }
    counts.insert("people".to_owned(), record.people.len() as u64);
    counts.insert("desks".to_owned(), record.desks.len() as u64);
    counts.insert("images".to_owned(), record.enterprise.images.len() as u64);
    counts.insert("workspace roles".to_owned(), record.enterprise.roles.len() as u64);
    counts.insert("connectors".to_owned(), record.enterprise.connections.len() as u64);
    match super::desks::rehearse(record, 0) {
        Ok(rehearsal) => {
            counts.insert("accounts an import would create".to_owned(), rehearsal.principals as u64);
            counts.insert("desks on a computer now".to_owned(), rehearsal.placed as u64);
            counts.insert("desks belonging to somebody".to_owned(), rehearsal.owned as u64);
            counts.insert("desks with their data packed up".to_owned(), rehearsal.parcels as u64);
        }
        Err(_) => {
            // A record the bridge refuses is still counted: the refusal belongs in a rehearsal
            // report, where it can be read with the rest of what would have happened.
        }
    }
}

/// A realm's database, read without changing it and without its key.
///
/// The handle `open_for_reading` gives back is asked for read-only at the operating system, not
/// merely told to refuse writes, because a read-write connection closing last on a realm in
/// write-ahead logging check-points it and rewrites bytes a survey has no business touching.
/// What can still appear beside the realm is SQLite's own `-shm` and `-wal`, which it may create
/// in order to read at all; the realm's own file is what is left alone.
fn look_at_realm(path: &std::path::Path) -> RealmSeen {
    let file = path.file_name().map(|name| name.to_string_lossy().to_string()).unwrap_or_else(|| "a realm".to_owned());
    let bytes = std::fs::metadata(path).map(|data| data.len()).unwrap_or(0);
    let mut seen = RealmSeen { file, schema_version: 0, steps: Vec::new(), bytes, notes: Vec::new() };
    match super::super::store::Store::open_for_reading(path) {
        Ok(store) => {
            seen.schema_version = store.version().unwrap_or(0);
            seen.steps = store.history().map(|rows| rows.into_iter().map(|(version, _, _)| version).collect()).unwrap_or_default();
            seen.notes.push("whether this realm's history verifies is not asked here: that needs its key, which lives in this computer's vault and never in this crate".to_owned());
        }
        Err(refusal) => seen.notes.push(refusal),
    }
    seen
}
