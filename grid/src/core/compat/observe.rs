//! Observation mode: the product's hub keeps deciding, the core decides the same question beside
//! it, and every answer the two give differently is written down instead of being applied.
//!
//! `compat::neo::compare` already did this for one thing: where a model goes. This module is that
//! idea with the shape taken out of it, so every profile is observed the same way and a reader of
//! the ledger does not have to know which product a line came from.
//!
//! Three rules hold everywhere here, and they are what make an observation worth reading.
//!
//! **Nothing is applied.** No function here writes to a hub's record, and the two that need a
//! realm build a throwaway one in a folder the caller owns. A pilot realm that holds the import
//! is never the realm a comparison places work into, because `compat::*::roll_back` refuses once
//! work has been placed from a computer the import brought in: comparing in the pilot realm would
//! quietly destroy the undo that the same stage depends on.
//!
//! **Both sides are asked in the core's vocabulary.** The hub says `ready` and the core says
//! `assigned`; a bridge already says which is which, and that translation is documented, tested
//! and not a disagreement. So the hub's answer is put through the bridge's own translation first
//! and only then compared. What is left is a real disagreement about the same question.
//!
//! **A difference is a stop unless something says otherwise.** The two exceptions are named in
//! `judge` and nowhere else. Anything that is not one of them ends the pilot for that profile,
//! including a difference nobody meant. That direction is chosen on purpose: a false stop costs
//! an afternoon, and a difference waved through costs somebody's work.
use super::{frozen::Product, Sources};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// How long a profile is watched before anybody may act on the result.
///
/// Fourteen days is a proposal, not a measurement: nothing in this repository has watched a real
/// grid for any length of time, and whether fourteen days of an ordinary company's use actually
/// contains the situations `Coverage` asks for is unknown until one runs. A time-only gate is
/// passed by doing nothing, which is why the coverage below is part of the same gate.
pub const WINDOW_DAYS: i64 = 14;

/// What a realm is being asked to take over. One profile moves at a time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Profile {
    Models,
    Workspaces,
    Research,
    Credentials,
}

impl Profile {
    /// The order the four move in, and the reasons are in docs/grid-core/rollout.md.
    pub fn all() -> &'static [Profile] {
        &[Profile::Models, Profile::Workspaces, Profile::Research, Profile::Credentials]
    }

    pub fn word(self) -> &'static str {
        match self {
            Profile::Models => "models",
            Profile::Workspaces => "workspaces",
            Profile::Research => "research",
            Profile::Credentials => "credentials",
        }
    }

    pub fn from_word(word: &str) -> Option<Profile> {
        Profile::all().iter().copied().find(|profile| profile.word() == word)
    }

    /// Which shipped product owns this profile today.
    pub fn product(self) -> Product {
        match self {
            Profile::Models => Product::NeoGrid,
            Profile::Workspaces => Product::SandboxGrid,
            Profile::Research => Product::SwarmMining,
            Profile::Credentials => Product::AccessGrid,
        }
    }
}

/// The six questions both sides are asked. Every observation is about one of them, so a ledger
/// can be read heading by heading whichever product wrote it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Heading {
    /// What the admin asked for: plans, desk orders, rules.
    Plans,
    /// Where each thing was put: which computer runs which model, holds which desk.
    Assignments,
    /// Who may do what.
    Permissions,
    /// What is running, and in which state.
    Workloads,
    /// What each side wrote in its own record of what happened.
    Audit,
    /// What somebody asking the product would be told.
    Answers,
}

impl Heading {
    pub fn all() -> &'static [Heading] {
        &[Heading::Plans, Heading::Assignments, Heading::Permissions, Heading::Workloads, Heading::Audit, Heading::Answers]
    }

    pub fn name(self) -> &'static str {
        match self {
            Heading::Plans => "plans",
            Heading::Assignments => "assignments",
            Heading::Permissions => "permissions",
            Heading::Workloads => "workloads",
            Heading::Audit => "audit events",
            Heading::Answers => "user-visible answers",
        }
    }

    pub fn asks(self) -> &'static str {
        match self {
            Heading::Plans => "what the administrator asked this grid to do",
            Heading::Assignments => "which computer each thing was put on",
            Heading::Permissions => "what each account may do",
            Heading::Workloads => "what is running, and in which state",
            Heading::Audit => "what each side recorded about it",
            Heading::Answers => "what somebody asking the product would be told",
        }
    }
}

/// Which band a difference falls into.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", content = "because", rename_all = "camelCase")]
pub enum Verdict {
    /// Both sides said the same thing.
    Agrees,
    /// They differ, and the difference is one of the two the rollout accepts.
    Noted(String),
    /// They differ, and the pilot for this profile ends here.
    Stop(String),
    /// Nothing could ask this question on this computer. Not an agreement and not a difference.
    Unobserved(String),
}

impl Verdict {
    pub fn stops(&self) -> bool {
        matches!(self, Verdict::Stop(_))
    }

    pub fn word(&self) -> &'static str {
        match self {
            Verdict::Agrees => "agrees",
            Verdict::Noted(_) => "noted",
            Verdict::Stop(_) => "stop",
            Verdict::Unobserved(_) => "unobserved",
        }
    }
}

/// One question, asked of both sides at one moment, with both answers and the band.
///
/// Every field is an identifier, a state word, a count or a fixed sentence. There is no field
/// here that could hold a person's name, an email address, a model's name, a bounty's title, an
/// address, a hostname, a certificate, a salt, a token hash or a path, and no flag adds one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Observation {
    pub at: i64,
    pub profile: Profile,
    pub heading: Heading,
    /// The hub's own identifier for the thing being asked about.
    pub subject: String,
    pub hub: String,
    pub core: String,
    pub verdict: Verdict,
}

impl Observation {
    pub fn new(at: i64, profile: Profile, heading: Heading, subject: &str, hub: &str, core: &str, verdict: Verdict) -> Observation {
        Observation { at, profile, heading, subject: subject.to_owned(), hub: hub.to_owned(), core: core.to_owned(), verdict }
    }

    /// One line a person can read: the thing, both answers and the band.
    pub fn describe(&self) -> String {
        match &self.verdict {
            Verdict::Agrees => format!("{} {}: both say {}", self.heading.name(), self.subject, self.hub),
            Verdict::Noted(why) => format!("{} {}: the hub says {}, the core says {} ({why})", self.heading.name(), self.subject, self.hub, self.core),
            Verdict::Stop(why) => format!("STOP {} {}: the hub says {}, the core says {} ({why})", self.heading.name(), self.subject, self.hub, self.core),
            Verdict::Unobserved(why) => format!("{} {}: not observed here ({why})", self.heading.name(), self.subject),
        }
    }
}

/// Whether an answer is an identifier a grid minted rather than a word somebody chose.
///
/// This is what makes the rule below mechanical. A bridge's note is a sentence about a whole
/// grid and never names one computer, so a difference between two identifiers can never be
/// explained away by one. Every placement difference therefore stops, which is the single most
/// important rule in this file.
fn an_identifier(text: &str) -> bool {
    let Some((prefix, tail)) = text.rsplit_once('-') else { return false };
    !prefix.is_empty() && tail.len() >= 4 && tail.chars().all(|letter| letter.is_ascii_hexdigit())
}

/// One answer as a set of things, for the headings whose answer is a list. A role is written
/// `workspace administrator`, so the separator is the comma and never the space.
fn items(text: &str) -> Vec<&str> {
    text.split(',').map(str::trim).filter(|item| !item.is_empty()).collect()
}

/// The items of an answer that the other side's answer does not have.
fn only_in(mine: &str, theirs: &str) -> Vec<String> {
    let other = items(theirs);
    items(mine).into_iter().filter(|item| !other.contains(item)).map(str::to_owned).collect()
}

/// An answer broken into the smallest pieces a note could name.
fn words(text: &str) -> Vec<&str> {
    text.split([',', ' ', ':']).map(str::trim).filter(|word| word.len() > 3).collect()
}

/// Which band a difference falls into. This is the whole of the rule, in one place.
///
/// The two sides are already in the same vocabulary when they get here, because each bridge puts
/// the hub's answer through its own documented translation before asking. So:
///
/// - the same answer agrees;
/// - under `Assignments`, every difference stops, whatever the reason. Where a computer, a model
///   or somebody's desk is put is the thing the whole migration is about, and a reason to place
///   it differently belongs in the notes an operator reads rather than in a decision to carry on
///   without them;
/// - under `Permissions`, a core that allows a subset of what the hub allowed is a note, because
///   less is the direction a migration is allowed to err in, and anything the core allows that
///   the hub did not is a stop even if it looks harmless;
/// - under the other four headings, a difference is a note only when one of the bridge's own
///   notes names a word that differs and that word is not an identifier a grid minted;
/// - everything else stops.
pub fn judge(heading: Heading, hub: &str, core: &str, notes: &[String]) -> Verdict {
    if hub == core {
        return Verdict::Agrees;
    }
    if heading == Heading::Assignments {
        return Verdict::Stop(format!("the hub puts this on {hub} and the core puts it on {core}"));
    }
    if heading == Heading::Permissions {
        let extra = only_in(core, hub);
        if extra.is_empty() {
            let fewer = only_in(hub, core);
            return Verdict::Noted(format!("the core allows less here than the hub did: it does not grant {}", fewer.join(", ")));
        }
        return Verdict::Stop(format!("the core allows something here the hub never granted: {}", extra.join(", ")));
    }
    let hub_words = words(hub);
    let core_words = words(core);
    let differing: Vec<&str> = hub_words
        .iter()
        .filter(|word| !core_words.contains(word))
        .chain(core_words.iter().filter(|word| !hub_words.contains(word)))
        .copied()
        .filter(|word| !an_identifier(word))
        .collect();
    for word in &differing {
        if let Some(note) = notes.iter().find(|note| note.contains(*word)) {
            return Verdict::Noted(note.clone());
        }
    }
    Verdict::Stop(format!("the hub says {hub} and the core says {core}, and nothing this bridge wrote explains it"))
}

/// Everything one pass of observation saw for one profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pass {
    pub profile: Profile,
    pub at: i64,
    pub observations: Vec<Observation>,
}

impl Pass {
    pub fn stops(&self) -> Vec<&Observation> {
        self.observations.iter().filter(|observation| observation.verdict.stops()).collect()
    }

    /// Whether this pass found nothing that ends the pilot.
    pub fn clean(&self) -> bool {
        self.stops().is_empty()
    }

    pub fn describe(&self) -> String {
        let mut lines = vec![format!(
            "{}: {} questions, {} agreed, {} noted, {} stopped, {} not observable here",
            self.profile.word(),
            self.observations.len(),
            self.count("agrees"),
            self.count("noted"),
            self.count("stop"),
            self.count("unobserved"),
        )];
        for observation in self.observations.iter().filter(|observation| !matches!(observation.verdict, Verdict::Agrees)) {
            lines.push(format!("  {}", observation.describe()));
        }
        lines.join("\n")
    }

    fn count(&self, word: &str) -> usize {
        self.observations.iter().filter(|observation| observation.verdict.word() == word).count()
    }
}

/// One pass over every profile this deployment has, writing nothing to any hub.
///
/// A product that is not installed here contributes nothing. A product whose profile cannot be
/// observed contributes a line saying so, which is the point: a ledger that is silent about the
/// Access Grid and a ledger that says the Access Grid cannot be observed read very differently to
/// whoever has to decide whether a rollout may continue.
///
/// `scratch` is a folder this function owns and empties. The workspace comparison needs a
/// database because the core's chooser reads one, so it is far heavier than the model grid's,
/// which is a pure function; this runs on a schedule and samples rather than watching.
pub fn watch(sources: &Sources, scratch: &Path, now: i64) -> Result<Vec<Pass>, String> {
    let mut passes = Vec::new();
    if let Some(path) = sources.neo_hub.as_deref().filter(|path| path.exists()) {
        let record = crate::hub::load(path)?;
        passes.push(Pass { profile: Profile::Models, at: now, observations: super::neo::observe(&record, now) });
    }
    if let Some(path) = sources.desks_hub.as_deref().filter(|path| path.exists()) {
        let record = crate::hub::load(path)?;
        let hosts = super::desks::hosts_from_record(&record);
        passes.push(Pass { profile: Profile::Workspaces, at: now, observations: super::desks::observe(&record, &hosts, &scratch.join("workspaces"), now)? });
    }
    if let Some(path) = sources.bounty_host.as_deref().filter(|path| path.exists()) {
        let record = crate::bounty::load(path)?;
        passes.push(Pass { profile: Profile::Research, at: now, observations: super::bounty::observe(&record, now) });
    }
    if let Some(path) = sources.access_hub.as_deref().filter(|path| path.exists()) {
        let record = crate::access::hub::load(path)?;
        passes.push(Pass { profile: Profile::Credentials, at: now, observations: super::access::observe(&record, now) });
    }
    Ok(passes)
}

/// Where one profile's ledger for one day is kept, under a folder the caller owns.
pub fn ledger_path(folder: &Path, profile: Profile, now: i64) -> PathBuf {
    let day = chrono::DateTime::from_timestamp(now, 0).map(|at| at.format("%Y-%m-%d").to_string()).unwrap_or_else(|| "undated".to_owned());
    folder.join(format!("{}-{day}.jsonl", profile.word()))
}

/// Appends a pass to the ledger, one JSON object per line.
///
/// The ledger is append-only and is never rewritten, because a record of an observation that can
/// be edited is not a record of anything. Nothing here deletes a line and nothing here reads one
/// in order to change it.
pub fn record(folder: &Path, pass: &Pass) -> Result<PathBuf, String> {
    use std::io::Write;
    std::fs::create_dir_all(folder).map_err(|error| format!("Cannot open the folder for the observations: {error}"))?;
    let path = ledger_path(folder, pass.profile, pass.at);
    let mut file = std::fs::OpenOptions::new().create(true).append(true).open(&path).map_err(|error| format!("Cannot write the observations: {error}"))?;
    for observation in &pass.observations {
        let line = serde_json::to_string(observation).map_err(|error| error.to_string())?;
        writeln!(file, "{line}").map_err(|error| format!("Cannot write the observations: {error}"))?;
    }
    Ok(path)
}

/// Every observation of one profile the ledger holds, oldest first.
pub fn read(folder: &Path, profile: Profile) -> Result<Vec<Observation>, String> {
    let mut files: Vec<PathBuf> = Vec::new();
    let Ok(entries) = std::fs::read_dir(folder) else { return Ok(Vec::new()) };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with(&format!("{}-", profile.word())) && name.ends_with(".jsonl") {
            files.push(entry.path());
        }
    }
    files.sort();
    let mut all = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file).map_err(|error| format!("Cannot read the observations: {error}"))?;
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            all.push(serde_json::from_str::<Observation>(line).map_err(|error| format!("An observation could not be read: {error}"))?);
        }
    }
    all.sort_by_key(|observation| observation.at);
    Ok(all)
}

/// What a window of observation has actually seen.
///
/// Every number here is derived from the ledger itself rather than asserted. A subject that
/// appears for the first time after the window opened joined; one that stops appearing left; one
/// whose hub answer changes moved. What that cannot see is said in `describe`: a computer that
/// joined and left between two passes is invisible, because the ledger only holds what a pass
/// looked at.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Coverage {
    pub profile_word: String,
    pub observations: usize,
    pub passes: usize,
    pub days: i64,
    pub agreed: usize,
    pub noted: usize,
    pub stopped: usize,
    pub unobserved: usize,
    /// Subjects that first appeared after the first pass.
    pub joined: usize,
    /// Subjects that were there and then stopped being looked at.
    pub left: usize,
    /// Subjects whose hub answer changed from one pass to the next.
    pub moved: usize,
}

impl Coverage {
    /// Whether this is a pilot rather than a demonstration.
    ///
    /// Time and coverage together, because a time-only gate is passed by doing nothing. Both
    /// numbers are proposals: nothing here has watched a real grid, and whether an ordinary
    /// fortnight contains all three situations is exactly the thing that cannot be answered from
    /// this repository.
    pub fn enough(&self) -> bool {
        self.days >= WINDOW_DAYS && self.joined > 0 && self.left > 0 && self.moved > 0 && self.stopped == 0
    }

    pub fn describe(&self) -> String {
        let mut lines = vec![
            format!("{}: {} observations over {} passes and {} days", self.profile_word, self.observations, self.passes, self.days),
            format!("{} agreed, {} noted, {} stopped, {} not observable here", self.agreed, self.noted, self.stopped, self.unobserved),
            format!("{} things joined, {} left and {} moved while this was watched", self.joined, self.left, self.moved),
        ];
        if !self.enough() {
            let mut missing = Vec::new();
            if self.days < WINDOW_DAYS {
                missing.push(format!("{} more days", WINDOW_DAYS - self.days));
            }
            if self.joined == 0 {
                missing.push("something joining".to_owned());
            }
            if self.left == 0 {
                missing.push("something leaving".to_owned());
            }
            if self.moved == 0 {
                missing.push("something moving".to_owned());
            }
            if self.stopped > 0 {
                missing.push(format!("{} differences that stop a rollout, which have to be understood first", self.stopped));
            }
            lines.push(format!("this is not a pilot yet: it still needs {}", missing.join(", ")));
        }
        lines.push("a computer that joined and left between two passes was never seen at all: the ledger holds what each pass looked at and nothing in between".to_owned());
        lines.join("\n")
    }
}

/// What the ledger says about one profile.
pub fn coverage(observations: &[Observation], profile: Profile) -> Coverage {
    let mut moments: Vec<i64> = observations.iter().map(|observation| observation.at).collect();
    moments.sort_unstable();
    moments.dedup();
    let days = match (moments.first(), moments.last()) {
        (Some(first), Some(last)) => (last - first) / 86_400,
        _ => 0,
    };
    let mut joined = 0;
    let mut left = 0;
    let mut moved = 0;
    let mut answers: std::collections::BTreeMap<String, (usize, String)> = std::collections::BTreeMap::new();
    for (pass, moment) in moments.iter().enumerate() {
        let now: Vec<&Observation> = observations.iter().filter(|observation| observation.at == *moment && observation.heading == Heading::Assignments).collect();
        for observation in &now {
            match answers.get(&observation.subject) {
                None if pass > 0 => {
                    joined += 1;
                    answers.insert(observation.subject.clone(), (pass, observation.hub.clone()));
                }
                None => {
                    answers.insert(observation.subject.clone(), (pass, observation.hub.clone()));
                }
                Some((_, was)) => {
                    if was != &observation.hub {
                        moved += 1;
                    }
                    answers.insert(observation.subject.clone(), (pass, observation.hub.clone()));
                }
            }
        }
    }
    // Anything that was being looked at and is not in the last pass has left. A thing that joined
    // and left between two passes was never in the ledger at all, and nothing here can say so.
    if let Some(last) = moments.len().checked_sub(1) {
        left = answers.values().filter(|(seen, _)| *seen < last).count();
    }
    let count = |word: &str| observations.iter().filter(|observation| observation.verdict.word() == word).count();
    Coverage {
        profile_word: profile.word().to_owned(),
        observations: observations.len(),
        passes: moments.len(),
        days,
        agreed: count("agrees"),
        noted: count("noted"),
        stopped: count("stop"),
        unobserved: count("unobserved"),
        joined,
        left,
        moved,
    }
}
