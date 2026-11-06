//! Keeping a folder of this computer and a sandbox's copy of it in step, for a setup's folder
//! binding of mode sync (`environment.sync`, ADR-0001 section 16).
//!
//! The rules are the launcher's own, from one place: `cli/src/launcher/reconcile.rs`, included
//! here so this sync and `yougori launch`'s two-way sync decide every path the same way. Only the
//! side unchanged since the two copies last matched may be overwritten; a file changed in both
//! places never loses either version. With `conflicts: keep_both` both copies are kept — this
//! computer's under its own name, the sandbox's beside it as `NAME.from-sandbox` — and the file
//! waits, named in the setup's health, until the person makes them match. With `conflicts: stop`
//! the pass stops before changing anything and says which file to look at.
//!
//! Nothing here deletes the person's folder or anything in it that the sandbox did not have:
//! a file the sandbox deleted is deleted here only when this computer's copy still matches what
//! they last shared, which is the launcher's rule too.
#[allow(dead_code)]
#[path = "../../../cli/src/reconcile.rs"]
pub(crate) mod reconcile;

use reconcile::{change, decide, unsupported, Change, Direction, Priority};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

/// Relative path to the SHA-256 of the file there, in hex. Paths use `/`.
pub(crate) type Checksums = BTreeMap<String, String>;

/// What a conflicting file does, as the template's binding declared it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Conflicts {
    /// Keep both versions: the sandbox's copy is saved beside this computer's.
    #[default]
    KeepBoth,
    /// Stop the sync, changing nothing, until the two copies match again.
    Stop,
}

impl Conflicts {
    pub(crate) fn read(text: &str) -> Conflicts {
        if text == "stop" { Conflicts::Stop } else { Conflicts::KeepBoth }
    }
}

/// What this computer and the sandbox last agreed on for one synced folder, kept beside the
/// setup so a later pass, or a later run of Yougori, can still tell which side changed.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Record {
    /// The checksum of each file when the two copies last matched.
    #[serde(default)]
    pub common: Checksums,
    /// Files whose shared version was lost with a record that could not be read. Nobody can tell
    /// which copy is newer, so each keeps both copies until the two match again.
    #[serde(default)]
    pub unknown: BTreeSet<String>,
    /// The record was there and could not be read: what differs is not decided by a priority.
    #[serde(skip)]
    pub unreadable: bool,
    /// What the last finished pass had to say, when it had anything. Kept here rather than on the
    /// operation's receipt on purpose: the receipt lives in `registry.json`, whose shape is
    /// checked strictly and whose `SCHEMA` an older engine refuses outright, so a field there
    /// would lock every setup out after a downgrade. This file has no schema number and every
    /// field defaults, so an older engine reads it, ignores this, and at worst drops the line
    /// until a newer engine's next pass.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last: Option<LastPass>,
}

/// What the last pass over a folder held back, kept for the setup's notes to read.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LastPass {
    /// When the pass finished, in seconds.
    #[serde(default)]
    pub at: i64,
    /// Set when the pass stopped without changing anything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stopped: Option<String>,
    /// The first few paths left alone, with why. Capped: one folder of names this computer cannot
    /// store can hold thousands, and a record is not the place to keep them all.
    #[serde(default)]
    pub held: Vec<HeldPath>,
    /// How many were held in total, which `held` may not list in full.
    #[serde(default)]
    pub held_total: usize,
}

/// One held-back path on the record. `Held` itself is not stored, so its shape stays free to
/// change without touching a file already on disk.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HeldPath {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub reason: String,
}

/// Where one synced folder's record lives, under the setup's own folder. The writer and every
/// reader take the path from here, so they can never disagree about which file is which.
pub(crate) fn record_path(setup_folder: &Path, resource: &str, binding: &str) -> PathBuf {
    let name = format!("{resource}-{binding}").chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_')).collect::<String>();
    setup_folder.join("sync").join(format!("{name}.json"))
}

/// Every line a setup's synced folders have to say right now, read from their records: one per
/// folder that stopped or held something back, newest state as of its last pass. A folder whose
/// record is missing or says nothing contributes nothing, so a setup with healthy folders has no
/// notes at all. Only bindings the resource declares today are read, so a binding that has gone
/// can never put a line back on screen.
pub(crate) fn notes(setup_folder: &Path, resource: &str, spec: &serde_json::Value) -> Vec<String> {
    let mut said = Vec::new();
    for folder in folders(spec) {
        let record = Record::load(&record_path(setup_folder, resource, &folder.binding));
        let Some(last) = record.last.filter(LastPass::worth_saying) else { continue };
        let Some(line) = last.report().note(&folder.binding) else { continue };
        let mut text = line;
        // `held` is capped on the record, so say how many it does not list rather than implying
        // the list is all of them.
        let unlisted = last.held_total.saturating_sub(last.held.len());
        if unlisted > 0 {
            text.push_str(&format!(" {unlisted} more are waiting the same way and are not listed here."));
        }
        // A pass runs when the sandbox converges — a change to the setup, or Try again on one
        // that failed — and NOT when the setup is merely started: `EnvironmentHandler::apply`
        // returns for `Action::Start` before it converges. So this must not say "start it again".
        text.push_str(" This is from the last sync; the folder is synced again the next time this setup changes.");
        said.push(text);
    }
    said
}

/// At most this many clashing files are named in one stop message. The rest are counted: a
/// person reading a refusal needs the names to act on, not every name there is.
const CLASHES_NAMED: usize = 10;

/// At most this many held paths are written to a record.
const HELD_KEPT: usize = 20;

impl LastPass {
    /// The record's own view of a finished pass, for the setup's notes.
    pub(crate) fn report(&self) -> Report {
        Report {
            moved: 0,
            held: self.held.iter().map(|held| Held { path: held.path.clone(), reason: held.reason.clone() }).collect(),
            stopped: self.stopped.clone(),
        }
    }

    /// Whether this pass has anything to tell the person at all.
    pub(crate) fn worth_saying(&self) -> bool {
        self.stopped.is_some() || self.held_total > 0
    }
}

/// What a finished pass leaves on the record, with the held list capped and its true size kept.
fn last_pass(report: &Report, at: i64) -> LastPass {
    LastPass {
        at,
        stopped: report.stopped.clone(),
        held: report.held.iter().take(HELD_KEPT).map(|held| HeldPath { path: held.path.clone(), reason: held.reason.clone() }).collect(),
        held_total: report.held.len(),
    }
}

impl Record {
    /// The record of the last pass. None at all is a first sync; one that is there and cannot be
    /// read comes back empty and marked `unreadable`, never passed off as a first sync.
    pub(crate) fn load(path: &Path) -> Record {
        match fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or(Record { unreadable: true, ..Record::default() }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Record::default(),
            Err(_) => Record { unreadable: true, ..Record::default() },
        }
    }

    pub(crate) fn save(&self, path: &Path) -> Result<(), String> {
        let folder = path.parent().ok_or("The setup's folder is missing")?;
        fs::create_dir_all(folder).map_err(|error| error.to_string())?;
        let mut file = tempfile::NamedTempFile::new_in(folder).map_err(|error| error.to_string())?;
        serde_json::to_writer(&mut file, self).map_err(|error| error.to_string())?;
        file.as_file().sync_all().map_err(|error| error.to_string())?;
        file.persist(path).map_err(|error| error.error.to_string())?;
        Ok(())
    }
}

/// One thing a pass does to one path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    /// Copy this computer's file into the sandbox (it is gone here: delete it there).
    Send { path: String, gone: bool },
    /// Copy the sandbox's file to this computer (it is gone there: delete it here).
    Receive { path: String, gone: bool },
    /// Both copies differ from what they last shared: keep both, under `kept` on this computer.
    KeepBoth { path: String, kept: String },
}

impl Step {
    pub(crate) fn path(&self) -> &str {
        match self {
            Step::Send { path, .. } | Step::Receive { path, .. } | Step::KeepBoth { path, .. } => path,
        }
    }
}

/// What a pass found it could not do, each a plain sentence for the person.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Held {
    pub path: String,
    pub reason: String,
}

/// What one pass over a folder comes to.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Pass {
    pub steps: Vec<Step>,
    /// Paths left alone this pass, with why.
    pub held: Vec<Held>,
    /// Set when `conflicts: stop` met a file changed in both places: nothing is done at all.
    pub stopped: Option<String>,
}

/// Where the sandbox's copy of a conflicting file is kept on this computer, beside the person's
/// own: never over it, and never a name the sandbox chose.
pub(crate) fn kept_name(path: &str) -> String {
    format!("{path}.from-sandbox")
}

/// What to do with every path of one synced folder: this computer's checksums, the sandbox's, and
/// what they last shared. Pure, so a test decides every case without a sandbox. `read_only` syncs
/// one way only: this computer's copy goes in, and nothing in the person's folder is touched.
pub(crate) fn plan_pass(local: &Checksums, remote: &Checksums, record: &mut Record, read_only: bool, conflicts: Conflicts) -> Pass {
    let direction = if read_only { Direction::ToContainer } else { Direction::Both };
    let mut pass = Pass::default();
    let paths: BTreeSet<String> = local.keys().chain(remote.keys()).chain(record.common.keys()).cloned().collect();
    let mut matched: Vec<(String, Option<String>)> = Vec::new();
    // Files changed on both sides while `conflicts: stop` is set. Collected, not acted on.
    let mut clashing: Vec<String> = Vec::new();
    for path in &paths {
        // A conflict copy of an earlier pass is the person's to resolve; it is never synced back.
        if path.ends_with(".from-sandbox") {
            continue;
        }
        if let Some(reason) = unsupported(path) {
            pass.held.push(Held { path: path.clone(), reason: format!("{path} can't be synced ({reason}); it stays where it is.") });
            continue;
        }
        let (here, there) = (local.get(path).map(String::as_str), remote.get(path).map(String::as_str));
        let ordinary = change(record.common.get(path).map(String::as_str), here, there);
        let action = decide(ordinary, path, Priority::KeepBoth, record.unreadable, &mut record.unknown);
        // A handoff never consumes changes waiting to travel the other way: a read-only folder
        // leaves what the sandbox changed alone, and never records it as shared.
        if (action == Change::Push && !direction.sends()) || (action == Change::Pull && !direction.receives()) {
            continue;
        }
        match action {
            Change::Same => matched.push((path.clone(), here.map(str::to_owned))),
            Change::Push => {
                pass.steps.push(Step::Send { path: path.clone(), gone: here.is_none() });
                matched.push((path.clone(), here.map(str::to_owned)));
            }
            Change::Pull => {
                pass.steps.push(Step::Receive { path: path.clone(), gone: there.is_none() });
                matched.push((path.clone(), there.map(str::to_owned)));
            }
            Change::Conflict => {
                if conflicts == Conflicts::Stop {
                    // Every conflicting file, not just the first: a person fixing one only to meet
                    // the next is being told the truth one file at a time. Nothing is done either
                    // way, so collecting them costs nothing but the names.
                    clashing.push(path.clone());
                    continue;
                }
                // Both versions are kept; the file has no shared version until they match again.
                if there.is_some() {
                    pass.steps.push(Step::KeepBoth { path: path.clone(), kept: kept_name(path) });
                }
                pass.held.push(Held {
                    path: path.clone(),
                    reason: format!(
                        "{path} changed both on this computer and in the sandbox. Both versions are kept: yours, and the sandbox's as {}. Syncing this file goes on once only one is left.",
                        kept_name(path)
                    ),
                });
                record.common.remove(path);
            }
        }
    }
    // `conflicts: stop` means nothing is done at all, so a pass with any clash is thrown away
    // whole: no steps, no held files, no shared versions recorded. The person is told every file
    // that clashed rather than the first one, so fixing them is one round rather than many.
    if !clashing.is_empty() {
        let named = clashing.iter().take(CLASHES_NAMED).cloned().collect::<Vec<_>>().join(", ");
        let rest = clashing.len().saturating_sub(CLASHES_NAMED);
        let more = if rest > 0 { format!(" and {rest} more") } else { String::new() };
        let these = if clashing.len() == 1 { "it" } else { "them" };
        return Pass {
            stopped: Some(format!(
                "{named}{more} changed both on this computer and in the sandbox, so the sync stopped and changed nothing. Make {these} match, then press Try again to finish."
            )),
            ..Pass::default()
        };
    }
    // Only what matched by the end of the pass has a shared version again.
    for (path, checksum) in matched {
        record.unknown.remove(&path);
        match checksum {
            Some(checksum) => {
                record.common.insert(path, checksum);
            }
            None => {
                record.common.remove(&path);
            }
        }
    }
    pass
}

/// The checksum of every file under `root`, by its path relative to it with `/` separators.
/// Folders the launcher keeps per computer (`.git`, `node_modules`, …) are never exchanged, as in
/// two-way sync: their contents belong to the computer they are on.
pub(crate) fn scan(root: &Path) -> Result<Checksums, String> {
    use sha2::{Digest, Sha256};
    let mut found = Checksums::new();
    let mut folders = vec![(root.to_path_buf(), String::new())];
    while let Some((folder, relative)) = folders.pop() {
        if relative.split('/').count() > 128 {
            return Err("The folder has folders nested more than 128 levels deep.".into());
        }
        let entries = match fs::read_dir(&folder) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("The folder could not be read: {error}")),
        };
        for entry in entries {
            let entry = entry.map_err(|error| format!("The folder could not be read: {error}"))?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else { continue };
            if reconcile::host_only(&name) {
                continue;
            }
            let path = if relative.is_empty() { name } else { format!("{relative}/{name}") };
            let meta = match fs::symlink_metadata(entry.path()) {
                Ok(meta) => meta,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(format!("{path} could not be read: {error}")),
            };
            // Links are reported by neither side: following one would reach outside the folder.
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                folders.push((entry.path(), path));
            } else if meta.is_file() {
                let bytes = fs::read(entry.path()).map_err(|error| format!("{path} could not be read: {error}"))?;
                found.insert(path, format!("{:x}", Sha256::digest(&bytes)));
            }
        }
    }
    Ok(found)
}

/// Where a path of a synced folder is on this computer, refusing anything that would leave the
/// folder: the person's folder is reached exactly as far as it says and no further.
pub(crate) fn host_path(root: &Path, relative: &str) -> Result<PathBuf, String> {
    if let Some(reason) = unsupported(relative) {
        return Err(format!("{relative} is not a path this sync can use ({reason})."));
    }
    let mut path = root.to_path_buf();
    for part in relative.split('/') {
        path.push(part);
        if fs::symlink_metadata(&path).is_ok_and(|meta| meta.file_type().is_symlink()) {
            return Err(format!("A link is in the way of {relative}; it was left alone."));
        }
    }
    Ok(path)
}

/// One synced folder of a sandbox, as the plan resolved it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Folder {
    pub binding: String,
    /// The folder on this computer, as the person chose it.
    pub path: PathBuf,
    /// The folder inside the sandbox that holds the copy.
    pub target: String,
    pub read_only: bool,
    pub continuous: bool,
    pub conflicts: Conflicts,
}

/// The synced folders of a resolved sandbox specification.
pub(crate) fn folders(spec: &serde_json::Value) -> Vec<Folder> {
    spec["sync"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            let path = entry["path"].as_str().filter(|path| !path.is_empty())?;
            Some(Folder {
                binding: entry["binding"].as_str().unwrap_or_default().to_owned(),
                path: PathBuf::from(path),
                target: entry["target"].as_str().unwrap_or_default().trim_end_matches('/').to_owned(),
                read_only: entry["read_only"] != false,
                continuous: entry["continuous"] != false,
                conflicts: Conflicts::read(entry["conflicts"].as_str().unwrap_or_default()),
            })
        })
        .collect()
}

/// What moves the files of one pass. The engine's own implementation talks to the sandbox; tests
/// use a fake, so no real sandbox or folder of the person is touched.
pub(crate) trait Transfer: Send + Sync {
    fn files<'a>(&'a self, folder: &'a str) -> crate::setups::ordinary::BoxFuture<'a, Result<Checksums, String>>;
    fn send<'a>(&'a self, from: &'a Path, folder: &'a str, relative: &'a str) -> crate::setups::ordinary::BoxFuture<'a, Result<(), String>>;
    fn receive<'a>(&'a self, folder: &'a str, relative: &'a str, to: &'a Path) -> crate::setups::ordinary::BoxFuture<'a, Result<(), String>>;
    fn remove<'a>(&'a self, folder: &'a str, relative: &'a str) -> crate::setups::ordinary::BoxFuture<'a, Result<(), String>>;
}

/// What one finished pass has to say to the person.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Report {
    /// How many files travelled, either way.
    pub moved: usize,
    /// Files left as they are, with why: a conflict, a path this computer cannot store.
    pub held: Vec<Held>,
    /// Set when the pass stopped without changing anything.
    pub stopped: Option<String>,
}

impl Report {
    /// What the setup's health says about this folder, when there is anything to say.
    ///
    /// Two callers, and they differ on purpose. A pass that STOPPED did not sync the folder at
    /// all, so `ordinary.rs::sync_folders` fails the step with this as its message: a template
    /// asks for `conflicts: stop` so that a file changed on both sides is not passed over
    /// quietly. A pass that succeeded while holding files back — a conflict kept as both copies,
    /// a path this computer cannot store — did sync the rest, so it is not a failure; that line
    /// is kept on the record as `last` and read back into the setup's notes.
    pub(crate) fn note(&self, binding: &str) -> Option<String> {
        if let Some(stopped) = &self.stopped {
            return Some(format!("The folder you chose for {binding} is not syncing. {stopped}"));
        }
        let kept = self.held.len();
        (kept > 0).then(|| {
            let first = self.held.first().map(|held| held.reason.clone()).unwrap_or_default();
            match kept {
                1 => first,
                _ => format!("{first} {} other file(s) are waiting the same way.", kept - 1),
            }
        })
    }
}

/// Runs one pass over `folder`: reads both sides, decides every path with the shared rules, and
/// moves only what can be moved without losing an edit. The record is saved whatever happens, so
/// a pass that fails part way never makes the next one think a file was never synced.
pub(crate) async fn run(folder: &Folder, transfer: &dyn Transfer, record_path: &Path) -> Result<Report, String> {
    let local = scan(&folder.path)?;
    let remote = transfer.files(&folder.target).await?;
    let mut record = Record::load(record_path);
    let pass = plan_pass(&local, &remote, &mut record, folder.read_only, folder.conflicts);
    if let Some(stopped) = pass.stopped {
        // Nothing is done, but the pass still happened, so it is recorded: the step fails on this
        // and the line survives for the setup's notes even if nobody is watching the operation.
        let report = Report { stopped: Some(stopped), ..Report::default() };
        record.last = Some(last_pass(&report, now()));
        record.save(record_path)?;
        return Ok(report);
    }
    let mut report = Report { held: pass.held, ..Report::default() };
    let mut failed = None;
    for step in &pass.steps {
        let result = match step {
            Step::Send { path, gone: false } => match host_path(&folder.path, path) {
                Ok(from) => transfer.send(&from, &folder.target, path).await,
                Err(problem) => Err(problem),
            },
            Step::Send { path, gone: true } => transfer.remove(&folder.target, path).await,
            Step::Receive { path, gone: false } => match host_path(&folder.path, path) {
                Ok(to) => transfer.receive(&folder.target, path, &to).await,
                Err(problem) => Err(problem),
            },
            Step::Receive { path, gone: true } => match host_path(&folder.path, path) {
                // Deleting here is safe only because this computer's copy still matched what the
                // two last shared; anything else was a conflict and never reached this step.
                Ok(path) => match fs::remove_file(&path) {
                    Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.to_string()),
                    _ => Ok(()),
                },
                Err(problem) => Err(problem),
            },
            Step::KeepBoth { path, kept } => match host_path(&folder.path, kept) {
                Ok(to) => transfer.receive(&folder.target, path, &to).await,
                Err(problem) => Err(problem),
            },
        };
        match result {
            // A step that didn't happen has no shared version: the next pass sees it again.
            Err(problem) => {
                record.common.remove(step.path());
                failed.get_or_insert(format!("{} could not be synced: {problem}", step.path()));
            }
            Ok(()) if matches!(step, Step::KeepBoth { .. }) => {}
            Ok(()) => report.moved += 1,
        }
    }
    // A clean pass writes a `last` with nothing held, which clears whatever an earlier pass said.
    record.last = Some(last_pass(&report, now()));
    record.save(record_path)?;
    match failed {
        Some(problem) => Err(problem),
        None => Ok(report),
    }
}

/// Seconds since the epoch, or 0 on a computer whose clock is before it.
fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|since| since.as_secs() as i64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sums(pairs: &[(&str, &str)]) -> Checksums {
        pairs.iter().map(|(path, sum)| ((*path).to_owned(), (*sum).to_owned())).collect()
    }

    /// PROVES that an edit made on either side, in the same pass, reaches the other and that
    /// neither replaces the other: the plan's row for `dev-workspace` ("edits from both sides
    /// without silent loss").
    #[test]
    fn edits_on_both_sides_travel_and_nothing_is_lost() {
        let mut record = Record { common: sums(&[("here.txt", "a"), ("there.txt", "b"), ("same.txt", "c")]), ..Record::default() };
        // This computer edited here.txt; the sandbox edited there.txt; same.txt is untouched.
        let local = sums(&[("here.txt", "a2"), ("there.txt", "b"), ("same.txt", "c"), ("new-here.txt", "n")]);
        let remote = sums(&[("here.txt", "a"), ("there.txt", "b2"), ("same.txt", "c"), ("new-there.txt", "m")]);
        let pass = plan_pass(&local, &remote, &mut record, false, Conflicts::KeepBoth);
        assert!(pass.stopped.is_none());
        assert_eq!(
            pass.steps,
            vec![
                Step::Send { path: "here.txt".into(), gone: false },
                Step::Send { path: "new-here.txt".into(), gone: false },
                Step::Receive { path: "new-there.txt".into(), gone: false },
                Step::Receive { path: "there.txt".into(), gone: false },
            ],
            "each side's own edit travels to the other, and neither is overwritten"
        );
        assert!(pass.held.is_empty());
        // Both sides now hold the same versions, so the next pass has nothing to do.
        assert_eq!(record.common, sums(&[("here.txt", "a2"), ("new-here.txt", "n"), ("new-there.txt", "m"), ("same.txt", "c"), ("there.txt", "b2")]));
        let settled = plan_pass(&record.common.clone(), &record.common.clone(), &mut record, false, Conflicts::KeepBoth);
        assert!(settled.steps.is_empty() && settled.held.is_empty());
    }

    /// PROVES that a file changed in both places keeps both versions, visibly, and that the
    /// person's own copy is never written over.
    #[test]
    fn a_file_changed_in_both_places_keeps_both_copies() {
        let mut record = Record { common: sums(&[("code.txt", "base")]), ..Record::default() };
        let pass = plan_pass(&sums(&[("code.txt", "mine")]), &sums(&[("code.txt", "theirs")]), &mut record, false, Conflicts::KeepBoth);
        assert_eq!(pass.steps, vec![Step::KeepBoth { path: "code.txt".into(), kept: "code.txt.from-sandbox".into() }]);
        assert_eq!(pass.held.len(), 1);
        assert!(pass.held[0].reason.contains("Both versions are kept") && pass.held[0].reason.contains("code.txt.from-sandbox"), "{}", pass.held[0].reason);
        assert!(!record.common.contains_key("code.txt"), "the file has no shared version until the two match");
        // The kept copy is the person's to resolve: it is never synced back into the sandbox.
        let with_kept = sums(&[("code.txt", "mine"), ("code.txt.from-sandbox", "theirs")]);
        let next = plan_pass(&with_kept, &sums(&[("code.txt", "theirs")]), &mut record, false, Conflicts::KeepBoth);
        assert!(next.steps.iter().all(|step| step.path() == "code.txt"), "{:?}", next.steps);
        // Once the person makes them match, the file syncs again by itself.
        let settled = plan_pass(&sums(&[("code.txt", "theirs")]), &sums(&[("code.txt", "theirs")]), &mut record, false, Conflicts::KeepBoth);
        assert!(settled.steps.is_empty() && settled.held.is_empty());
        assert_eq!(record.common.get("code.txt").map(String::as_str), Some("theirs"));
    }

    #[test]
    fn stop_changes_nothing_at_all_and_names_every_file_that_clashed() {
        let mut record = Record { common: sums(&[("code.txt", "base"), ("other.txt", "x")]), ..Record::default() };
        let local = sums(&[("code.txt", "mine"), ("other.txt", "x2")]);
        let remote = sums(&[("code.txt", "theirs"), ("other.txt", "x")]);
        let pass = plan_pass(&local, &remote, &mut record, false, Conflicts::Stop);
        assert!(pass.steps.is_empty(), "nothing at all is done: {:?}", pass.steps);
        let said = pass.stopped.expect("it stops");
        assert!(said.contains("code.txt") && said.contains("changed nothing"), "{said}");
        // Starting a setup does not sync: `EnvironmentHandler::apply` returns for `Action::Start`
        // before it converges. So the person must never be sent to Start.
        assert!(said.contains("then press Try again to finish"), "{said}");
        assert!(!said.to_lowercase().contains("start the setup"), "Start does not sync: {said}");

        // PROVES every clashing file is named, not just the first: fixing them is one round.
        let many: Vec<(String, String, String)> = (0..13).map(|n| (format!("f{n:02}.txt"), format!("base{n}"), format!("mine{n}"))).collect();
        let mut record = Record {
            common: many.iter().map(|(path, base, _)| (path.clone(), base.clone())).collect(),
            ..Record::default()
        };
        let local: Checksums = many.iter().map(|(path, _, mine)| (path.clone(), mine.clone())).collect();
        let remote: Checksums = many.iter().map(|(path, _, _)| (path.clone(), "theirs".to_owned())).collect();
        let said = plan_pass(&local, &remote, &mut record, false, Conflicts::Stop).stopped.expect("it stops");
        assert!(said.contains("f00.txt") && said.contains("f09.txt"), "the first ten are named: {said}");
        assert!(said.contains("and 3 more"), "the rest are counted: {said}");
        assert!(said.contains("Make them match"), "more than one file reads as plural: {said}");
    }

    #[test]
    fn a_read_only_folder_is_never_changed_by_the_sandbox() {
        let mut record = Record { common: sums(&[("code.txt", "base"), ("gone.txt", "g")]), ..Record::default() };
        // The sandbox changed code.txt and deleted gone.txt; this computer added one file.
        let local = sums(&[("code.txt", "base"), ("gone.txt", "g"), ("new.txt", "n")]);
        let remote = sums(&[("code.txt", "theirs")]);
        let pass = plan_pass(&local, &remote, &mut record, true, Conflicts::KeepBoth);
        // Only this computer's new file travels. Nothing comes back, so the person's folder is
        // untouched; and the file the sandbox deleted is neither restored there nor deleted here,
        // because that change is waiting to travel the other way and this direction never
        // consumes it — the launcher's own rule for a one-way handoff.
        assert_eq!(pass.steps, vec![Step::Send { path: "new.txt".into(), gone: false }]);
        assert!(!pass.steps.iter().any(|step| matches!(step, Step::Receive { .. })), "nothing comes back into the person's folder");
        assert_eq!(record.common.get("code.txt").map(String::as_str), Some("base"), "what the sandbox changed is not recorded as shared");
        assert_eq!(record.common.get("gone.txt").map(String::as_str), Some("g"), "nor is what it deleted");
    }

    #[test]
    fn a_deletion_on_one_side_travels_but_only_from_what_both_last_had() {
        let mut record = Record { common: sums(&[("here.txt", "a"), ("there.txt", "b")]), ..Record::default() };
        // Each side deleted one file the other still has, unchanged.
        let pass = plan_pass(&sums(&[("there.txt", "b")]), &sums(&[("here.txt", "a")]), &mut record, false, Conflicts::KeepBoth);
        assert_eq!(pass.steps, vec![Step::Send { path: "here.txt".into(), gone: true }, Step::Receive { path: "there.txt".into(), gone: true }]);
        assert!(record.common.is_empty());
        // A deletion against an edit is a conflict, so the edit is never deleted silently.
        let mut record = Record { common: sums(&[("code.txt", "base")]), ..Record::default() };
        let pass = plan_pass(&Checksums::new(), &sums(&[("code.txt", "theirs")]), &mut record, false, Conflicts::KeepBoth);
        assert_eq!(pass.steps, vec![Step::KeepBoth { path: "code.txt".into(), kept: "code.txt.from-sandbox".into() }]);
    }

    /// PROVES that a record that cannot be read never decides which copy survives, as the
    /// launcher's own rule does (`sync::Saved::unreadable`).
    #[test]
    fn a_record_that_cannot_be_read_keeps_both_copies_until_they_match() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("sync.json");
        fs::write(&path, b"{ damaged").unwrap();
        let mut record = Record::load(&path);
        assert!(record.unreadable);
        let pass = plan_pass(&sums(&[("code.txt", "mine")]), &sums(&[("code.txt", "theirs")]), &mut record, false, Conflicts::KeepBoth);
        assert_eq!(pass.steps, vec![Step::KeepBoth { path: "code.txt".into(), kept: "code.txt.from-sandbox".into() }]);
        assert!(record.unknown.contains("code.txt"));
        // Saved and read back, that file still keeps both copies, though the record now reads.
        record.save(&path).unwrap();
        let mut again = Record::load(&path);
        assert!(!again.unreadable && again.unknown.contains("code.txt"));
        let pass = plan_pass(&sums(&[("code.txt", "mine")]), &sums(&[("code.txt", "theirs")]), &mut again, false, Conflicts::KeepBoth);
        assert!(matches!(pass.steps.first(), Some(Step::KeepBoth { .. })));
        // Once they match it is an ordinary file again.
        plan_pass(&sums(&[("code.txt", "same")]), &sums(&[("code.txt", "same")]), &mut again, false, Conflicts::KeepBoth);
        assert!(again.unknown.is_empty());
        // No record at all is a first sync, and a first sync still keeps both copies here.
        let first = Record::load(&folder.path().join("missing.json"));
        assert!(!first.unreadable && first.common.is_empty());
    }

    #[test]
    fn paths_that_cannot_be_stored_here_are_held_and_never_leave_the_folder() {
        let mut record = Record::default();
        let remote = sums(&[("fine.txt", "a"), ("a\\b", "b"), ("../escape", "c")]);
        let pass = plan_pass(&Checksums::new(), &remote, &mut record, false, Conflicts::KeepBoth);
        assert_eq!(pass.steps, vec![Step::Receive { path: "fine.txt".into(), gone: false }]);
        assert_eq!(pass.held.len(), 2, "{:?}", pass.held);
        assert!(pass.held.iter().all(|held| held.reason.contains("can't be synced")), "{:?}", pass.held);
        let folder = tempfile::tempdir().unwrap();
        assert!(host_path(folder.path(), "../escape").is_err());
        assert!(host_path(folder.path(), "a/b.txt").is_ok());
    }

    /// A sandbox's copy of the folder, as a folder on this computer: the test moves real bytes
    /// both ways without a sandbox, a container or anything of the person's.
    struct FakeSandbox {
        root: PathBuf,
    }

    impl FakeSandbox {
        fn at(&self, folder: &str, relative: &str) -> PathBuf {
            self.root.join(folder.trim_start_matches('/')).join(relative)
        }
        fn write(&self, folder: &str, relative: &str, text: &str) {
            let path = self.at(folder, relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        }
        fn read(&self, folder: &str, relative: &str) -> Option<String> {
            fs::read_to_string(self.at(folder, relative)).ok()
        }
    }

    impl Transfer for FakeSandbox {
        fn files<'a>(&'a self, folder: &'a str) -> crate::setups::ordinary::BoxFuture<'a, Result<Checksums, String>> {
            Box::pin(async move { scan(&self.root.join(folder.trim_start_matches('/'))) })
        }
        fn send<'a>(&'a self, from: &'a Path, folder: &'a str, relative: &'a str) -> crate::setups::ordinary::BoxFuture<'a, Result<(), String>> {
            Box::pin(async move {
                let to = self.at(folder, relative);
                fs::create_dir_all(to.parent().ok_or("no parent")?).map_err(|e| e.to_string())?;
                fs::copy(from, to).map_err(|e| e.to_string()).map(|_| ())
            })
        }
        fn receive<'a>(&'a self, folder: &'a str, relative: &'a str, to: &'a Path) -> crate::setups::ordinary::BoxFuture<'a, Result<(), String>> {
            Box::pin(async move {
                fs::create_dir_all(to.parent().ok_or("no parent")?).map_err(|e| e.to_string())?;
                fs::copy(self.at(folder, relative), to).map_err(|e| e.to_string()).map(|_| ())
            })
        }
        fn remove<'a>(&'a self, folder: &'a str, relative: &'a str) -> crate::setups::ordinary::BoxFuture<'a, Result<(), String>> {
            Box::pin(async move {
                match fs::remove_file(self.at(folder, relative)) {
                    Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.to_string()),
                    _ => Ok(()),
                }
            })
        }
    }

    /// PROVES, over real files on both sides, that a pass carries each side's edits to the other
    /// and that a file edited in both places keeps both versions: the acceptance row for
    /// `dev-workspace` in plan section 15.
    #[tokio::test]
    async fn a_pass_moves_both_sides_edits_and_keeps_a_conflict_visible() {
        let here = tempfile::tempdir().unwrap();
        let there = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let record = state.path().join("code.json");
        let sandbox = FakeSandbox { root: there.path().to_path_buf() };
        let folder = Folder {
            binding: "code".into(),
            path: here.path().to_path_buf(),
            target: "/workspace".into(),
            read_only: false,
            continuous: true,
            conflicts: Conflicts::KeepBoth,
        };
        let write_here = |path: &str, text: &str| {
            let at = here.path().join(path);
            fs::create_dir_all(at.parent().unwrap()).unwrap();
            fs::write(at, text).unwrap();
        };
        // First pass: the person's folder has the code; the sandbox's copy is empty.
        write_here("app.js", "one");
        write_here("src/lib.rs", "two");
        let report = run(&folder, &sandbox, &record).await.unwrap();
        assert_eq!((report.moved, report.held.len(), report.stopped.is_none()), (2, 0, true));
        assert_eq!(sandbox.read("/workspace", "app.js").as_deref(), Some("one"));
        assert_eq!(sandbox.read("/workspace", "src/lib.rs").as_deref(), Some("two"));
        // Nothing changed: a second pass moves nothing.
        assert_eq!(run(&folder, &sandbox, &record).await.unwrap().moved, 0);

        // Each side edits a different file, and each adds one.
        write_here("app.js", "one-here");
        sandbox.write("/workspace", "src/lib.rs", "two-there");
        write_here("notes.md", "mine");
        sandbox.write("/workspace", "out.txt", "built");
        let report = run(&folder, &sandbox, &record).await.unwrap();
        assert_eq!(report.moved, 4, "{report:?}");
        assert_eq!(sandbox.read("/workspace", "app.js").as_deref(), Some("one-here"));
        assert_eq!(fs::read_to_string(here.path().join("src/lib.rs")).unwrap(), "two-there", "the sandbox's edit reached this computer");
        assert_eq!(fs::read_to_string(here.path().join("out.txt")).unwrap(), "built");
        assert_eq!(sandbox.read("/workspace", "notes.md").as_deref(), Some("mine"));

        // The same file edited in both places: both versions are kept, neither is overwritten.
        write_here("app.js", "mine-now");
        sandbox.write("/workspace", "app.js", "theirs-now");
        let report = run(&folder, &sandbox, &record).await.unwrap();
        assert_eq!(report.moved, 0, "nothing was replaced");
        assert_eq!(fs::read_to_string(here.path().join("app.js")).unwrap(), "mine-now", "the person's file is untouched");
        assert_eq!(sandbox.read("/workspace", "app.js").as_deref(), Some("theirs-now"), "the sandbox keeps its own");
        assert_eq!(fs::read_to_string(here.path().join("app.js.from-sandbox")).unwrap(), "theirs-now", "the sandbox's version is kept beside it");
        let note = report.note("code").expect("the person is told");
        assert!(note.contains("app.js") && note.contains("Both versions are kept"), "{note}");

        // Resolving it by hand lets the file sync again; the conflict copy is the person's to
        // delete and is never sent into the sandbox.
        write_here("app.js", "theirs-now");
        fs::remove_file(here.path().join("app.js.from-sandbox")).unwrap();
        let report = run(&folder, &sandbox, &record).await.unwrap();
        assert_eq!((report.moved, report.held.len()), (0, 0), "{report:?}");
        assert!(sandbox.read("/workspace", "app.js.from-sandbox").is_none());

        // A deletion travels when the other side never touched the file.
        fs::remove_file(here.path().join("notes.md")).unwrap();
        let report = run(&folder, &sandbox, &record).await.unwrap();
        assert_eq!(report.moved, 1);
        assert!(sandbox.read("/workspace", "notes.md").is_none());
        // And removing the setup never touches the person's folder: nothing here does that.
        assert!(here.path().join("app.js").exists() && here.path().join("src/lib.rs").exists());
    }

    #[tokio::test]
    async fn stopping_on_a_conflict_changes_nothing_on_either_side() {
        let here = tempfile::tempdir().unwrap();
        let there = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let record = state.path().join("code.json");
        let sandbox = FakeSandbox { root: there.path().to_path_buf() };
        let folder = Folder {
            binding: "code".into(),
            path: here.path().to_path_buf(),
            target: "/workspace".into(),
            read_only: false,
            continuous: true,
            conflicts: Conflicts::Stop,
        };
        fs::write(here.path().join("app.js"), "one").unwrap();
        fs::write(here.path().join("other.txt"), "x").unwrap();
        assert_eq!(run(&folder, &sandbox, &record).await.unwrap().moved, 2);
        fs::write(here.path().join("app.js"), "mine").unwrap();
        sandbox.write("/workspace", "app.js", "theirs");
        fs::write(here.path().join("other.txt"), "x2").unwrap();
        let report = run(&folder, &sandbox, &record).await.unwrap();
        assert_eq!(report.moved, 0);
        assert!(report.stopped.as_deref().is_some_and(|said| said.contains("app.js")), "{report:?}");
        assert_eq!(sandbox.read("/workspace", "other.txt").as_deref(), Some("x"), "not even the file that was safe moved");
        assert!(report.note("code").unwrap().contains("not syncing"));
    }

    /// PROVES that what a pass held back survives the pass, so the setup can say so later. A
    /// stopped pass and a holding pass both leave a line; a clean one clears it.
    #[tokio::test]
    async fn what_a_pass_holds_back_is_kept_on_the_record_and_a_clean_pass_clears_it() {
        let here = tempfile::tempdir().unwrap();
        let there = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let record = state.path().join("code.json");
        let sandbox = FakeSandbox { root: there.path().to_path_buf() };
        let folder = Folder {
            binding: "code".into(),
            path: here.path().to_path_buf(),
            target: "/workspace".into(),
            read_only: false,
            continuous: true,
            conflicts: Conflicts::Stop,
        };
        fs::write(here.path().join("app.js"), "one").unwrap();
        run(&folder, &sandbox, &record).await.unwrap();
        // A clean pass says nothing worth saying.
        let clean = Record::load(&record);
        assert!(clean.last.is_some(), "a finished pass is always recorded");
        assert!(!clean.last.unwrap().worth_saying());

        // Now make it stop, and check the line outlives the call.
        fs::write(here.path().join("app.js"), "mine").unwrap();
        sandbox.write("/workspace", "app.js", "theirs");
        run(&folder, &sandbox, &record).await.unwrap();
        let stopped = Record::load(&record).last.expect("the stopped pass is recorded");
        assert!(stopped.worth_saying());
        assert!(stopped.report().note("code").unwrap().contains("not syncing"));
        assert!(stopped.at > 0, "it says when");

        // And that a later clean pass clears it rather than leaving a stale warning.
        sandbox.write("/workspace", "app.js", "mine");
        run(&folder, &sandbox, &record).await.unwrap();
        assert!(!Record::load(&record).last.unwrap().worth_saying(), "a folder that is syncing says nothing");
    }

    /// PROVES the downgrade claim rather than asserting it: a record written by this engine still
    /// loads in an engine that has never heard of `last`, and a record from before it loads here.
    #[test]
    fn a_record_travels_both_ways_between_engines_that_know_last_and_engines_that_do_not() {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct OlderRecord {
            #[serde(default)]
            common: Checksums,
            #[serde(default)]
            unknown: BTreeSet<String>,
        }
        let mine = Record {
            common: sums(&[("app.js", "a")]),
            last: Some(LastPass { at: 12, stopped: Some("app.js changed in both places.".into()), held: Vec::new(), held_total: 0 }),
            ..Record::default()
        };
        let written = serde_json::to_string(&mine).unwrap();
        // An older engine has no `deny_unknown_fields` here, so it reads the file and ignores the
        // field it does not know. It would drop `last` on its next save, which costs only the line.
        let older: OlderRecord = serde_json::from_str(&written).expect("an older engine still reads it");
        assert_eq!(older.common["app.js"], "a");
        assert!(older.unknown.is_empty());
        // And a record written before `last` existed is not treated as unreadable here.
        let state = tempfile::tempdir().unwrap();
        let path = state.path().join("old.json");
        fs::write(&path, r#"{"common":{"app.js":"a"},"unknown":[]}"#).unwrap();
        let before = Record::load(&path);
        assert!(!before.unreadable);
        assert!(before.last.is_none());
        assert_eq!(before.common["app.js"], "a");
    }

    /// PROVES the held list cannot grow without bound on disk: one folder of names this computer
    /// cannot store can hold thousands, and the record keeps the count rather than the list.
    #[test]
    fn the_held_list_is_capped_on_the_record_and_the_true_total_is_kept() {
        let held = (0..500).map(|n| Held { path: format!("bad{n}"), reason: "This computer cannot store this name.".into() }).collect();
        let last = last_pass(&Report { moved: 0, held, stopped: None }, 7);
        assert_eq!(last.held.len(), HELD_KEPT);
        assert_eq!(last.held_total, 500);
        assert!(last.worth_saying());
    }

    #[test]
    fn the_synced_folders_of_a_spec_are_read_as_the_plan_resolved_them() {
        let spec = serde_json::json!({"sync": [
            {"binding": "code", "target": "/workspace/", "path": "/home/sam/code", "read_only": false, "continuous": false, "conflicts": "stop"},
            {"binding": "notes", "target": "/notes", "path": "", "read_only": true, "continuous": true, "conflicts": "keep_both"},
        ]});
        let found = folders(&spec);
        assert_eq!(found.len(), 1, "a binding with no folder chosen syncs nothing");
        assert_eq!(found[0], Folder {
            binding: "code".into(),
            path: PathBuf::from("/home/sam/code"),
            target: "/workspace".into(),
            read_only: false,
            continuous: false,
            conflicts: Conflicts::Stop,
        });
        assert!(folders(&serde_json::json!({})).is_empty());
    }

    #[test]
    fn a_folder_is_read_without_what_each_computer_keeps_for_itself() {
        let folder = tempfile::tempdir().unwrap();
        for (path, text) in [("app.js", "1"), ("src/main.rs", "2"), (".git/config", "x"), ("node_modules/left/index.js", "y")] {
            let file = folder.path().join(path);
            fs::create_dir_all(file.parent().unwrap()).unwrap();
            fs::write(file, text).unwrap();
        }
        let found = scan(folder.path()).unwrap();
        assert_eq!(found.keys().cloned().collect::<Vec<_>>(), ["app.js", "src/main.rs"]);
        assert_eq!(found["app.js"].len(), 64);
        // A folder that is not there yet reads as empty, not as an error.
        assert!(scan(&folder.path().join("missing")).unwrap().is_empty());
    }
}
