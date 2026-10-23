//! The Access Grid's activity log: one JSON line per use, refusal, decision, sign-in and change,
//! appended beside the hub's record. Each line carries a MAC over itself and the previous line's
//! MAC, keyed from the hub's sealing key, so a line edited, removed or slipped in afterwards
//! breaks the chain where it happened. It shows tampering by anyone without the hub's OS vault;
//! it is not a substitute for copying the log somewhere the hub's own administrators cannot write.
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    io::Write,
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
};

/// Entries kept in memory for the page.
pub const KEPT: usize = 2000;
/// The file is moved aside to `.1` past this size; the chain carries on across the two.
const FILE_LIMIT: u64 = 8 * 1024 * 1024;

/// One line of the activity log.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub at: i64,
    /// The username, or empty for an unknown caller.
    pub person: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub agent: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub computer: String,
    /// `use`, `reveal`, `approve`, `deny`, `signin` or `change`.
    pub action: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub credential: String,
    /// `METHOD https://host/path`, never the query.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub target: String,
    pub outcome: String,
    /// The previous line's MAC.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub prev: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mac: String,
}

fn mac(key: &[u8], prev: &str, entry: &Entry) -> String {
    let bare = Entry { prev: String::new(), mac: String::new(), ..entry.clone() };
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(prev.as_bytes());
    mac.update(b"\n");
    mac.update(serde_json::to_string(&bare).unwrap_or_default().as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// The key the chain is made with, from the hub's sealing key.
pub fn chain_key(seal_key: &str) -> Vec<u8> {
    Sha256::digest(format!("yougori-access-activity:{}", seal_key.trim()).as_bytes()).to_vec()
}

struct State {
    last: String,
    recent: VecDeque<Entry>,
}

pub struct Log {
    path: PathBuf,
    key: Vec<u8>,
    state: Mutex<State>,
}

/// One file of the log: its entries, and how many of its lines could not be read as one. A file
/// that is not there holds none; any other failure to read it is an error, never an empty log.
fn read(path: &Path) -> Result<(Vec<Entry>, usize), String> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), 0)),
        Err(error) => return Err(format!("{} could not be read ({error})", path.display())),
    };
    let mut entries = Vec::new();
    let mut unreadable = 0;
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        match serde_json::from_str(line) {
            Ok(entry) => entries.push(entry),
            Err(_) => unreadable += 1,
        }
    }
    Ok((entries, unreadable))
}

/// Both files of the log, oldest first, with how many lines could not be read.
fn read_all(path: &Path) -> Result<(Vec<Entry>, usize), String> {
    let (mut entries, older) = read(&path.with_extension("jsonl.1"))?;
    let (newer, unreadable) = read(path)?;
    entries.extend(newer);
    Ok((entries, older + unreadable))
}

impl Log {
    pub fn open(path: PathBuf, key: Vec<u8>) -> Log {
        // A log that cannot be read now starts its chain afresh; `verify` then shows the break, or
        // says the log cannot be read, rather than passing it.
        let entries = read_all(&path).map(|(entries, _)| entries).unwrap_or_default();
        let last = entries.last().map(|entry| entry.mac.clone()).unwrap_or_default();
        let skip = entries.len().saturating_sub(KEPT);
        Log { path, key, state: Mutex::new(State { last, recent: entries.into_iter().skip(skip).collect() }) }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn append(&self, mut entry: Entry) {
        let mut state = self.lock();
        entry.prev = state.last.clone();
        entry.mac = mac(&self.key, &entry.prev, &entry);
        if let Ok(line) = serde_json::to_string(&entry) {
            if std::fs::metadata(&self.path).is_ok_and(|meta| meta.len() > FILE_LIMIT) {
                let _ = std::fs::rename(&self.path, self.path.with_extension("jsonl.1"));
            }
            if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&self.path) {
                let _ = writeln!(file, "{line}");
            }
        }
        state.last = entry.mac.clone();
        state.recent.push_back(entry);
        while state.recent.len() > KEPT {
            state.recent.pop_front();
        }
    }

    /// The latest `count` entries, newest first, without their MACs.
    pub fn recent(&self, count: usize) -> Vec<Entry> {
        self.lock().recent.iter().rev().take(count).map(|entry| Entry { prev: String::new(), mac: String::new(), ..entry.clone() }).collect()
    }

    /// Up to `count` entries from the files, oldest first, with their MACs, for an auditor to keep.
    /// A log that cannot be read is an error, never an empty export.
    pub fn export(&self, count: usize) -> Result<Vec<Entry>, String> {
        let _state = self.lock();
        let (entries, _) = read_all(&self.path).map_err(|reason| format!("The activity log could not be exported: {reason}"))?;
        let skip = entries.len().saturating_sub(count);
        Ok(entries.into_iter().skip(skip).collect())
    }

    /// Checks the chain through both files: `{ok, entries, brokenAt?, reason?}`. The first line
    /// kept is trusted as the start, since older lines were rotated away.
    /// A log that cannot be read, holds a line that is not an entry, or no longer ends with the
    /// last entry this hub wrote (deleted, cut short or replaced since) is never passed.
    pub fn verify(&self) -> Value {
        let state = self.lock();
        let (entries, unreadable) = match read_all(&self.path) {
            Ok(read) => read,
            Err(reason) => return json!({"ok": false, "entries": 0, "reason": format!("the activity log could not be read: {reason}")}),
        };
        for (index, entry) in entries.iter().enumerate() {
            if index > 0 && entry.prev != entries[index - 1].mac {
                return json!({"ok": false, "entries": entries.len(), "brokenAt": index + 1, "at": entry.at, "reason": "a line before this one was removed, added or reordered"});
            }
            if mac(&self.key, &entry.prev, entry) != entry.mac {
                return json!({"ok": false, "entries": entries.len(), "brokenAt": index + 1, "at": entry.at, "reason": "this line was changed after it was written"});
            }
        }
        if unreadable > 0 {
            return json!({"ok": false, "entries": entries.len(), "reason": format!("{unreadable} line(s) of the activity log could not be read as an entry")});
        }
        if !state.last.is_empty() && entries.last().map(|entry| entry.mac.as_str()) != Some(state.last.as_str()) {
            return json!({"ok": false, "entries": entries.len(), "reason": "the latest entries this hub wrote are missing: the log was deleted, cut short or replaced"});
        }
        json!({"ok": true, "entries": entries.len()})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(at: i64, outcome: &str) -> Entry {
        Entry { at, person: "ada".into(), action: "use".into(), outcome: outcome.into(), ..Entry::default() }
    }

    /// PROVES that a log which is gone, cut short, garbled or unreadable is never vouched for.
    ///
    /// Any failure to read a file was taken for no entries, and lines that could not be parsed
    /// were dropped, so `verify` called a deleted log ok with 0 entries and never noticed a
    /// garbled last line, and an auditor's export of an unreadable log came back empty and was
    /// written over their earlier one as "Wrote 0 activity entries".
    #[test]
    fn a_log_that_is_gone_cut_short_or_unreadable_is_never_vouched_for() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("access-activity.jsonl");
        let log = Log::open(path.clone(), chain_key("k"));
        assert_eq!(log.verify(), json!({"ok": true, "entries": 0}), "a hub that has written nothing has nothing missing");
        for at in 0..4 {
            log.append(entry(at, "sent"));
        }
        let text = std::fs::read_to_string(&path).unwrap();

        std::fs::remove_file(&path).unwrap();
        assert_eq!(log.verify()["ok"], false, "a deleted log is not ok with 0 entries");

        std::fs::write(&path, text.lines().take(2).map(|line| format!("{line}\n")).collect::<String>()).unwrap();
        assert_eq!(log.verify()["ok"], false, "a log cut short of what this hub wrote is not ok");

        std::fs::write(&path, format!("{text}{{\"at\": 9, \"person\": \"ad")).unwrap();
        assert_eq!(Log::open(path.clone(), chain_key("k")).verify()["ok"], false, "a line that cannot be read is not passed over");

        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let unreadable = Log::open(path.clone(), chain_key("k"));
        assert_eq!(unreadable.verify()["ok"], false, "a log that cannot be read is not an empty one");
        assert!(unreadable.export(10).is_err(), "and an auditor's export of it is an error, never an empty file");
    }

    #[test]
    fn the_chain_survives_reopening_and_shows_any_edit() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("access-activity.jsonl");
        let log = Log::open(path.clone(), chain_key("k"));
        for at in 0..5 {
            log.append(entry(at, "sent"));
        }
        assert_eq!(log.verify()["ok"], true);
        assert_eq!(log.recent(2)[0].at, 4);
        assert!(log.recent(1)[0].mac.is_empty(), "the page gets entries without their MACs");
        let reopened = Log::open(path.clone(), chain_key("k"));
        reopened.append(entry(5, "sent"));
        assert_eq!(reopened.verify(), json!({"ok": true, "entries": 6}));
        assert_eq!(reopened.export(3).unwrap().len(), 3);
        assert_eq!(Log::open(path.clone(), chain_key("other")).verify()["ok"], false, "another key cannot vouch for the chain");

        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replacen("\"outcome\":\"sent\"", "\"outcome\":\"refused\"", 1)).unwrap();
        let tampered = Log::open(path.clone(), chain_key("k")).verify();
        assert_eq!((tampered["ok"].as_bool(), tampered["brokenAt"].as_u64()), (Some(false), Some(1)));

        std::fs::write(&path, text.lines().enumerate().filter(|(index, _)| *index != 2).map(|(_, line)| format!("{line}\n")).collect::<String>()).unwrap();
        let removed = Log::open(path, chain_key("k")).verify();
        assert_eq!((removed["ok"].as_bool(), removed["brokenAt"].as_u64()), (Some(false), Some(3)));
    }
}
