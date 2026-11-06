//! The three-way sync rules, once shared with the project launcher's two-way sync (gone with the
//! launcher) and still used by the engine's folder sync for setups (`src-tauri/src/setups/folder_sync.rs`, which
//! includes this file). Only the side unchanged since the last shared checksum may be
//! overwritten; concurrent edits remain on both sides. Pure: no file is read or written here.
//!
//! Moved here unchanged from `sync.rs` and `live/two_way.rs`, so both syncs decide every path
//! the same way.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Priority { Local, Remote, #[default] KeepBoth }

/// A handoff never consumes changes waiting to travel in the other direction.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Direction { ToContainer, ToComputer, Both }
impl Direction {
    pub fn sends(self) -> bool { self != Self::ToComputer }
    pub fn receives(self) -> bool { self != Self::ToContainer }
}

/// Folders that tools manage separately on each computer: version-control metadata,
/// installed dependencies and interpreter caches. Two-way sync never exchanges them.
/// Their changes are invisible to a code review (`git diff`), yet hooks, package
/// binaries and bytecode in them run on this computer.
pub const HOST_ONLY: [&str; 7] = [".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__"];

/// A filename as case-insensitive filesystems compare it (NTFS, APFS, HFS+): ignoring
/// letter case, trailing dots and spaces (Windows) and the zero-width characters HFS+
/// ignores. The container helper (assets/two-way.cjs) folds names the same way.
pub fn folded(name: &str) -> String {
    let visible: String = name
        .chars()
        .filter(|c| !matches!(c, '\u{200c}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{206a}'..='\u{206f}' | '\u{feff}'))
        .collect();
    visible.trim_end_matches(['.', ' ']).to_uppercase()
}

/// Whether a path component names a HOST_ONLY folder, in any spelling this computer
/// may resolve to the same folder.
pub fn host_only(name: &str) -> bool {
    let name = folded(name);
    HOST_ONLY.iter().any(|protected| name == protected.to_uppercase())
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Change {
    Same,
    Push,
    Pull,
    Conflict,
}

pub fn prioritized(change: Change, priority: Priority) -> Change {
    if change != Change::Conflict { return change; }
    match priority { Priority::Local => Change::Push, Priority::Remote => Change::Pull, Priority::KeepBoth => Change::Conflict }
}

/// What happens to one path in a two-way pass. When the record of the last sync could not be
/// read (`unreadable`), nobody can tell which copy of a file that differs is newer, so it joins
/// `unknown` and keeps both copies whatever the priority, until the copies match. Taking that
/// record for a first sync let the pre-selected "This computer wins" push older copies over the
/// container's edits.
pub fn decide(ordinary: Change, path: &str, priority: Priority, unreadable: bool, unknown: &mut BTreeSet<String>) -> Change {
    match ordinary {
        Change::Conflict if unreadable => {
            unknown.insert(path.to_owned());
        }
        Change::Same => {
            unknown.remove(path);
        }
        _ => {}
    }
    prioritized(ordinary, if unknown.contains(path) { Priority::KeepBoth } else { priority })
}

/// How one path changed, from the checksum both sides last shared (`base`) and each side's
/// checksum now (`None`: the file is not there).
pub fn change<'a>(base: Option<&'a str>, local: Option<&'a str>, remote: Option<&'a str>) -> Change {
    if local == remote {
        Change::Same
    } else if local == base {
        Change::Pull
    } else if remote == base {
        Change::Push
    } else {
        Change::Conflict
    }
}

pub fn windows_device(part: &str) -> bool {
    let base = part.split('.').next().unwrap_or("").trim_end_matches(' ').to_ascii_uppercase();
    matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$")
        || ["COM", "LPT"].iter().any(|device| {
            base.strip_prefix(device).is_some_and(|n| matches!(n, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"))
        })
}

/// Why this computer cannot store a path, if it cannot. Windows rules apply only on Windows.
pub fn unsupported(relative: &str) -> Option<&'static str> {
    if relative.is_empty() || relative.len() > 4096 || relative.split('/').count() > 128 {
        return Some("too long or nested too deeply");
    }
    if relative.chars().any(|c| c.is_control() || c == '\\') {
        return Some("control characters or backslashes");
    }
    for part in relative.split('/') {
        if part.is_empty() || part == "." || part == ".." || part.starts_with(".yougori-sync-") {
            return Some("an empty or reserved name");
        }
        if cfg!(windows) {
            if part.ends_with(['.', ' ']) || part.contains(['<', '>', ':', '"', '|', '?', '*']) {
                return Some("characters Windows filenames cannot contain");
            }
            if windows_device(part) {
                return Some("a name Windows reserves for devices");
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_side_unchanged_since_the_last_sync_is_overwritten() {
        assert_eq!(change(Some("base"), Some("base"), Some("remote")), Change::Pull);
        assert_eq!(change(Some("base"), Some("local"), Some("base")), Change::Push);
        assert_eq!(change(Some("base"), Some("local"), Some("remote")), Change::Conflict);
        assert_eq!(change(Some("base"), None, Some("remote")), Change::Conflict);
        assert_eq!(change(None, Some("local"), Some("remote")), Change::Conflict);
        assert_eq!(change(None, Some("new"), None), Change::Push);
        assert_eq!(change(Some("same"), Some("same"), Some("same")), Change::Same);
        // Keep both is the default priority, and an unreadable record keeps both whatever it is.
        assert_eq!(Priority::default(), Priority::KeepBoth);
        let mut unknown = BTreeSet::new();
        assert_eq!(decide(Change::Conflict, "a", Priority::Local, true, &mut unknown), Change::Conflict);
        assert_eq!(decide(Change::Conflict, "a", Priority::Local, false, &mut unknown), Change::Conflict, "still unknown");
        assert_eq!(decide(Change::Same, "a", Priority::Local, false, &mut unknown), Change::Same);
        assert_eq!(decide(Change::Conflict, "a", Priority::Local, false, &mut unknown), Change::Push);
        assert!(Direction::ToContainer.sends() && !Direction::ToContainer.receives());
        assert!(host_only(".GIT") && host_only("node_modules") && !host_only(".github"));
    }
}
