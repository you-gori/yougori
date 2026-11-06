//! Several Access Grids on one computer: where each one keeps its files and what its keys are
//! called in the OS vault.
//!
//! The Access Grid a computer had before there could be several is instance `default`. Its files
//! stay where they always were (`grid/access-hub.json`, `access-member.json`, `access-tunnel.json`
//! and the activity log beside them), its keys keep their names (`yougori-access-hub-key`,
//! `yougori-access-hub-seal`, `yougori-access-device`) and its ports stay 7465 and 7466. Nothing of
//! it is moved or renamed.
//!
//! Every other Access Grid gets a local key, `i-` and eight hex digits, a folder
//! `grid/access/<key>/` holding the same file names (so its activity log is its own), and key
//! names ending in `-<key>`. The seal key is what keeps a grid's credentials readable: a second
//! grid writing over the first one's would leave the first one's credentials sealed for good. So
//! a new instance is only ever given a key whose folder does not exist and whose every key name
//! the vault says it does not hold, and writing a key checks once more just before (the caller's
//! job, see `src-tauri/src/accessgrid.rs`).
use std::path::{Path, PathBuf};

/// The instance a computer's first Access Grid is, under its old names.
pub const DEFAULT: &str = "default";
pub const HUB_FILE: &str = "access-hub.json";
pub const MEMBER_FILE: &str = "access-member.json";
pub const TUNNEL_FILE: &str = "access-tunnel.json";
pub const ACTIVITY_FILE: &str = "access-activity.jsonl";
/// The folder under `grid/` that holds every instance but the default one.
pub const FOLDER: &str = "access";
pub const HUB_KEY: &str = "yougori-access-hub-key";
pub const SEAL_KEY: &str = "yougori-access-hub-seal";
/// A computer's device token: it signs the person in again by itself.
pub const DEVICE_TOKEN: &str = "yougori-access-device";
/// The MCP server name agents know the default instance's broker by.
pub const MCP_NAME: &str = "yougori-access";
/// The default instance's ports, beside the Neo Grid (7460/7461), a closed bounty (7462) and the
/// Sandbox Grid (7463/7464). Other instances have theirs allocated and kept in their record.
pub const DEFAULT_PORT: u16 = 7465;
pub const DEFAULT_TUNNEL_PORT: u16 = 7466;
/// At most this many instances are read from disk; a folder holding more is not an Access Grid
/// anybody made by hand.
pub const MOST: usize = 64;
/// How many fresh keys are tried before giving up. Eight hex digits rarely clash at all.
const TRIES: usize = 16;

/// Whether `text` is an instance key: `default`, or `i-` and eight lowercase hex digits.
pub fn is_key(text: &str) -> bool {
    text == DEFAULT || text.strip_prefix("i-").is_some_and(|rest| rest.len() == 8 && rest.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
}

/// A new random instance key.
pub fn new_key() -> String {
    format!("i-{}", &crate::token()[..8])
}

/// What one instance's keys are called in the OS vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Names {
    pub hub_key: String,
    pub seal_key: String,
    pub device: String,
}

impl Names {
    pub fn of(key: &str) -> Names {
        if key == DEFAULT {
            Names { hub_key: HUB_KEY.into(), seal_key: SEAL_KEY.into(), device: DEVICE_TOKEN.into() }
        } else {
            Names { hub_key: format!("{HUB_KEY}-{key}"), seal_key: format!("{SEAL_KEY}-{key}"), device: format!("{DEVICE_TOKEN}-{key}") }
        }
    }

    pub fn all(&self) -> [&str; 3] {
        [&self.hub_key, &self.seal_key, &self.device]
    }
}

/// One instance's place on disk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layout {
    root: PathBuf,
    key: String,
}

impl Layout {
    /// Instance `key` under `root`, the engine's `grid` data folder.
    pub fn new(root: &Path, key: &str) -> Result<Layout, String> {
        if !is_key(key) {
            return Err(format!("'{key}' is not an Access Grid instance on this computer"));
        }
        Ok(Layout { root: root.to_owned(), key: key.to_owned() })
    }

    /// The computer's first Access Grid, where it always was.
    pub fn default_in(root: &Path) -> Layout {
        Layout { root: root.to_owned(), key: DEFAULT.into() }
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn is_default(&self) -> bool {
        self.key == DEFAULT
    }

    /// The folder holding this instance's files: `grid/` itself for the default instance.
    pub fn folder(&self) -> PathBuf {
        if self.is_default() {
            self.root.clone()
        } else {
            self.root.join(FOLDER).join(&self.key)
        }
    }

    pub fn hub(&self) -> PathBuf {
        self.folder().join(HUB_FILE)
    }

    pub fn member(&self) -> PathBuf {
        self.folder().join(MEMBER_FILE)
    }

    pub fn tunnel(&self) -> PathBuf {
        self.folder().join(TUNNEL_FILE)
    }

    /// The activity log, in the instance's own folder. `hub::activity_path` of `hub()` is the
    /// same file.
    pub fn activity(&self) -> PathBuf {
        self.folder().join(ACTIVITY_FILE)
    }

    pub fn names(&self) -> Names {
        Names::of(&self.key)
    }

    /// The MCP server name for this instance's broker: the old one for the default instance.
    pub fn mcp_name(&self) -> String {
        if self.is_default() {
            MCP_NAME.into()
        } else {
            format!("{MCP_NAME}-{}", self.key)
        }
    }

    /// Whether a hub or a sign-in is recorded here.
    pub fn in_use(&self) -> bool {
        self.hub().exists() || self.member().exists()
    }

    /// Removes a non-default instance's folder once nothing is left in it. Only an empty folder
    /// is removed, so nothing anybody kept there is lost; the default folder is `grid/` and is
    /// never touched.
    pub fn tidy(&self) {
        if !self.is_default() && !self.in_use() {
            let _ = std::fs::remove_file(self.tunnel());
            let _ = std::fs::remove_dir(self.folder());
        }
    }
}

/// Every instance with a hub or a sign-in recorded under `root`: the default one first, then the
/// others by key.
pub fn on_disk(root: &Path) -> Vec<String> {
    let mut found = Vec::new();
    if Layout::default_in(root).in_use() {
        found.push(DEFAULT.to_owned());
    }
    let mut others: Vec<String> = std::fs::read_dir(root.join(FOLDER))
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .filter_map(|entry| entry.file_name().to_str().map(str::to_owned))
        .filter(|key| key != DEFAULT && is_key(key))
        .filter(|key| Layout::new(root, key).is_ok_and(|layout| layout.in_use()))
        .take(MOST)
        .collect();
    others.sort();
    found.extend(others);
    found
}

/// A new instance under `root` whose folder does not exist and none of whose key names the vault
/// holds. `held` answers whether the vault holds a name, or that it could not be asked, which
/// stops everything: a name that might be in use is never handed out.
pub fn fresh(root: &Path, mut held: impl FnMut(&str) -> Result<bool, String>) -> Result<Layout, String> {
    for _ in 0..TRIES {
        let layout = Layout::new(root, &new_key())?;
        if layout.folder().exists() {
            continue;
        }
        let mut free = true;
        for name in layout.names().all() {
            if held(name)? {
                free = false;
                break;
            }
        }
        if free {
            return Ok(layout);
        }
    }
    Err("Yougori could not find a free name for another Access Grid on this computer. Nothing was changed; try again.".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn the_first_access_grid_keeps_every_old_name() {
        let root = Path::new("grid");
        let layout = Layout::default_in(root);
        assert_eq!(layout.hub(), root.join("access-hub.json"));
        assert_eq!(layout.member(), root.join("access-member.json"));
        assert_eq!(layout.tunnel(), root.join("access-tunnel.json"));
        assert_eq!(layout.activity(), root.join("access-activity.jsonl"));
        assert_eq!(layout.activity(), super::super::hub::activity_path(&layout.hub()));
        assert_eq!(layout.names(), Names { hub_key: "yougori-access-hub-key".into(), seal_key: "yougori-access-hub-seal".into(), device: "yougori-access-device".into() });
        assert_eq!(layout.mcp_name(), "yougori-access");
        assert_eq!(Layout::new(root, "default").unwrap(), layout);
    }

    #[test]
    fn another_access_grid_has_its_own_folder_names_and_activity_log() {
        let root = Path::new("grid");
        let layout = Layout::new(root, "i-0a1b2c3d").unwrap();
        assert_eq!(layout.hub(), root.join("access").join("i-0a1b2c3d").join("access-hub.json"));
        assert_eq!(layout.member(), root.join("access").join("i-0a1b2c3d").join("access-member.json"));
        assert_eq!(layout.activity(), root.join("access").join("i-0a1b2c3d").join("access-activity.jsonl"));
        // The activity log follows the record's own folder, never the old shared file.
        assert_eq!(super::super::hub::activity_path(&layout.hub()), layout.activity());
        assert_ne!(layout.activity(), Layout::default_in(root).activity());
        assert_eq!(layout.names().all(), ["yougori-access-hub-key-i-0a1b2c3d", "yougori-access-hub-seal-i-0a1b2c3d", "yougori-access-device-i-0a1b2c3d"]);
        assert_eq!(layout.mcp_name(), "yougori-access-i-0a1b2c3d");
        // Every name stays within what the vault takes (letters, digits, dashes; at most 80).
        assert!(layout.names().all().iter().all(|name| name.len() <= 80 && name.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')));
    }

    #[test]
    fn only_well_formed_keys_name_an_instance() {
        for key in ["default", "i-00000000", "i-abcdef12"] {
            assert!(is_key(key), "{key}");
        }
        for key in ["", "i-", "i-ABCDEF12", "i-abcdef1", "i-abcdef123", "x-abcdef12", "../evil", "i-abcdef1g", "Default"] {
            assert!(!is_key(key), "{key}");
            assert!(Layout::new(Path::new("grid"), key).is_err(), "{key}");
        }
        for _ in 0..64 {
            assert!(is_key(&new_key()));
        }
    }

    #[test]
    fn instances_on_disk_are_found_with_the_default_first() {
        let folder = tempfile::tempdir().unwrap();
        let root = folder.path();
        assert!(on_disk(root).is_empty());
        std::fs::create_dir_all(root.join("access").join("i-bbbbbbbb")).unwrap();
        std::fs::write(root.join("access").join("i-bbbbbbbb").join(MEMBER_FILE), "{}").unwrap();
        std::fs::create_dir_all(root.join("access").join("i-aaaaaaaa")).unwrap();
        std::fs::write(root.join("access").join("i-aaaaaaaa").join(HUB_FILE), "{}").unwrap();
        // An empty instance folder and a folder that is not an instance are both passed over.
        std::fs::create_dir_all(root.join("access").join("i-cccccccc")).unwrap();
        std::fs::create_dir_all(root.join("access").join("not-one")).unwrap();
        std::fs::write(root.join("access").join("not-one").join(HUB_FILE), "{}").unwrap();
        assert_eq!(on_disk(root), ["i-aaaaaaaa", "i-bbbbbbbb"]);
        std::fs::write(root.join(MEMBER_FILE), "{}").unwrap();
        assert_eq!(on_disk(root), ["default", "i-aaaaaaaa", "i-bbbbbbbb"]);
        // A tunnel file alone is no instance.
        std::fs::remove_file(root.join(MEMBER_FILE)).unwrap();
        std::fs::write(root.join(TUNNEL_FILE), "{}").unwrap();
        assert_eq!(on_disk(root), ["i-aaaaaaaa", "i-bbbbbbbb"]);
    }

    #[test]
    fn a_fresh_instance_never_takes_a_name_the_vault_holds_or_a_folder_that_exists() {
        let folder = tempfile::tempdir().unwrap();
        let root = folder.path();
        // The vault holds the default names and, for the first key tried, a seal key already.
        let mut asked = Vec::new();
        let mut first = None::<String>;
        let layout = fresh(root, |name| {
            asked.push(name.to_owned());
            if first.is_none() && name.starts_with(SEAL_KEY) {
                first = Some(name.to_owned());
                return Ok(true);
            }
            Ok(false)
        })
        .unwrap();
        assert!(!layout.is_default() && !layout.folder().exists());
        assert_ne!(Some(layout.names().seal_key.clone()), first, "the held seal name was handed out");
        let names = layout.names();
        let held: HashSet<&str> = names.all().into_iter().collect();
        assert!(held.iter().all(|name| asked.iter().any(|asked| asked == name)), "every name was asked about before it was handed out");
        // A vault that will not answer stops it; nothing is guessed.
        assert!(fresh(root, |_| Err("The OS credential vault would not answer".into())).unwrap_err().contains("would not answer"));
        // A vault that holds every name gives up plainly.
        assert!(fresh(root, |_| Ok(true)).unwrap_err().contains("Nothing was changed"));
    }

    #[test]
    fn only_an_emptied_instance_folder_is_tidied_away() {
        let folder = tempfile::tempdir().unwrap();
        let layout = Layout::new(folder.path(), "i-12345678").unwrap();
        std::fs::create_dir_all(layout.folder()).unwrap();
        std::fs::write(layout.hub(), "{}").unwrap();
        layout.tidy();
        assert!(layout.hub().exists());
        std::fs::remove_file(layout.hub()).unwrap();
        std::fs::write(layout.folder().join("kept.txt"), "x").unwrap();
        layout.tidy();
        assert!(layout.folder().exists(), "a folder holding anything else is left alone");
        std::fs::remove_file(layout.folder().join("kept.txt")).unwrap();
        layout.tidy();
        assert!(!layout.folder().exists());
        // The default instance's folder is grid/ itself and is never removed.
        let default = Layout::default_in(folder.path());
        default.tidy();
        assert!(folder.path().exists());
    }
}
