//! Read-only adopted setups for the grids that predate setups: Neo Grid, Sandbox Grid (desks),
//! Access Grid and Swarm Mining. Each is found by the existence of its own saved records under
//! the engine's data folder. Only file metadata is read: no record is opened, so nothing here can
//! get in the way of a product saving its own files (the live Swarm worker above all), and no
//! key, certificate or secret is ever read. Nothing here starts, stops or migrates anything.
//!
//! Their state is not observed: an adopted setup says it is managed from its own tab, never
//! that it is running or stopped (invariant 16). A record that exists but can't be looked at is
//! shown as unreadable, never left out.
//!
//! These are temporary legacy views (plan 19.2) until each product moves to the setup engine.
use super::views::{Detail, OperationBrief};
use std::{fs, io::ErrorKind, path::Path, time::UNIX_EPOCH};
use yougori_setup::dto;

const PREFIX: &str = "adopted-";

/// One legacy deployment's records, as their own modules name them (`grid.rs`, `deskgrid.rs`,
/// `desks.rs`, `accessgrid.rs`, `bounty.rs`, `swarm/mod.rs`). Paths are relative to the engine
/// data folder.
struct Known {
    id: &'static str,
    profile: dto::GridProfile,
    role: &'static str,
    name: &'static str,
    file: &'static str,
}

const KNOWN: &[Known] = &[
    Known { id: "neo-grid-hub", profile: dto::GridProfile::NeoGrid, role: "hub", name: "Neo Grid (hub on this computer)", file: "grid/hub.json" },
    Known { id: "neo-grid-member", profile: dto::GridProfile::NeoGrid, role: "member", name: "Neo Grid (this computer is a member)", file: "grid/member.json" },
    Known { id: "sandbox-grid-hub", profile: dto::GridProfile::SandboxGrid, role: "hub", name: "Sandbox Grid (hub on this computer)", file: "grid/desks-hub.json" },
    Known { id: "sandbox-grid-member", profile: dto::GridProfile::SandboxGrid, role: "member", name: "Sandbox Grid (this computer is a member)", file: "grid/desks-member.json" },
    Known { id: "sandbox-grid-desks", profile: dto::GridProfile::SandboxGrid, role: "desks", name: "Desks hosted on this computer", file: "grid/desks.json" },
    Known { id: "access-grid-hub", profile: dto::GridProfile::AccessGrid, role: "hub", name: "Access Grid (hub on this computer)", file: "grid/access-hub.json" },
    Known { id: "access-grid-member", profile: dto::GridProfile::AccessGrid, role: "member", name: "Access Grid (this computer is a member)", file: "grid/access-member.json" },
    Known { id: "swarm-mining-hub", profile: dto::GridProfile::SwarmMiningGrid, role: "hub", name: "Swarm Mining (hub on this computer)", file: "bounty/host.json" },
    Known { id: "swarm-mining-workers", profile: dto::GridProfile::SwarmMiningGrid, role: "workers", name: "Swarm Mining workers", file: "swarm/workers.json" },
];

/// A product's later grids: the folder each one has under the data folder (`grid/neo/<key>/` and
/// so on), and its records by the same names as the first grid's, as the product's own
/// `instances` module lays them out. The first grid of each kind is in `KNOWN`.
struct Later {
    folder: &'static str,
    profile: dto::GridProfile,
    product: &'static str,
    /// The id `KNOWN` gives the first grid's record, its file name and role, and what it is.
    records: &'static [(&'static str, &'static str, &'static str, &'static str)],
}

const LATER: &[Later] = &[
    Later {
        folder: "grid/neo",
        profile: dto::GridProfile::NeoGrid,
        product: "Neo Grid",
        records: &[("neo-grid-hub", "hub.json", "hub", "hub on this computer"), ("neo-grid-member", "member.json", "member", "this computer is a member")],
    },
    Later {
        folder: "grid/desks",
        profile: dto::GridProfile::SandboxGrid,
        product: "Sandbox Grid",
        records: &[
            ("sandbox-grid-hub", "desks-hub.json", "hub", "hub on this computer"),
            ("sandbox-grid-member", "desks-member.json", "member", "this computer is a member"),
            ("sandbox-grid-desks", "desks.json", "desks", "desks hosted on this computer"),
        ],
    },
    Later {
        folder: "grid/access",
        profile: dto::GridProfile::AccessGrid,
        product: "Access Grid",
        records: &[("access-grid-hub", "access-hub.json", "hub", "hub on this computer"), ("access-grid-member", "access-member.json", "member", "this computer is a member")],
    },
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Adopted {
    pub id: String,
    pub profile: dto::GridProfile,
    pub role: &'static str,
    pub name: String,
    pub readable: bool,
    pub found_at: i64,
    pub note: String,
    /// The product's own key for a later grid of its kind (`i-` and eight hex digits); `None` for
    /// the first one, whose records are where they always were.
    pub instance: Option<String>,
}

pub(crate) fn is_adopted_id(id: &str) -> bool {
    id.starts_with(PREFIX)
}

/// Whether an adopted setup is Swarm Mining's, which My setups doesn't list: what is said about
/// it never sends anyone there.
pub(crate) fn is_swarm_mining_id(id: &str) -> bool {
    id.strip_prefix(PREFIX).is_some_and(|id| KNOWN.iter().any(|known| known.id == id && known.profile == dto::GridProfile::SwarmMiningGrid))
}

/// The legacy deployments whose records exist under `root`: the first grid of each kind, then each
/// later one in the products' own instance folders, by product and key.
pub(crate) fn scan(root: &Path) -> Vec<Adopted> {
    let mut found: Vec<Adopted> = KNOWN.iter().filter_map(|known| inspect(root, &root.join(known.file), known.id, known.profile, known.role, known.name.to_owned(), None)).collect();
    for later in LATER {
        for key in instance_keys(&root.join(later.folder)) {
            for (id, file, role, what) in later.records {
                let path = root.join(later.folder).join(&key).join(file);
                let name = format!("{} ({what}, {key})", later.product);
                found.extend(inspect(root, &path, &format!("{id}-{key}"), later.profile, role, name, Some(key.clone())));
            }
        }
    }
    // A Neo hub is a member of its own grid and keeps a record of that too: one deployment, so
    // one entry, the hub. The same for each later Neo Grid.
    let hubs: Vec<String> = found.iter().filter(|record| record.profile == dto::GridProfile::NeoGrid && record.role == "hub").map(|record| record.id.clone()).collect();
    found.into_iter().filter(|record| !(record.role == "member" && record.profile == dto::GridProfile::NeoGrid && hubs.contains(&record.id.replacen("neo-grid-member", "neo-grid-hub", 1)))).collect()
}

/// The later grids a product keeps under `folder`, by key, in key order. A folder whose name is
/// not a key the product could have made is not one of them and is left alone.
fn instance_keys(folder: &Path) -> Vec<String> {
    let mut keys: Vec<String> = fs::read_dir(folder)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name != crate::grid::instances::DEFAULT && crate::grid::instances::is_key(name))
        .collect();
    keys.sort();
    keys
}

fn inspect(_root: &Path, path: &Path, id: &str, profile: dto::GridProfile, role: &'static str, name: String, instance: Option<String>) -> Option<Adopted> {
    let (readable, found_at) = match fs::symlink_metadata(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => return None,
        Err(_) => (false, 0),
        Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => (false, 0),
        Ok(metadata) => (
            true,
            metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                .map(|elapsed| elapsed.as_secs() as i64)
                .unwrap_or(0),
        ),
    };
    let note = if !readable {
        "Yougori found this but can't look at its records. They were left untouched.".to_owned()
    } else if profile == dto::GridProfile::SwarmMiningGrid {
        "Left as it is and managed on its own, not from here. Its state isn't checked, and nothing here can start it.".to_owned()
    } else {
        "Managed from its own tab here for now; Yougori doesn't check its state yet.".to_owned()
    };
    Some(Adopted {
        id: format!("{PREFIX}{id}"),
        profile,
        role,
        name: if readable { name } else { format!("{name} (can't be read)") },
        readable,
        found_at,
        note,
        instance,
    })
}

impl Adopted {
    pub(crate) fn summary(&self) -> dto::SetupSummary {
        dto::SetupSummary {
            setup_id: self.id.clone(),
            name: self.name.clone(),
            source: dto::SourceRef::InstalledSetup { setup_id: self.id.clone() },
            // Not observed (`state_observed: false`). `stopped` because it never implies that
            // something runs or can be started from here.
            state: dto::InstanceState::Stopped,
            state_observed: false,
            profile: Some(self.profile),
            adopted_legacy: true,
            health: None,
            created_at: self.found_at,
            current_operation: None,
        }
    }

    pub(crate) fn detail(&self) -> Detail {
        Detail {
            setup: dto::SetupDetail {
                summary: self.summary(),
                revision: 0,
                capabilities: Vec::new(),
                resources: Vec::new(),
                outputs: Vec::new(),
                actions: Vec::new(),
                views: Vec::new(),
            },
            operations: Vec::<OperationBrief>::new(),
            notes: vec![self.note.clone()],
            readable: self.readable,
            customization: None,
            lock: None,
            resource_details: Default::default(),
            product: None,
            product_unavailable: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, relative: &str, content: &[u8]) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    #[test]
    fn a_neo_hub_and_its_own_membership_are_one_entry() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "grid/hub.json", b"{}");
        write(root.path(), "grid/member.json", b"{}");
        let ids: Vec<String> = scan(root.path()).into_iter().map(|record| record.id).collect();
        assert_eq!(ids, [format!("{PREFIX}neo-grid-hub")]);
        // A computer that only joined someone's Neo Grid still shows its membership.
        let member = tempfile::tempdir().unwrap();
        write(member.path(), "grid/member.json", b"{}");
        let ids: Vec<String> = scan(member.path()).into_iter().map(|record| record.id).collect();
        assert_eq!(ids, [format!("{PREFIX}neo-grid-member")]);
    }

    /// PROVES that every grid a product keeps is found, not only the first of each kind: each later
    /// one by its product's own key, read-only and named so it can be told apart, while a folder
    /// that isn't a key and an empty one are left alone.
    #[test]
    fn later_grids_of_each_kind_are_found_by_their_own_keys() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "grid/hub.json", b"{}");
        write(root.path(), "grid/neo/i-0000abcd/hub.json", b"{}");
        write(root.path(), "grid/neo/i-0000abcd/member.json", b"{}");
        write(root.path(), "grid/neo/i-0000beef/member.json", b"{}");
        write(root.path(), "grid/desks/i-0000c0de/desks-hub.json", b"{}");
        write(root.path(), "grid/access/i-0000f00d/access-member.json", b"{}");
        write(root.path(), "grid/neo/not-a-key/hub.json", b"{}");
        fs::create_dir_all(root.path().join("grid/desks/i-00000000")).unwrap();
        let found = scan(root.path());
        let ids = found.iter().map(|record| record.id.as_str()).collect::<Vec<_>>();
        assert_eq!(ids, [
            "adopted-neo-grid-hub",
            "adopted-neo-grid-hub-i-0000abcd",
            "adopted-neo-grid-member-i-0000beef",
            "adopted-sandbox-grid-hub-i-0000c0de",
            "adopted-access-grid-member-i-0000f00d",
        ], "a later Neo hub's own membership is one entry with it, as the first one's is");
        let later = found.iter().find(|record| record.id == "adopted-sandbox-grid-hub-i-0000c0de").unwrap();
        assert_eq!(later.name, "Sandbox Grid (hub on this computer, i-0000c0de)");
        assert_eq!((later.role, later.instance.as_deref()), ("hub", Some("i-0000c0de")));
        assert!(later.summary().adopted_legacy && !later.summary().state_observed);
        assert_eq!(found[0].instance, None, "the first grid is where it always was");
    }

    #[test]
    fn nothing_is_adopted_from_an_empty_folder() {
        let root = tempfile::tempdir().unwrap();
        assert!(scan(root.path()).is_empty());
    }

    #[test]
    fn existing_grids_are_adopted_read_only_with_no_state_claimed_and_files_untouched() {
        let root = tempfile::tempdir().unwrap();
        let secret = br#"{"password":"SECRET-HUB","certificate":"-----BEGIN-----"}"#;
        let files = ["grid/hub.json", "grid/desks-member.json", "grid/access-hub.json", "bounty/host.json", "swarm/workers.json"];
        for file in files {
            write(root.path(), file, secret);
        }
        let before = files.map(|file| {
            let path = root.path().join(file);
            (fs::read(&path).unwrap(), fs::metadata(&path).unwrap().modified().unwrap())
        });
        let adopted = scan(root.path());
        let ids = adopted.iter().map(|record| record.id.as_str()).collect::<Vec<_>>();
        assert_eq!(
            ids,
            ["adopted-neo-grid-hub", "adopted-sandbox-grid-member", "adopted-access-grid-hub", "adopted-swarm-mining-hub", "adopted-swarm-mining-workers"]
        );
        for record in &adopted {
            let summary = record.summary();
            assert!(summary.adopted_legacy && !summary.state_observed);
            assert_eq!(summary.state, dto::InstanceState::Stopped);
            let shown = serde_json::to_string(&record.detail()).unwrap();
            assert!(!shown.contains("SECRET"));
            assert!(record.detail().setup.actions.is_empty());
            // Where it is managed is said without sending anyone to a page that is gone.
            assert!(!record.note.contains("page"), "{}", record.note);
            assert_eq!(is_swarm_mining_id(&record.id), record.profile == dto::GridProfile::SwarmMiningGrid, "{}", record.id);
        }
        let after = files.map(|file| {
            let path = root.path().join(file);
            (fs::read(&path).unwrap(), fs::metadata(&path).unwrap().modified().unwrap())
        });
        assert_eq!(before, after);
    }

    #[test]
    fn unreadable_records_are_shown_not_omitted() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("grid/hub.json")).unwrap();
        let adopted = scan(root.path());
        assert_eq!(adopted.len(), 1);
        assert!(!adopted[0].readable);
        assert!(adopted[0].name.ends_with("(can't be read)"));
    }
}
