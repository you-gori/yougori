//! Several Neo Grids on one computer, and the port allocator every grid product shares.
//!
//! The grid this computer had before instances existed is instance `default`. Its files stay
//! where they always were (`grid/hub.json`, `grid/member.json`, `grid/tunnel.json`,
//! `grid/neocloud.json`), its keys keep their names in the OS vault and its hub keeps ports 7460
//! and 7461, so an existing installation reads exactly as it did. Every grid made after it gets
//! a key of its own, `i-` and eight lowercase hex digits, a folder `grid/neo/<key>/` holding the
//! same file names, vault names ending in `-<key>`, and ports from [`allocate_ports`], stored in
//! its hub record.
//!
//! The first grid on a computer with none still goes in `default`: older builds, the rollout
//! and every tool that reads the legacy files keep seeing it.
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::Mutex,
};

pub(crate) const DEFAULT: &str = "default";
/// The ports new instances of every grid product take, in order.
pub(crate) const FIRST_PORT: u16 = 7480;
pub(crate) const LAST_PORT: u16 = 7599;
/// The products' and observer's fixed ports. Never handed out: an older build, or a product not
/// yet on instances, may open any of them at any time.
pub(crate) const FIXED_PORTS: std::ops::RangeInclusive<u16> = 7460..=7467;
/// Records larger than this are not read for their ports (a hub record is far smaller).
const RECORD_LIMIT: u64 = 32 * 1024 * 1024;

/// A new instance key: `i-` and eight lowercase hex digits.
pub(crate) fn new_key() -> String {
    format!("i-{}", &uuid::Uuid::new_v4().simple().to_string()[..8])
}

/// `default`, or a key [`new_key`] could have made. Anything else is never used as a folder name.
pub(crate) fn is_key(text: &str) -> bool {
    text == DEFAULT || text.len() == 10 && text.starts_with("i-") && text[2..].bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Where an instance's files live inside the `grid` data folder.
pub(crate) fn folder(grid: &Path, instance: &str) -> PathBuf {
    if instance == DEFAULT {
        grid.to_path_buf()
    } else {
        grid.join("neo").join(instance)
    }
}

/// One of an instance's files, under the same name for every instance.
pub(crate) fn file(grid: &Path, instance: &str, name: &str) -> PathBuf {
    folder(grid, instance).join(name)
}

/// An instance's name for a vault entry: the old name for `default`, `<name>-<key>` otherwise.
pub(crate) fn vault_name(base: &str, instance: &str) -> String {
    if instance == DEFAULT {
        base.to_owned()
    } else {
        format!("{base}-{instance}")
    }
}

/// The files that make an instance worth loading: a hub, a membership, or rented GPUs that may
/// still be billing.
const MARKERS: [&str; 3] = ["hub.json", "member.json", "neocloud.json"];

/// Every instance on disk: `default` first (always, so its legacy files are read whether or not
/// they exist), then each `grid/neo/<key>/` holding a hub, a membership or rented GPUs.
pub(crate) fn on_disk(grid: &Path) -> Vec<String> {
    let mut found = vec![DEFAULT.to_owned()];
    let Ok(entries) = std::fs::read_dir(grid.join("neo")) else { return found };
    let mut others: Vec<String> = entries
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name != DEFAULT && is_key(name))
        .filter(|name| MARKERS.iter().any(|marker| file(grid, name, marker).exists()))
        .collect();
    others.sort();
    found.extend(others);
    found
}

/// Removes an instance's folder once nothing is left in it. `default` is the grid folder itself
/// and is never removed.
pub(crate) fn tidy(grid: &Path, instance: &str) {
    if instance != DEFAULT {
        let _ = std::fs::remove_dir(folder(grid, instance));
    }
}

/// Visits every file under `grid`, at most three folders deep, whose name ends with `suffix`.
fn records(grid: &Path, suffix: &str, mut visit: impl FnMut(&Path)) {
    let mut stack = vec![(grid.to_path_buf(), 0u8)];
    while let Some((folder, depth)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&folder) else { continue };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            match entry.file_type() {
                Ok(kind) if kind.is_dir() && depth < 3 => stack.push((path, depth + 1)),
                Ok(kind) if kind.is_file() && entry.file_name().to_string_lossy().ends_with(suffix) => visit(&path),
                _ => {}
            }
        }
    }
}

fn read_small(path: &Path) -> Option<serde_json::Value> {
    if std::fs::metadata(path).ok()?.len() > RECORD_LIMIT {
        return None;
    }
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

/// Every port a hub record of any grid product on this computer holds: the `port` and
/// `tunnelPort` of each `*hub.json` under the `grid` data folder (`hub.json`, `desks-hub.json`,
/// `access-hub.json`, and the same inside any instance folder).
pub(crate) fn recorded_ports(grid: &Path) -> BTreeSet<u16> {
    let mut ports = BTreeSet::new();
    records(grid, "hub.json", |path| {
        if let Some(record) = read_small(path) {
            for key in ["port", "tunnelPort"] {
                if let Some(port) = record[key].as_u64().and_then(|port| u16::try_from(port).ok()).filter(|port| *port != 0) {
                    ports.insert(port);
                }
            }
        }
    });
    ports
}

/// The saved Cloudflare domains the grids on this computer tunnel through, from every
/// `*tunnel.json` under the `grid` data folder, each with the file that names it.
pub(crate) fn tunnel_domains(grid: &Path) -> Vec<(PathBuf, String)> {
    let mut found = Vec::new();
    records(grid, "tunnel.json", |path| {
        if let Some(domain) = read_small(path).filter(|setup| setup["kind"] == "domain").and_then(|setup| setup["domain"].as_str().map(str::to_owned)) {
            found.push((path.to_path_buf(), domain));
        }
    });
    found
}

/// Ports handed out in this run and not yet released; a record holding them may not be written yet.
static RESERVED: Mutex<BTreeSet<u16>> = Mutex::new(BTreeSet::new());

/// Picks `count` free ports for a new instance of any grid product: from 7480 to 7599, never
/// 7460 to 7467, skipping every port a hub record of any product holds ([`recorded_ports`]),
/// every port handed out earlier in this run and not released, and every port that fails to bind
/// on this computer now.
///
/// The ports stay reserved in this process until [`release_ports`]. A create that fails after
/// this call must release them; one that succeeds may release them once its record is written,
/// since the record keeps them out from then on, or keep them reserved, which is harmless.
pub(crate) fn allocate_ports(grid: &Path, count: usize) -> Result<Vec<u16>, String> {
    let recorded = recorded_ports(grid);
    let mut reserved = RESERVED.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let picked = pick(&recorded, &reserved, count, bindable)?;
    reserved.extend(picked.iter().copied());
    Ok(picked)
}

/// Gives back ports [`allocate_ports`] handed out. Ports it did not hand out are ignored.
pub(crate) fn release_ports(ports: &[u16]) {
    let mut reserved = RESERVED.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    for port in ports {
        reserved.remove(port);
    }
}

fn bindable(port: u16) -> bool {
    std::net::TcpListener::bind(("0.0.0.0", port)).is_ok() && std::net::TcpListener::bind(("127.0.0.1", port)).is_ok()
}

fn pick(recorded: &BTreeSet<u16>, reserved: &BTreeSet<u16>, count: usize, bindable: impl Fn(u16) -> bool) -> Result<Vec<u16>, String> {
    let picked: Vec<u16> = (FIRST_PORT..=LAST_PORT)
        .filter(|port| !FIXED_PORTS.contains(port) && !recorded.contains(port) && !reserved.contains(port))
        .filter(|port| bindable(*port))
        .take(count)
        .collect();
    if picked.len() < count {
        return Err(format!(
            "No free port is left between {FIRST_PORT} and {LAST_PORT} for another grid on this computer. Delete a grid you no longer use, or close the program holding those ports, and try again."
        ));
    }
    Ok(picked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn write(path: &Path, value: serde_json::Value) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
    }

    #[test]
    fn the_default_instance_keeps_every_old_name_and_a_new_one_gets_its_own() {
        let grid = Path::new("data").join("grid");
        assert_eq!(file(&grid, DEFAULT, "hub.json"), grid.join("hub.json"));
        assert_eq!(file(&grid, DEFAULT, "member.json"), grid.join("member.json"));
        assert_eq!(file(&grid, DEFAULT, "tunnel.json"), grid.join("tunnel.json"));
        assert_eq!(file(&grid, DEFAULT, "neocloud.json"), grid.join("neocloud.json"));
        assert_eq!(vault_name("yougori-grid-hub-key", DEFAULT), "yougori-grid-hub-key");
        let key = new_key();
        assert!(is_key(&key) && key.starts_with("i-") && key.len() == 10, "{key}");
        assert_ne!(key, new_key(), "two new instances never share a key");
        assert_eq!(file(&grid, &key, "hub.json"), grid.join("neo").join(&key).join("hub.json"));
        assert_eq!(vault_name("yougori-grid-member-token", &key), format!("yougori-grid-member-token-{key}"));
        for bad in ["", "i-", "i-1234567", "i-123456789", "i-ABCDEF12", "../hub", "i-12/45678", "neo"] {
            assert!(!is_key(bad), "{bad}");
        }
    }

    #[test]
    fn instances_on_disk_are_default_and_every_folder_that_holds_a_grid() {
        let root = tempfile::tempdir().unwrap();
        let grid = root.path().join("grid");
        assert_eq!(on_disk(&grid), [DEFAULT], "default is always read, so its legacy files are found");
        write(&grid.join("neo").join("i-0000beef").join("member.json"), json!({}));
        write(&grid.join("neo").join("i-0000abcd").join("hub.json"), json!({}));
        std::fs::create_dir_all(grid.join("neo").join("i-00000001")).unwrap();
        std::fs::create_dir_all(grid.join("neo").join("not-a-key")).unwrap();
        write(&grid.join("neo").join("not-a-key").join("hub.json"), json!({}));
        assert_eq!(on_disk(&grid), [DEFAULT, "i-0000abcd", "i-0000beef"], "an empty folder or a stray name is not an instance");
        tidy(&grid, "i-00000001");
        assert!(!grid.join("neo").join("i-00000001").exists());
        tidy(&grid, "i-0000beef");
        assert!(grid.join("neo").join("i-0000beef").exists(), "a folder with files in it stays");
        tidy(&grid, DEFAULT);
        assert!(grid.exists());
    }

    #[test]
    fn ports_come_from_the_shared_range_and_skip_what_any_product_recorded() {
        let root = tempfile::tempdir().unwrap();
        let grid = root.path().join("grid");
        write(&grid.join("hub.json"), json!({"port": 7460, "tunnelPort": 7461}));
        write(&grid.join("neo").join("i-0000abcd").join("hub.json"), json!({"port": 7480, "tunnelPort": 7481}));
        write(&grid.join("desks-hub.json"), json!({"port": 7463}));
        write(&grid.join("desks").join("i-00000001").join("desks-hub.json"), json!({"port": 7482}));
        write(&grid.join("access").join("i-00000002").join("access-hub.json"), json!({"port": 7484, "tunnelPort": 7485}));
        write(&grid.join("member.json"), json!({"port": 7483}));
        let recorded = recorded_ports(&grid);
        assert_eq!(recorded, BTreeSet::from([7460, 7461, 7463, 7480, 7481, 7482, 7484, 7485]), "only hub records hold ports");
        let picked = pick(&recorded, &BTreeSet::new(), 2, |_| true).unwrap();
        assert_eq!(picked, [7483, 7486]);
        let picked = pick(&recorded, &BTreeSet::from([7483]), 2, |port| port != 7486).unwrap();
        assert_eq!(picked, [7487, 7488], "reserved and unbindable ports are skipped");
        assert!(picked.iter().all(|port| !FIXED_PORTS.contains(port) && (FIRST_PORT..=LAST_PORT).contains(port)));
        let refused = pick(&recorded, &BTreeSet::new(), 200, |_| true).unwrap_err();
        assert!(refused.contains("No free port") && refused.contains("try again"), "{refused}");
    }

    #[test]
    fn a_released_port_can_be_handed_out_again() {
        let root = tempfile::tempdir().unwrap();
        let grid = root.path().join("grid");
        let first = allocate_ports(&grid, 2).unwrap();
        assert_eq!(first.len(), 2);
        let second = allocate_ports(&grid, 1).unwrap();
        assert!(!first.contains(&second[0]), "a port handed out and not released is not handed out twice");
        release_ports(&first);
        release_ports(&second);
        let reserved = RESERVED.lock().unwrap();
        assert!(first.iter().chain(&second).all(|port| !reserved.contains(port)));
    }

    #[test]
    fn tunnel_domains_are_read_from_every_products_tunnel_file() {
        let root = tempfile::tempdir().unwrap();
        let grid = root.path().join("grid");
        write(&grid.join("tunnel.json"), json!({"kind": "domain", "domain": "grid.acme.example"}));
        write(&grid.join("desks-tunnel.json"), json!({"kind": "quick"}));
        write(&grid.join("neo").join("i-0000abcd").join("tunnel.json"), json!({"kind": "domain", "domain": "two.acme.example"}));
        let mut domains: Vec<String> = tunnel_domains(&grid).into_iter().map(|(_, domain)| domain).collect();
        domains.sort();
        assert_eq!(domains, ["grid.acme.example", "two.acme.example"]);
    }
}
