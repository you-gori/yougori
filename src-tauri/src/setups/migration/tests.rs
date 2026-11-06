//! Migration dry-run tests. Every one of them builds its own folder in a temporary directory:
//! nothing here reads, copies or touches this computer's real Yougori data folder, and nothing
//! here runs, starts or stops any product.
use super::*;
use std::collections::BTreeMap;

fn write(root: &Path, relative: &str, content: &[u8]) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
}

/// A folder that looks like a Yougori data folder with every product deployed, and files that Neo
/// Grid and Sandbox Grid left behind before they were removed from the product.
fn full_folder(root: &Path) {
    write(root, "grid/hub.json", br#"{"name":"office","port":7460,"computers":[{"id":"a"},{"id":"b"}]}"#);
    write(root, "grid/tunnel.json", br#"{"domain":"example.invalid","token":"SECRET-TOKEN"}"#);
    write(root, "grid/neocloud.json", br#"{"pods":[{"id":"p1"}]}"#);
    write(root, "grid/desks-hub.json", br#"{"name":"desks","port":7463}"#);
    write(root, "grid/desks.json", br#"{"desks":[{"id":"d1"},{"id":"d2"},{"id":"d3"}]}"#);
    write(root, "grid/desk-parcels.json", br#"{"parcels":[{"id":"x"}]}"#);
    write(root, "grid/access-hub.json", br#"{"people":[{"id":"p"},{"id":"q"}],"groups":[{"id":"g"}],"seal":"SECRET-SEAL"}"#);
    write(root, "grid/access-tunnel.json", br#"{"kind":"domain","domain":"access.example.invalid"}"#);
    write(root, "bounty/host.json", br#"{"project":"private","password":"SECRET-HUB"}"#);
    fs::create_dir_all(root.join("bounty/imports")).unwrap();
    write(root, "swarm/workers.json", br#"{"workers":{"w1":{"name":"one"},"w2":{"name":"two"}}}"#);
    fs::create_dir_all(root.join("grid/images")).unwrap();
    write(root, "hub/instances/my-api/instance.json", br#"{"schema":1,"name":"my-api","updatedAt":5}"#);
    write(root, "hub/instances/shop/instance.json", br#"{"schema":1,"name":"shop","updatedAt":6}"#);
}

/// Every file under `root`, with its SHA-256 and its last-changed time. Used to prove a reading
/// changed nothing at all.
fn fingerprint(root: &Path) -> BTreeMap<String, (String, u64, Option<SystemTime>)> {
    fn walk(root: &Path, at: &Path, into: &mut BTreeMap<String, (String, u64, Option<SystemTime>)>) {
        let Ok(entries) = fs::read_dir(at) else { return };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(metadata) = fs::symlink_metadata(&path) else { continue };
            if metadata.is_dir() {
                into.insert(format!("dir:{}", path.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/")), (String::new(), 0, None));
                walk(root, &path, into);
            } else {
                let name = path.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
                let (checksum, bytes) = checksum_of(&path).unwrap_or_else(|_| ("unreadable".into(), 0));
                into.insert(name, (checksum, bytes, metadata.modified().ok()));
            }
        }
    }
    let mut into = BTreeMap::new();
    walk(root, root, &mut into);
    into
}

#[test]
fn an_inventory_lists_every_product_with_counts_and_checksums_and_no_contents() {
    let folder = tempfile::tempdir().unwrap();
    full_folder(folder.path());
    let taken = inventory(folder.path());

    assert!(!taken.empty);
    assert_eq!(taken.totals.products_present, 2);
    assert_eq!(taken.totals.records_unreadable, 0);
    assert_eq!(taken.totals.instances, 2);

    let hub = taken.products.iter().flat_map(|p| &p.records).find(|r| r.id == "access-grid/hub").unwrap();
    match &hub.found {
        Found::Present { checksum, bytes, counts, summarised } => {
            assert!(checksum.starts_with("sha256:") && checksum.len() == 71);
            assert!(*bytes > 0 && !summarised);
            assert_eq!((counts.get("people"), counts.get("groups")), (Some(&2), Some(&1)));
        }
        other => panic!("expected a present record, got {other:?}"),
    }
    assert_eq!(
        taken.products.iter().flat_map(|p| &p.records).find(|r| r.id == "swarm-mining/workers").map(|r| match &r.found {
            Found::Present { counts, .. } => counts.get("workers").copied(),
            _ => None,
        }),
        Some(Some(2))
    );

    // Nothing confidential is ever in the output.
    let shown = serde_json::to_string(&taken).unwrap();
    for secret in ["SECRET-TOKEN", "SECRET-SEAL", "SECRET-HUB", "example.invalid", "office"] {
        assert!(!shown.contains(secret), "the inventory leaked {secret}");
    }
    // Nor is the folder that was read.
    assert!(!shown.contains(&folder.path().to_string_lossy().replace('\\', "/")));
    // What the removed products left behind is not a record of anything here.
    assert!(!shown.contains("\"grid/hub.json\"") && !shown.contains("desks"));
}

#[test]
fn a_missing_product_is_simply_absent_and_an_empty_folder_says_so() {
    let folder = tempfile::tempdir().unwrap();
    write(folder.path(), "grid/hub.json", b"{}");
    let taken = inventory(folder.path());
    let access = taken.products.iter().find(|p| p.product == Product::AccessGrid).unwrap();
    assert!(!access.present);
    assert!(access.records.iter().all(|r| r.found == Found::Missing));
    // Still listed, so a person sees it was looked for.
    assert_eq!(access.records.len(), 3);

    let nothing = tempfile::tempdir().unwrap();
    let taken = inventory(nothing.path());
    assert!(taken.empty);
    assert!(taken.notes.iter().any(|note| note.contains("Nothing of Yougori's was found here")));
}

#[test]
fn an_unreadable_record_is_reported_as_unreadable_not_omitted() {
    let folder = tempfile::tempdir().unwrap();
    // A folder where a record should be: present, but not something Yougori can read.
    fs::create_dir_all(folder.path().join("grid/access-hub.json")).unwrap();
    let taken = inventory(folder.path());
    let hub = taken.products.iter().flat_map(|p| &p.records).find(|r| r.id == "access-grid/hub").unwrap();
    assert!(matches!(hub.found, Found::Unreadable { .. }));
    assert_eq!(taken.totals.records_unreadable, 1);
    assert!(taken.products.iter().find(|p| p.product == Product::AccessGrid).unwrap().present);
    assert!(taken.notes.iter().any(|note| note.contains("could not be read")));
}

#[test]
fn a_huge_record_and_a_crowded_folder_are_summarised_never_streamed_whole() {
    let folder = tempfile::tempdir().unwrap();
    write(folder.path(), "grid/access-hub.json", &vec![b'x'; (READ_LIMIT + 1024) as usize]);
    for n in 0..(ENTRY_LIMIT + 5) {
        write(folder.path(), &format!("bounty/imports/{n}.bin"), b"i");
    }
    let taken = inventory(folder.path());
    let hub = taken.products.iter().flat_map(|p| &p.records).find(|r| r.id == "access-grid/hub").unwrap();
    match &hub.found {
        Found::Present { summarised, counts, bytes, .. } => {
            assert!(*summarised && counts.is_empty() && *bytes == READ_LIMIT + 1024);
        }
        other => panic!("expected a present record, got {other:?}"),
    }
    let images = taken.products.iter().flat_map(|p| &p.folders).find(|f| f.id == "swarm-mining/imports").unwrap();
    assert!(images.present && images.at_least && images.entries == ENTRY_LIMIT as u64);
    assert!(taken.notes.iter().any(|note| note.contains("too large to look inside")));
}

#[test]
fn a_backup_carries_the_records_with_checksums_and_verify_agrees() {
    let folder = tempfile::tempdir().unwrap();
    full_folder(folder.path());
    let into = tempfile::tempdir().unwrap();
    let destination = into.path().join("backup");

    let taken = inventory(folder.path());
    let manifest = backup(folder.path(), &destination, &taken).unwrap();
    // Four records plus two template instances; what the removed products left behind is not carried.
    assert_eq!(manifest.files.len(), 4 + 2);
    assert!(manifest.files.iter().all(|file| !file.file.starts_with("records/grid/hub") && !file.file.contains("desk")));
    assert!(manifest.left_behind.is_empty());
    assert!(manifest.files.iter().all(|file| file.checksum.starts_with("sha256:")));
    assert!(manifest.cannot_carry.iter().any(|said| said.contains("credential store")));
    assert!(manifest.cannot_carry.iter().any(|said| said.contains("sealed")));
    assert!(manifest.notes.iter().any(|note| note.contains("not a rollback")));

    let checked = verify(&destination).unwrap();
    assert!(checked.good);
    assert_eq!(checked.checked, checked.matched);
    assert_eq!(checked.problems, Vec::new());
    assert!(!checked.cannot_carry.is_empty());
}

#[test]
fn verify_names_a_file_that_changed_or_went_missing() {
    let folder = tempfile::tempdir().unwrap();
    full_folder(folder.path());
    let into = tempfile::tempdir().unwrap();
    let destination = into.path().join("backup");
    let taken = inventory(folder.path());
    backup(folder.path(), &destination, &taken).unwrap();

    fs::write(destination.join("records/grid/access-hub.json"), b"{}").unwrap();
    fs::remove_file(destination.join("records/bounty/host.json")).unwrap();
    let checked = verify(&destination).unwrap();
    assert!(!checked.good);
    assert!(checked.problems.iter().any(|problem| problem.id == "access-grid/hub" && problem.what.contains("not the same")));
    assert!(checked.problems.iter().any(|problem| problem.id == "swarm-mining/host" && problem.what.contains("missing")));
    assert!(checked.notes.iter().any(|note| note.contains("not complete")));
}

#[test]
fn a_backup_refuses_a_folder_that_already_holds_something_and_lists_what_it_could_not_copy() {
    let folder = tempfile::tempdir().unwrap();
    write(folder.path(), "grid/hub.json", b"{}");
    let into = tempfile::tempdir().unwrap();
    write(into.path(), "already/there.txt", b"hello");
    let refusal = backup(folder.path(), into.path(), &inventory(folder.path())).unwrap_err();
    assert_eq!(refusal.code, "backup_folder");
    assert!(refusal.message.contains("already holds something"));

    // An unreadable record is named, not quietly skipped.
    let awkward = tempfile::tempdir().unwrap();
    fs::create_dir_all(awkward.path().join("grid/access-hub.json")).unwrap();
    let into = tempfile::tempdir().unwrap();
    let destination = into.path().join("backup");
    let manifest = backup(awkward.path(), &destination, &inventory(awkward.path())).unwrap();
    assert!(manifest.files.is_empty());
    assert_eq!(manifest.left_behind.len(), 1);
    assert_eq!(manifest.left_behind[0].id, "access-grid/hub");
    assert!(!verify(&destination).unwrap().good);
}

#[test]
fn verify_refuses_a_folder_that_is_not_a_backup_and_a_newer_one() {
    let empty = tempfile::tempdir().unwrap();
    assert_eq!(verify(empty.path()).unwrap_err().code, "not_a_backup");
    fs::write(empty.path().join("manifest.json"), b"not json").unwrap();
    assert_eq!(verify(empty.path()).unwrap_err().code, "not_a_backup");
    fs::write(empty.path().join("manifest.json"), br#"{"manifestVersion":99,"madeAt":0,"files":[],"leftBehind":[],"cannotCarry":[],"notes":[]}"#).unwrap();
    assert_eq!(verify(empty.path()).unwrap_err().code, "newer_backup");
}

#[test]
fn verify_never_follows_an_entry_out_of_the_backup_folder() {
    let backup_folder = tempfile::tempdir().unwrap();
    fs::write(
        backup_folder.path().join("manifest.json"),
        br#"{"manifestVersion":1,"madeAt":0,"files":[{"id":"x","file":"../outside.json","bytes":1,"checksum":"sha256:0"}],"leftBehind":[],"cannotCarry":[],"notes":[]}"#,
    )
    .unwrap();
    let checked = verify(backup_folder.path()).unwrap();
    assert!(!checked.good);
    assert!(checked.problems[0].what.contains("outside the backup folder"));
}

#[test]
fn a_rehearsal_says_what_each_adoption_would_create_and_names_every_difference() {
    let folder = tempfile::tempdir().unwrap();
    full_folder(folder.path());
    let rehearsed = rehearse(folder.path());

    // What adoption would create for the products that are still part of Yougori, by the same ids
    // as `adopt::scan`.
    let ids: Vec<&str> = rehearsed.intended.iter().map(|setup| setup.setup_id.as_str()).collect();
    assert_eq!(ids, ["adopted-access-grid-hub", "adopted-swarm-mining-hub", "adopted-swarm-mining-workers"]);
    let scanned: Vec<String> = super::super::adopt::scan(folder.path()).into_iter().map(|entry| entry.id).collect();
    assert!(ids.iter().all(|id| scanned.iter().any(|seen| seen == id)), "{scanned:?}");

    // Swarm Mining is never adopted, and says so instead of pretending.
    let swarm = rehearsed.intended.iter().find(|setup| setup.product == Product::SwarmMining).unwrap();
    assert!(swarm.blocked.as_deref().is_some_and(|why| why.contains("managed on its own, not from here")));
    assert!(swarm.carries.is_empty());

    // The Access hub would carry each of its own records, and its data would stay where it is.
    let access = rehearsed.intended.iter().find(|setup| setup.product == Product::AccessGrid).unwrap();
    assert_eq!(access.carries, ["access-grid/hub", "access-grid/tunnel"]);
    assert!(access.data_stays_at.contains(&"grid/access-hub.json".to_owned()));

    // Every area of plan 19.3 step 3 is covered.
    for area in ["counts", "identities", "permissions", "assignments", "data-locations", "urls"] {
        assert!(rehearsed.checks.iter().any(|check| check.area == area), "no check for {area}");
    }
    // Swarm Mining's records are found but not carried, so that is named as a difference.
    assert!(!rehearsed.matches);
    assert!(rehearsed.differences.iter().any(|said| said.contains("Swarm Mining")));
    assert!(rehearsed.differences.iter().any(|said| said.contains("not adopted")));

    // The public link is acknowledged without ever being printed.
    let link = rehearsed.checks.iter().find(|check| check.subject == "Access Grid public link").unwrap();
    assert_eq!((link.before.as_str(), link.after.as_str()), ("set up", "set up, unchanged"));
    let shown = serde_json::to_string(&rehearsed).unwrap();
    assert!(!shown.contains("example.invalid") && !shown.contains("SECRET"));
}

#[test]
fn a_rehearsal_of_a_folder_with_nothing_in_it_says_so_plainly() {
    let folder = tempfile::tempdir().unwrap();
    let rehearsed = rehearse(folder.path());
    assert!(rehearsed.intended.is_empty());
    assert!(rehearsed.matches);
    assert!(rehearsed.notes.iter().any(|note| note.contains("No deployment in this folder would become a setup")));
}

#[test]
fn an_unreadable_deployment_would_not_be_adopted_and_the_rehearsal_says_it_is_incomplete() {
    let folder = tempfile::tempdir().unwrap();
    fs::create_dir_all(folder.path().join("grid/access-hub.json")).unwrap();
    let rehearsed = rehearse(folder.path());
    let access = rehearsed.intended.iter().find(|setup| setup.product == Product::AccessGrid).unwrap();
    assert!(access.blocked.as_deref().is_some_and(|why| why.contains("can't look at")));
    assert!(rehearsed.notes.iter().any(|note| note.contains("not complete")));
}

/// Plan 19.3 step 4 and invariant 15: a read-only comparison cannot mutate either source.
#[test]
fn reading_a_folder_changes_nothing_in_it() {
    let folder = tempfile::tempdir().unwrap();
    full_folder(folder.path());
    fs::create_dir_all(folder.path().join("grid/unreadable.json")).unwrap();
    let before = fingerprint(folder.path());

    let taken = inventory(folder.path());
    let into = tempfile::tempdir().unwrap();
    let destination = into.path().join("backup");
    backup(folder.path(), &destination, &taken).unwrap();
    verify(&destination).unwrap();
    rehearse(folder.path());

    let after = fingerprint(folder.path());
    assert_eq!(before.len(), after.len(), "a file or folder appeared or went away");
    for (name, was) in &before {
        let now = after.get(name).unwrap_or_else(|| panic!("{name} went away"));
        assert_eq!(&was.0, &now.0, "{name} changed");
        assert_eq!(&was.1, &now.1, "{name} changed size");
        assert_eq!(&was.2, &now.2, "{name} was written to");
    }
}

#[test]
fn the_live_folder_is_refused_unless_it_is_explicitly_allowed() {
    let live = tempfile::tempdir().unwrap();
    fs::create_dir_all(live.path().join("grid")).unwrap();
    let elsewhere = tempfile::tempdir().unwrap();

    // The folder itself, a folder inside it, and a folder that holds it are all refused.
    for candidate in [live.path().to_path_buf(), live.path().join("grid"), live.path().parent().unwrap().to_path_buf()] {
        let refusal = refuse_live(&candidate, live.path(), false).unwrap_err();
        assert_eq!(refusal.code, "live_folder");
        assert!(refusal.message.contains("Make a copy of it"));
    }
    // Somewhere else is fine, and an explicit allow lets the live folder through.
    assert!(refuse_live(elsewhere.path(), live.path(), false).is_ok());
    assert!(refuse_live(live.path(), live.path(), true).is_ok());
}

#[test]
fn a_folder_that_is_not_there_or_not_a_full_path_is_refused_with_a_next_step() {
    assert_eq!(readable_folder(Path::new("relative/folder")).unwrap_err().code, "path_not_full");
    let holder = tempfile::tempdir().unwrap();
    let gone = holder.path().join("not-there");
    assert_eq!(readable_folder(&gone).unwrap_err().code, "no_such_folder");
    let there = tempfile::tempdir().unwrap();
    assert!(readable_folder(there.path()).is_ok());
}

// ---------------------------------------------------------------------------
// A synthetic 1.1.x installation's v1 template instances (plan 13.2 and 19.1)
// ---------------------------------------------------------------------------
//
// `migration/fixtures/installation-1.1/home/.yougori/` holds what a 1.1.x computer's CLI folder
// keeps for two v1 template instances, with fake values only: each as the CLI keeps it
// (`hub/records/NAME.json`) and as the desktop reads it (`hub/instances/NAME/instance.json`). Both
// were written by the CLI's own `State` and `app_view`.
//
// The fixture is an old installation, so it is never rewritten when a type changes: the test
// below instead proves that today's types still read every file and keep every value in it. Write
// it again only on purpose, with `UPDATE_MIGRATION_FIXTURES=1`.

fn installation_folder() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/setups/migration/fixtures/installation-1.1")
}

/// Every file of the synthetic installation, by its path under the fixture folder.
fn installation() -> BTreeMap<String, Vec<u8>> {
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for (name, title, version, phase, at) in [("my-api", "My API", "1.6.0", "ready", 1760000500_u64), ("shop", "Shop", "1.2.0", "stopped", 1760000600_u64)] {
        let state = yougori_cli::hub::instances::State {
            instance: name.into(),
            origin: "hub".into(),
            item: Some(format!("example/{name}")),
            template: name.into(),
            title: title.into(),
            version: version.into(),
            digest: "f1".repeat(32),
            project: "yougori.yaml".into(),
            answers: [("site_title".to_owned(), title.to_owned())].into(),
            secrets: vec!["admin_password".into()],
            environments: [("web".to_owned(), format!("env-fixture-{name}-web"))].into(),
            phase: phase.into(),
            created_at: at,
            updated_at: at + 60,
            ..Default::default()
        };
        files.insert(format!("home/.yougori/hub/records/{name}.json"), serde_json::to_vec_pretty(&state).unwrap());
        files.insert(format!("home/.yougori/hub/instances/{name}/instance.json"), serde_json::to_vec_pretty(&yougori_cli::hub::instances::app_view(&state)).unwrap());
    }
    files
}

/// Every file under the fixture's `home` folder, by its `/`-separated path.
fn files_under(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(root: &Path, at: &Path, into: &mut BTreeMap<String, Vec<u8>>) {
        for entry in fs::read_dir(at).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(root, &path, into);
            } else {
                into.insert(path.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/"), fs::read(&path).unwrap());
            }
        }
    }
    let mut into = BTreeMap::new();
    walk(root, &root.join("home"), &mut into);
    into
}

/// Every value `was` holds is in `now` too, unchanged: nothing was dropped or renamed.
fn kept(was: &Value, now: &Value, at: &str) -> Result<(), String> {
    match (was, now) {
        (Value::Object(was), Value::Object(now)) => was.iter().try_for_each(|(key, value)| match now.get(key) {
            Some(again) => kept(value, again, &format!("{at}.{key}")),
            None if value.is_null() => Ok(()),
            None => Err(format!("{at}.{key} is no longer read")),
        }),
        (Value::Array(was), Value::Array(now)) if was.len() == now.len() => was.iter().zip(now).enumerate().try_for_each(|(index, (value, again))| kept(value, again, &format!("{at}[{index}]"))),
        (was, now) if was == now => Ok(()),
        _ => Err(format!("{at} reads back as something else")),
    }
}

/// A fixture file read with the CLI's own type, then written out again by it. The desktop's view
/// is made from the CLI's record of the same instance.
fn read_back(path: &str, bytes: &[u8], all: &BTreeMap<String, Vec<u8>>) -> Value {
    if path.ends_with("/instance.json") {
        let instance = path.rsplit('/').nth(1).unwrap();
        let state: yougori_cli::hub::instances::State = serde_json::from_slice(&all[&format!("home/.yougori/hub/records/{instance}.json")]).unwrap();
        return yougori_cli::hub::instances::app_view(&state);
    }
    assert!(path.starts_with("home/.yougori/hub/records/"), "no reader for {path}");
    serde_json::to_value(serde_json::from_slice::<yougori_cli::hub::instances::State>(bytes).unwrap()).unwrap()
}

/// PROVES the fixture is a real 1.1.x installation for today's code: every file is there, and each
/// record reads with the CLI's own type and writes back every value it holds.
#[test]
fn the_synthetic_installation_reads_with_the_clis_own_types() {
    let folder = installation_folder();
    let built = installation();
    if std::env::var("UPDATE_MIGRATION_FIXTURES").as_deref() == Ok("1") {
        let _ = fs::remove_dir_all(folder.join("home"));
        for (path, bytes) in &built {
            write(&folder, path, bytes);
        }
    }
    let stored = files_under(&folder);
    assert_eq!(stored.keys().collect::<Vec<_>>(), built.keys().collect::<Vec<_>>(), "the fixture's files are not the installation's; write it again with UPDATE_MIGRATION_FIXTURES=1 only if that is meant");
    for (path, bytes) in &stored {
        let was: Value = serde_json::from_slice(bytes).unwrap_or_else(|error| panic!("{path} is not JSON: {error}"));
        if let Err(problem) = kept(&was, &read_back(path, bytes, &stored), path) {
            panic!("today's code would lose part of a 1.1.x record: {problem}");
        }
    }
    // Fake values only: nothing that looks like a real person, key, domain or path of this computer.
    let text = stored.values().map(|bytes| String::from_utf8_lossy(bytes).into_owned()).collect::<String>();
    for word in ["BEGIN PRIVATE KEY", "C:\\\\Users", "/home/", "/Users/", "trycloudflare.com", "@"] {
        assert!(!text.contains(word), "the fixture holds {word}");
    }
}

/// The CLI folder's v1 instances are inventoried and backed up with both of their records.
#[test]
fn the_installations_template_instances_are_inventoried_and_backed_up_whole() {
    let home = installation_folder().join("home/.yougori");
    let taken = inventory(&home);
    assert_eq!((taken.totals.instances, taken.totals.products_present, taken.empty), (2, 0, false));
    assert!(taken.instances.iter().all(|instance| instance.found.exists() && instance.record.exists()));
    let into = tempfile::tempdir().unwrap();
    let manifest = backup(&home, &into.path().join("home"), &taken).unwrap();
    let ids: Vec<&str> = manifest.files.iter().map(|file| file.id.as_str()).collect();
    assert_eq!(ids, ["instance:my-api", "instance-record:my-api", "instance:shop", "instance-record:shop"]);
    assert!(manifest.left_behind.is_empty());
    let checked = verify(&into.path().join("home")).unwrap();
    assert!(checked.good && checked.matched == 4);
    let shown = serde_json::to_string(&taken).unwrap();
    assert!(!shown.contains("admin_password") && !shown.contains("env-fixture"), "the inventory reads no record's contents");
}

/// Plan 19.3 step 4 on the fixture itself: inventory, backup, verify and rehearsal leave every
/// file of the installation exactly as it was.
#[test]
fn nothing_in_the_installation_is_written() {
    let folder = installation_folder();
    let before = fingerprint(&folder);
    assert!(before.len() > 5, "the fixture is missing");
    let home = folder.join("home/.yougori");
    let into = tempfile::tempdir().unwrap();
    let taken = inventory(&home);
    backup(&home, &into.path().join("home"), &taken).unwrap();
    verify(&into.path().join("home")).unwrap();
    rehearse(&home);
    assert_eq!(before, fingerprint(&folder), "reading the installation changed it");
}
