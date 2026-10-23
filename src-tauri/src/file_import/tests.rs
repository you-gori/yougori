use super::*;
use std::io::{Read, Seek, SeekFrom};

#[test]
fn drops_use_the_single_active_selected_folder() {
    let connection = |path: &str| -> crate::models::Connection {
        serde_json::from_value(serde_json::json!({
            "id":"conn-a","sourceId":"env-a","targetId":"env-b",
            "direction":"bidirectional","permissions":["data"],"ports":[],
            "selectedFolders":[{"environmentId":"env-a","path":path}],
            "active":true,"enforcementStatus":"enforced","createdAt":"2026-09-25T00:00:00Z"
        })).unwrap()
    };
    assert_eq!(selected_drop_folder(&[connection("/workspace")], "env-a"), Some("/workspace"));
    assert_eq!(selected_drop_folder(&[connection("/workspace")], "env-b"), None);
    assert_eq!(selected_drop_folder(&[connection("/")], "env-a"), None);
    let mut disabled = connection("/workspace");
    disabled.active = false;
    assert_eq!(selected_drop_folder(&[disabled], "env-a"), None);
    assert_eq!(selected_drop_folder(&[connection("/workspace"), connection("/data")], "env-a"), None);
}

fn fixture() -> (tempfile::TempDir, PathBuf, Vec<u8>) {
    let root = tempfile::tempdir().unwrap();
    let folder = root.path().join("Project ü ' $()");
    fs::create_dir_all(folder.join("nested/empty")).unwrap();
    let bytes: Vec<_> = (0..300_000).map(|i| (i % 251) as u8).collect();
    fs::write(folder.join("nested/data.bin"), &bytes).unwrap();
    fs::write(folder.join(".hidden"), b"keep me").unwrap();
    fs::write(folder.join("zero"), []).unwrap();
    (root, folder, bytes)
}

#[test]
fn file_import_copies_nested_binary_and_hidden_files_without_touching_sources() {
    let (_root, folder, bytes) = fixture();
    let before = fs::metadata(folder.join("nested/data.bin"))
        .unwrap()
        .modified()
        .unwrap();
    let plan = plan_copy(&[folder.to_string_lossy().into_owned()]).unwrap();
    assert_eq!(plan.files, 3);
    let stage = tempfile::tempdir().unwrap();
    let archive = stage.path().join("copy.tar");
    write_archive(&plan, &archive, |_| {}).unwrap();
    let copy = stage.path().join("unpacked");
    fs::create_dir(&copy).unwrap();
    tar::Archive::new(fs::File::open(&archive).unwrap())
        .unpack(&copy)
        .unwrap();
    let copied = copy.join(folder.file_name().unwrap());
    assert_eq!(fs::read(copied.join("nested/data.bin")).unwrap(), bytes);
    assert!(copied.join("nested/empty").is_dir());
    assert!(copied.join(".hidden").is_file());
    fs::write(copied.join("nested/data.bin"), b"guest edits").unwrap();
    fs::remove_file(copied.join(".hidden")).unwrap();
    assert_eq!(fs::read(folder.join("nested/data.bin")).unwrap(), bytes);
    assert_eq!(
        fs::metadata(folder.join("nested/data.bin"))
            .unwrap()
            .modified()
            .unwrap(),
        before
    );
    assert_eq!(fs::read(folder.join(".hidden")).unwrap(), b"keep me");
    assert!(write_archive(&plan, &archive, |_| {}).is_err());
}

#[test]
fn archive_progress_counts_source_bytes_and_reports_completion_after_flush() {
    let (_root, folder, _) = fixture();
    let plan = plan_copy(&[folder.to_string_lossy().into_owned()]).unwrap();
    let stage = tempfile::tempdir().unwrap();
    let mut progress = Vec::new();
    let archive = stage.path().join("copy.tar");
    let measurements = std::cell::RefCell::new(&mut progress);
    write_archive(&plan, &archive, |p| measurements.borrow_mut().push(p)).unwrap();
    assert!(progress.len() >= 2);
    assert_eq!(progress.first().unwrap().completed_bytes, 0);
    assert_eq!(progress.last().unwrap().completed_bytes, plan.bytes);
    assert!(progress.iter().all(|p| p.phase == "archiving" && p.total_bytes == plan.bytes && p.completed_bytes <= plan.bytes));
    assert!(progress.windows(2).all(|p| p[0].completed_bytes <= p[1].completed_bytes));
    assert!(fs::metadata(archive).unwrap().len() > plan.bytes); // tar headers aren't source bytes
}

#[test]
fn file_import_drive_is_independent_and_contains_real_nested_files() {
    let (_root, folder, bytes) = fixture();
    let plan = plan_copy(&[folder.to_string_lossy().into_owned()]).unwrap();
    let stage = tempfile::tempdir().unwrap();
    let path = stage.path().join("copy.img");
    drive::write_drive(&plan, &path, |_| {}).unwrap();
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let disk = fatfs::FileSystem::new(file, fatfs::FsOptions::new()).unwrap();
    let root = disk.root_dir();
    let mut copied = root
        .open_file(&format!(
            "{}/nested/data.bin",
            folder.file_name().unwrap().to_string_lossy()
        ))
        .unwrap();
    let mut contents = Vec::new();
    copied.read_to_end(&mut contents).unwrap();
    assert_eq!(contents, bytes);
    copied.seek(SeekFrom::Start(0)).unwrap();
    std::io::Write::write_all(&mut copied, b"guest edit").unwrap();
    assert_eq!(fs::read(folder.join("nested/data.bin")).unwrap(), bytes);
}

#[test]
fn file_import_rejects_duplicate_roots_and_sources_changed_during_copy() {
    let (_root, folder, _) = fixture();
    let selection = folder.to_string_lossy().into_owned();
    assert!(plan_copy(&[selection.clone(), selection.clone()]).is_err());
    assert!(plan_copy(&["relative/path".into()]).is_err());
    let plan = plan_copy(&[selection]).unwrap();
    fs::write(folder.join("nested/data.bin"), b"saved new data").unwrap();
    let stage = tempfile::tempdir().unwrap();
    assert!(write_archive(&plan, &stage.path().join("copy.tar"), |_| {})
        .unwrap_err()
        .contains("changed"));
    assert_eq!(
        fs::read(folder.join("nested/data.bin")).unwrap(),
        b"saved new data"
    );
}

#[test]
fn file_import_skips_linked_folders_without_reading_their_contents() {
    let (_root, folder, _) = fixture();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("private.txt"), b"outside selection").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(outside.path(), folder.join("linked")).unwrap();
    #[cfg(windows)]
    {
        // Junctions work without developer mode or administrator privileges.
        let status = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(folder.join("linked"))
            .arg(outside.path())
            .output()
            .unwrap();
        assert!(
            status.status.success(),
            "{}",
            String::from_utf8_lossy(&status.stderr)
        );
    }
    let plan = plan_copy(&[folder.to_string_lossy().into_owned()]).unwrap();
    assert_eq!(plan.skipped_links, 1);
    assert!(!plan
        .entries()
        .unwrap()
        .any(|e| e.unwrap().source.ends_with("private.txt")));
    assert_eq!(
        fs::read(outside.path().join("private.txt")).unwrap(),
        b"outside selection"
    );
}

/// A file symbolic link, or `None` where making one needs developer mode or administrator
/// rights (Windows ERROR_PRIVILEGE_NOT_HELD), so the test runs on every machine.
fn file_symlink(target: &Path, link: &Path) -> Option<()> {
    #[cfg(unix)]
    let made = std::os::unix::fs::symlink(target, link);
    #[cfg(windows)]
    let made = std::os::windows::fs::symlink_file(target, link);
    match made {
        Ok(()) => Some(()),
        Err(error) if cfg!(windows) && error.raw_os_error() == Some(1314) => None,
        Err(error) => panic!("{error}"),
    }
}

#[test]
fn junctions_and_symbolic_links_are_still_refused_while_ordinary_files_copy() {
    let (_root, folder, _) = fixture();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("private.txt"), b"outside selection").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(outside.path(), folder.join("linked")).unwrap();
    #[cfg(windows)]
    assert!(std::process::Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(folder.join("linked"))
        .arg(outside.path())
        .output()
        .unwrap()
        .status
        .success());
    assert!(linked(&fs::symlink_metadata(folder.join("linked")).unwrap()));
    let symlinked = file_symlink(&outside.path().join("private.txt"), &folder.join("private-link.txt"));
    if symlinked.is_some() {
        assert!(linked(&fs::symlink_metadata(folder.join("private-link.txt")).unwrap()));
    }
    assert!(!linked(&fs::symlink_metadata(folder.join("nested/data.bin")).unwrap()));
    assert!(!linked(&fs::symlink_metadata(folder.join("nested")).unwrap()));
    let plan = plan_copy(&[folder.to_string_lossy().into_owned()]).unwrap();
    assert_eq!(plan.skipped_links, 1 + usize::from(symlinked.is_some()));
    assert_eq!(plan.files, 3);
    assert!(!plan.entries().unwrap().any(|e| e.unwrap().source.to_string_lossy().contains("private")));
}

#[test]
fn file_import_rejects_a_file_replaced_by_a_symbolic_link_after_selection() {
    let (_root, folder, _) = fixture();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("data.bin"), b"outside selection").unwrap();
    let plan = plan_copy(&[folder.to_string_lossy().into_owned()]).unwrap();
    let entry = plan.entries().unwrap().map(Result::unwrap).find(|e| e.source.ends_with("data.bin")).unwrap();
    fs::rename(folder.join("nested/data.bin"), folder.join("nested/original.bin")).unwrap();
    if file_symlink(&outside.path().join("data.bin"), &folder.join("nested/data.bin")).is_none() {
        return;
    }
    assert!(open_source(&entry).is_err());
    assert_eq!(fs::read(outside.path().join("data.bin")).unwrap(), b"outside selection");
}

#[test]
fn file_import_rejects_a_parent_replaced_by_a_link_after_selection() {
    let (_root, folder, _) = fixture();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("data.bin"), b"outside selection").unwrap();
    let plan = plan_copy(&[folder.to_string_lossy().into_owned()]).unwrap();
    let entry = plan
        .entries()
        .unwrap()
        .map(Result::unwrap)
        .find(|e| e.source.ends_with("data.bin"))
        .unwrap();
    fs::rename(folder.join("nested"), folder.join("original-nested")).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(outside.path(), folder.join("nested")).unwrap();
    #[cfg(windows)]
    assert!(std::process::Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(folder.join("nested"))
        .arg(outside.path())
        .output()
        .unwrap()
        .status
        .success());
    assert!(open_source(&entry).is_err());
    assert_eq!(
        fs::read(outside.path().join("data.bin")).unwrap(),
        b"outside selection"
    );
}

#[test]
fn copied_unix_permissions_never_widen_group_or_other_access() {
    for (source, directory, want) in [
        (0o600, false, 0o600),
        (0o400, false, 0o600),
        (0o700, false, 0o700),
        (0o644, false, 0o644),
        (0o6777, false, 0o755),
        (0o700, true, 0o700),
        (0o500, true, 0o700),
        (0o2755, true, 0o755),
    ] {
        let actual = unix_copy_mode(source, directory);
        assert_eq!(actual, want);
        assert_eq!(actual & 0o077 & !source, 0, "source {source:o}");
    }
}

#[cfg(unix)]
#[test]
fn file_import_stages_private_unix_paths_without_exposing_them() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("private");
    fs::create_dir(&source).unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o700)).unwrap();
    let key = source.join("private-key");
    fs::write(&key, b"fixture-private-content").unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    let plan = plan_copy(&[source.to_string_lossy().into_owned()]).unwrap();
    let archive = root.path().join("copy.tar");
    write_archive(&plan, &archive, |_| {}).unwrap();
    let mut archive = tar::Archive::new(fs::File::open(archive).unwrap());
    for entry in archive.entries().unwrap() {
        let entry = entry.unwrap();
        assert_eq!(
            entry.header().mode().unwrap(),
            if entry.header().entry_type().is_dir() {
                0o700
            } else {
                0o600
            }
        );
    }
    assert_eq!(
        fs::metadata(&key).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(fs::read(key).unwrap(), b"fixture-private-content");
}

#[test]
fn a_folders_yougoriignore_leaves_matching_files_behind() {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("project");
    fs::create_dir_all(project.join("node_modules/pkg")).unwrap();
    fs::create_dir_all(project.join("src")).unwrap();
    fs::write(project.join(".yougoriignore"), "node_modules/\n*.log\n.env\n!important.log\n").unwrap();
    fs::write(project.join("node_modules/pkg/index.js"), "x").unwrap();
    fs::write(project.join("src/main.js"), "main").unwrap();
    fs::write(project.join("src/debug.log"), "noise").unwrap();
    fs::write(project.join("important.log"), "keep").unwrap();
    fs::write(project.join(".env"), "SECRET=1").unwrap();
    let manifest = tempfile::NamedTempFile::new().unwrap();
    let plan = scan_copy(&[project.to_string_lossy().into_owned()], manifest, |_| {}).unwrap();
    // Copied: .yougoriignore, src/main.js, important.log. Skipped: node_modules, debug.log, .env.
    assert_eq!((plan.files, plan.skipped_ignored), (3, 3));
    let listed = fs::read_to_string(plan.manifest.path()).unwrap();
    assert!(listed.contains("main.js") && listed.contains("important.log"));
    assert!(!listed.contains("node_modules") && !listed.contains("debug.log") && !listed.contains("SECRET"));
    assert!(!listed.contains("\".env\""));
}

#[test]
fn cancelled_archive_preserves_sources_and_does_not_start_another_environment_transfer() {
    let root=tempfile::tempdir().unwrap();let source=root.path().join("large.bin");fs::write(&source,vec![7;512*1024]).unwrap();
    let plan=plan_copy(&[source.to_string_lossy().into_owned()]).unwrap();
    let first=transfers::begin("env-cancelled-archive-test").unwrap();let second=transfers::begin("env-independent-archive-test").unwrap();
    let token=first.transfer.clone();let cancelled=token.clone();
    let result=write_archive_cancellable(&plan,&root.path().join("archive.tar"),move|_|{cancelled.cancellation.cancel();},Some(token));
    assert!(result.unwrap_err().contains("YOUGORI_OPERATION_CANCELLED"));assert_eq!(fs::read(&source).unwrap(),vec![7;512*1024]);assert!(second.transfer.check().is_ok());
}
