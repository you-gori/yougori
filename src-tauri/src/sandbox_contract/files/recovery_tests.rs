//! Recovering the teardown of a replaced sandbox root by its file identity, on real
//! temporary trees (VM part §6.1, §6.4; VM-W24, VM-W29 acceptance "user data preserved;
//! teardown cannot escape managed roots"; VM-P49).
//!
//! The sandbox root is renamed away within the temporary tree and another directory, a
//! junction or a file is put at its name, so teardown refuses; recovery then opens the root
//! by its journaled file ID. A crash is simulated with the deletion hook: the run stops
//! where the hook says, and recovery reads back strictly the journal last persisted, with the
//! registrations restored into a new registry. Opening by file ID is Windows-only; on Unix
//! recovery is refused, which the last test checks there.

#[cfg(windows)]
use std::collections::BTreeMap;
#[cfg(windows)]
use std::fs;
#[cfg(windows)]
use std::path::Path;

#[cfg(windows)]
use serde_json::json;

#[cfg(windows)]
use super::file_id;
use super::fresh_root_tests::{ephemeral_layout, launch, Launched, MemoryStore, NoVmProcesses};
#[cfg(windows)]
use super::fresh_root_tests::{id, outcomes};
#[cfg(windows)]
use super::fsutil;
#[cfg(windows)]
use super::recovery::recover_teardown_with;
use super::root_tests::snapshot;
#[cfg(windows)]
use super::root_tests::{dir_link, host, names_in, present, write};
use super::*;

#[cfg(windows)]
fn name(text: &str) -> GuestName {
    GuestName::parse(text).unwrap()
}

fn recover(
    parent: &GrantedRoot,
    registry: &ManagedObjects,
    journal: &mut RootJournal,
    store: &mut MemoryStore,
) -> Result<RecoveryReport, RecoveryError> {
    recover_teardown(parent, registry, journal, store, &NoVmProcesses)
}

/// The refusal a recovery run met.
fn refusal(result: Result<RecoveryReport, RecoveryError>) -> RecoveryRefusal {
    match result {
        Err(RecoveryError::Refused(refusal)) => refusal,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// Preserved user data, a kept volume, a rebuilt environment, an overlay and scratch, in
/// the strict profile.
#[cfg(windows)]
fn mixed_layout() -> RootLayout {
    let volume = |text: &str, renewal| LayoutEntry {
        name: name(text),
        entry: RootEntry::Volume { renewal },
    };
    RootLayout {
        base_image: id("base-image"),
        profile: PersistenceProfile::Strict,
        entries: vec![
            volume("workspace", VolumeRenewal::SourceWorkspace),
            volume("output", VolumeRenewal::UnreviewedOutput),
            volume(
                "venv",
                VolumeRenewal::ExecutableEnvironmentRebuild {
                    pinned_manifest: id("lock"),
                },
            ),
            LayoutEntry {
                name: name("overlay"),
                entry: RootEntry::Overlay,
            },
            LayoutEntry {
                name: name("scratch"),
                entry: RootEntry::Scratch,
            },
        ],
    }
}

/// What is put at the sandbox root's name once the root is renamed away.
#[cfg(windows)]
#[derive(Clone, Copy, Debug)]
enum Replacement {
    Directory,
    Junction,
    File,
}

/// Renames the sandbox root to `moved` and puts `replacement` at its name.
#[cfg(windows)]
fn replace(launched: &Launched, moved: &Path, replacement: Replacement) {
    fs::rename(&launched.root, moved).unwrap();
    match replacement {
        Replacement::Directory => write(&launched.root, "scratch/a.txt", b"another"),
        Replacement::Junction => dir_link(&launched.root, &launched.tree.outside),
        Replacement::File => fs::write(&launched.root, b"a file at the root's name").unwrap(),
    }
}

/// `snapshot` without the entry `prefix` and what lies beneath it.
#[cfg(windows)]
fn without(snapshot: &BTreeMap<String, String>, prefix: &str) -> BTreeMap<String, String> {
    let beneath = format!("{prefix}/");
    snapshot
        .iter()
        .filter(|(key, _)| key.as_str() != prefix && !key.starts_with(&beneath))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

#[cfg(windows)]
fn spared(deleted: u64, spared: u64) -> TeardownOutcome {
    TeardownOutcome::Incomplete {
        deleted,
        left: LeftBehind {
            spared,
            ..LeftBehind::default()
        },
    }
}

#[test]
#[cfg(windows)]
fn the_launch_journals_the_roots_raw_file_identity_beside_its_identity() {
    let Launched {
        tree: _tree,
        parent,
        store,
        journal,
        ..
    } = launch(&ephemeral_layout());
    let raw = journal.root_raw_identity().unwrap();
    assert_eq!(raw.identity(), journal.root().identity().unwrap());
    // Read from a handle on the root: the digest's volume, index and creation time are the
    // serial number's low half, the file ID's low half and the creation time.
    let info = fsutil::entry_info(parent.dir(), journal.root_name().as_str()).unwrap();
    assert_eq!(raw.volume_serial & u64::from(u32::MAX), info.volume);
    assert_eq!(raw.file_id.low_u64(), info.index);
    assert_eq!(raw.created, info.created);
    assert_eq!(
        file_id::volume_serial(parent.dir()).unwrap(),
        raw.volume_serial
    );
    assert_eq!(store.read_back().root_raw_identity(), Some(raw));
}

#[test]
#[cfg(windows)]
fn a_root_replaced_by_a_directory_a_junction_or_a_file_is_torn_down_through_its_file_id() {
    for (replacement, expected_at_name) in [
        (Replacement::Directory, LeftAtName::Directory),
        (Replacement::Junction, LeftAtName::Other),
        (Replacement::File, LeftAtName::Other),
    ] {
        let launched = launch(&mixed_layout());
        let root = launched.root.clone();
        write(&root, "workspace/src/main.rs", b"fn main() {}");
        write(&root, "output/result.txt", b"result");
        write(&root, "venv/lib/x.py", b"x");
        write(&root, "overlay/disk", b"disk");
        write(&root, "scratch/a/b.txt", b"b");
        dir_link(&host(&root, "scratch/escape"), &launched.tree.outside);
        write(&root, "vm.sock", b"socket");
        let moved = launched.tree.root.join("moved");
        replace(&launched, &moved, replacement);
        let Launched {
            tree,
            parent,
            registry,
            mut store,
            mut journal,
            ..
        } = launched;
        let committed = store.read_back();
        let before = snapshot(tree.dir.path());
        // Teardown refuses the name, with nothing deleted and the journal unchanged.
        assert!(
            matches!(
                teardown(&parent, &registry, &mut journal, &mut store, &NoVmProcesses),
                Err(TeardownError::Refused {
                    refusal: CleanupRefusal::RootIdentityChanged { .. },
                    ..
                })
            ),
            "{replacement:?}"
        );
        assert_eq!(snapshot(tree.dir.path()), before);
        assert_eq!(store.read_back(), committed);

        let report = recover(&parent, &registry, &mut journal, &mut store).unwrap();
        assert_eq!(report.left_at_name, expected_at_name, "{replacement:?}");
        assert!(report.teardown.torn_down, "{replacement:?}: {report:?}");
        assert!(report.teardown.failures.is_empty());
        let root_name = journal.root_name().as_str().to_owned();
        assert_eq!(
            outcomes(&report.teardown.objects),
            BTreeMap::from([
                ("workspace".to_owned(), TeardownOutcome::Preserved),
                (
                    "output".to_owned(),
                    TeardownOutcome::Kept {
                        class: VolumeClass::UnreviewedOutput
                    }
                ),
                ("venv".to_owned(), TeardownOutcome::Deleted { entries: 3 }),
                (
                    "overlay".to_owned(),
                    TeardownOutcome::Deleted { entries: 2 }
                ),
                (
                    "scratch".to_owned(),
                    TeardownOutcome::Deleted { entries: 4 }
                ),
                (root_name.clone(), spared(1, 2)),
            ]),
            "{replacement:?}"
        );
        // The original keeps its kept and preserved volumes, whole.
        assert_eq!(names_in(&moved), ["output", "workspace"]);
        assert_eq!(
            fs::read(host(&moved, "workspace/src/main.rs")).unwrap(),
            b"fn main() {}"
        );
        assert_eq!(
            fs::read(host(&moved, "output/result.txt")).unwrap(),
            b"result"
        );
        // Everything else is as it was: the replacement, what a junction points at, the
        // managed parent.
        assert_eq!(
            without(&snapshot(tree.dir.path()), "root/moved"),
            without(&before, "root/moved"),
            "{replacement:?}"
        );

        // The journal holds what the run did; a second run after a restart deletes nothing.
        let mut read = store.read_back();
        assert!(matches!(read.phase(), RootPhase::TornDown { .. }));
        assert_eq!(read, journal);
        let mut restored = ManagedObjects::new();
        read.restore_registrations(&mut restored).unwrap();
        let reopened = GrantedRoot::open(&tree.root).unwrap();
        let again = recover(&reopened, &restored, &mut read, &mut store).unwrap();
        assert!(again.teardown.torn_down);
        let found = outcomes(&again.teardown.objects);
        for removed in ["venv", "overlay", "scratch"] {
            assert_eq!(found[removed], TeardownOutcome::AlreadyGone, "{removed}");
        }
        assert_eq!(found["workspace"], TeardownOutcome::Preserved);
        assert_eq!(found[&root_name], spared(0, 2));
        assert_eq!(names_in(&moved), ["output", "workspace"]);
        assert_eq!(
            without(&snapshot(tree.dir.path()), "root/moved"),
            without(&before, "root/moved")
        );
    }
}

#[test]
#[cfg(windows)]
fn a_root_moved_out_of_the_parent_is_deleted_and_a_second_run_reports_it_gone() {
    let Launched {
        tree,
        parent,
        registry,
        mut store,
        mut journal,
        root,
    } = launch(&ephemeral_layout());
    write(&root, "scratch/a/b.txt", b"b");
    write(&root, "overlay/disk", b"disk");
    write(&root, "vm.sock", b"socket");
    // Anywhere on the volume, outside the managed parent too.
    let elsewhere = tree.dir.path().join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    let moved = elsewhere.join("moved");
    fs::rename(&root, &moved).unwrap();
    write(&root, "scratch/a.txt", b"another");
    let replacement = snapshot(&root);

    let report = recover(&parent, &registry, &mut journal, &mut store).unwrap();
    assert_eq!(report.left_at_name, LeftAtName::Directory);
    assert!(report.teardown.torn_down);
    let root_name = journal.root_name().as_str().to_owned();
    assert_eq!(
        outcomes(&report.teardown.objects),
        BTreeMap::from([
            ("venv".to_owned(), TeardownOutcome::Deleted { entries: 1 }),
            (
                "overlay".to_owned(),
                TeardownOutcome::Deleted { entries: 2 }
            ),
            (
                "scratch".to_owned(),
                TeardownOutcome::Deleted { entries: 3 }
            ),
            (root_name, TeardownOutcome::Deleted { entries: 2 }),
        ])
    );
    assert!(!present(&moved));
    assert!(names_in(&elsewhere).is_empty());
    assert_eq!(snapshot(&root), replacement);

    // Nothing has the file ID any more, and the journal shows the root deleted.
    let second = recover(&parent, &registry, &mut journal, &mut store).unwrap();
    assert!(second.teardown.torn_down);
    assert_eq!(second.teardown.objects.len(), 4);
    assert!(second
        .teardown
        .objects
        .iter()
        .all(|object| object.outcome == TeardownOutcome::AlreadyGone));
    let read = store.read_back();
    assert!(matches!(read.phase(), RootPhase::TornDown { .. }));
    assert_eq!(
        outcomes(read.phase().finished()),
        outcomes(&report.teardown.objects)
    );
    assert_eq!(snapshot(&root), replacement);
    // With nothing at the name either, it is still already gone.
    fs::remove_dir_all(&root).unwrap();
    let third = recover(&parent, &registry, &mut journal, &mut store).unwrap();
    assert_eq!(third.left_at_name, LeftAtName::Nothing);
    assert_eq!(third.teardown, second.teardown);
}

#[test]
#[cfg(windows)]
fn a_deleted_original_another_object_at_its_file_id_or_another_volume_is_refused() {
    // The original deleted after it was renamed away.
    let Launched {
        tree,
        parent,
        registry,
        mut store,
        mut journal,
        root,
    } = launch(&ephemeral_layout());
    write(&root, "scratch/a.txt", b"a");
    let moved = tree.root.join("moved");
    fs::rename(&root, &moved).unwrap();
    fs::create_dir(&root).unwrap();
    fs::remove_dir_all(&moved).unwrap();
    let committed = store.read_back();
    let before = snapshot(tree.dir.path());
    assert_eq!(
        refusal(recover(&parent, &registry, &mut journal, &mut store)),
        RecoveryRefusal::OriginalGone
    );
    assert_eq!(snapshot(tree.dir.path()), before);
    assert_eq!(journal.phase(), &RootPhase::Committed);
    assert_eq!(store.read_back(), committed);

    // The journal's file ID naming another directory, here the replacement: its identity is
    // not the root's, and nothing is deleted.
    let Launched {
        tree,
        parent,
        registry,
        mut store,
        mut journal,
        root,
    } = launch(&ephemeral_layout());
    let moved = tree.root.join("moved");
    fs::rename(&root, &moved).unwrap();
    write(&root, "scratch/a.txt", b"another");
    let replacement = GrantedRoot::open(&root).unwrap();
    let other = file_id::recorded_identity(replacement.dir(), replacement.identity()).unwrap();
    drop(replacement);
    let recorded = journal.root_raw_identity();
    journal.set_root_raw_identity(Some(other));
    let committed = store.read_back();
    let before = snapshot(tree.dir.path());
    assert_eq!(
        refusal(recover(&parent, &registry, &mut journal, &mut store)),
        RecoveryRefusal::IdentityChanged
    );
    assert_eq!(snapshot(tree.dir.path()), before);
    assert_eq!(journal.phase(), &RootPhase::Committed);
    assert_eq!(store.read_back(), committed);

    // A volume serial number the managed parent's volume does not have.
    let mut elsewhere = recorded.unwrap();
    elsewhere.volume_serial ^= 1 << 40;
    journal.set_root_raw_identity(Some(elsewhere));
    assert_eq!(
        refusal(recover(&parent, &registry, &mut journal, &mut store)),
        RecoveryRefusal::OtherVolume
    );
    assert_eq!(snapshot(tree.dir.path()), before);
    assert_eq!(store.read_back(), committed);

    // The root at its name is teardown's.
    let Launched {
        tree,
        parent,
        registry,
        mut store,
        mut journal,
        ..
    } = launch(&ephemeral_layout());
    let before = snapshot(tree.dir.path());
    assert_eq!(
        refusal(recover(&parent, &registry, &mut journal, &mut store)),
        RecoveryRefusal::NotReplaced
    );
    assert_eq!(snapshot(tree.dir.path()), before);
    assert_eq!(journal.phase(), &RootPhase::Committed);

    // Another managed parent opened at the parent's path, on the same volume: the original
    // opens by its file ID, but V05 refuses the parent before anything is deleted.
    let Launched {
        tree,
        registry,
        mut store,
        mut journal,
        ..
    } = launch(&ephemeral_layout());
    let moved = tree.dir.path().join("parent-moved");
    fs::rename(&tree.root, &moved).unwrap();
    fs::create_dir_all(tree.root.join(journal.root_name().as_str()).join("scratch")).unwrap();
    let impostor = GrantedRoot::open(&tree.root).unwrap();
    let before = snapshot(tree.dir.path());
    match recover(&impostor, &registry, &mut journal, &mut store) {
        Err(RecoveryError::Teardown(TeardownError::Refused {
            refusal: CleanupRefusal::RootIdentityChanged { root },
            ..
        })) => assert_eq!(root, journal.parent_root()),
        other => panic!("expected the parent to be refused, got {other:?}"),
    }
    assert_eq!(snapshot(tree.dir.path()), before);
    assert_eq!(journal.phase(), &RootPhase::Committed);
}

#[test]
fn a_journal_without_the_raw_identity_still_reads_and_recovery_is_refused() {
    let Launched {
        tree,
        parent,
        mut store,
        journal,
        root,
        ..
    } = launch(&ephemeral_layout());
    let mut value = serde_json::to_value(&journal).unwrap();
    if cfg!(windows) {
        assert!(value["root_raw_identity"].is_object());
    }
    value.as_object_mut().unwrap().remove("root_raw_identity");
    let mut old: RootJournal = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(old.root_raw_identity(), None);
    assert_eq!(old.root(), journal.root());
    // Written as before the field existed.
    assert_eq!(serde_json::to_value(&old).unwrap(), value);

    std::fs::rename(&root, tree.root.join("moved")).unwrap();
    std::fs::create_dir(&root).unwrap();
    let mut restored = ManagedObjects::new();
    old.restore_registrations(&mut restored).unwrap();
    let before = snapshot(tree.dir.path());
    let expected = if cfg!(windows) {
        RecoveryRefusal::NoRawIdentity
    } else {
        RecoveryRefusal::NoOpenByFileId
    };
    assert_eq!(
        refusal(recover(&parent, &restored, &mut old, &mut store)),
        expected
    );
    assert_eq!(snapshot(tree.dir.path()), before);
    assert_eq!(old.phase(), &RootPhase::Committed);
}

#[test]
#[cfg(windows)]
fn a_tampered_raw_identity_fails_read_back() {
    let Launched {
        tree,
        parent,
        registry,
        mut store,
        journal,
        root,
    } = launch(&ephemeral_layout());
    let raw = journal.root_raw_identity().unwrap();
    let value = serde_json::to_value(&journal).unwrap();
    assert_eq!(
        serde_json::from_value::<RootJournal>(value.clone()).unwrap(),
        journal
    );
    let refused = |change: &dyn Fn(&mut serde_json::Value), message: &str| {
        let mut changed = value.clone();
        change(&mut changed);
        let error = serde_json::from_value::<RootJournal>(changed).unwrap_err();
        assert!(error.to_string().contains(message), "{error}");
    };
    let flipped = |at: usize| {
        let mut bytes = *raw.file_id.as_bytes();
        bytes[at] ^= 1;
        json!(FileId128::from_bytes(bytes).to_string())
    };
    let mismatch = "raw file identity does not give";
    refused(
        &|v| v["root_raw_identity"]["file_id"] = flipped(0),
        mismatch,
    );
    refused(
        &|v| v["root_raw_identity"]["file_id"] = flipped(7),
        mismatch,
    );
    refused(
        &|v| v["root_raw_identity"]["volume_serial"] = json!(raw.volume_serial ^ 1),
        mismatch,
    );
    refused(
        &|v| v["root_raw_identity"]["created"] = json!(raw.created ^ 1),
        mismatch,
    );
    refused(
        &|v| v["root_raw_identity"]["unknown"] = json!(1),
        "unknown field",
    );
    refused(
        &|v| v["root_raw_identity"]["file_id"] = json!("00"),
        "32 hexadecimal digits",
    );
    refused(
        &|v| v["root_raw_identity"]["file_id"] = json!("zz".repeat(16)),
        "32 hexadecimal digits",
    );
    // A raw identity beside a root whose creation was only journaled.
    refused(
        &|v| {
            v["phase"] = json!({"phase": "creating"});
            v["root"] = json!({"state": "creating"});
            v["entries"] = json!([]);
        },
        mismatch,
    );

    // The high halves are bound by no digest, so a change there reads back; recovery then
    // finds no object with the whole raw identity and refuses.
    let mut high = value.clone();
    high["root_raw_identity"]["file_id"] = flipped(12);
    let mut tampered: RootJournal = serde_json::from_value(high).unwrap();
    std::fs::rename(&root, tree.root.join("moved")).unwrap();
    std::fs::create_dir(&root).unwrap();
    let before = snapshot(tree.dir.path());
    assert!(matches!(
        refusal(recover(&parent, &registry, &mut tampered, &mut store)),
        RecoveryRefusal::OriginalGone | RecoveryRefusal::IdentityChanged
    ));
    assert_eq!(snapshot(tree.dir.path()), before);
}

#[test]
#[cfg(windows)]
fn a_recovery_stopped_after_any_deletion_resumes_from_its_journal() {
    let mut interruptions = 0;
    for stop in 1.. {
        let launched = launch(&ephemeral_layout());
        let root = launched.root.clone();
        write(&root, "scratch/a/b/c.txt", b"c");
        write(&root, "scratch/a/d.txt", b"d");
        write(&root, "scratch/e.txt", b"e");
        write(&root, "overlay/disk", b"disk");
        write(&root, "venv/lib/x.py", b"x");
        write(&root, "vm.sock", b"socket");
        dir_link(&host(&root, "scratch/a/escape"), &launched.tree.outside);
        let moved = launched.tree.root.join("moved");
        replace(&launched, &moved, Replacement::Directory);
        let Launched {
            tree,
            parent,
            registry,
            mut store,
            mut journal,
            ..
        } = launched;
        let before = snapshot(tree.dir.path());
        let mut deletions = 0;
        let result = recover_teardown_with(
            &parent,
            &registry,
            &mut journal,
            &mut store,
            &NoVmProcesses,
            &mut || {
                deletions += 1;
                deletions < stop
            },
        );
        match result {
            Ok(report) => {
                assert!(report.teardown.torn_down);
                assert!(stop > 10, "every deletion point was met");
                break;
            }
            Err(RecoveryError::Teardown(TeardownError::Interrupted { .. })) => interruptions += 1,
            Err(other) => panic!("stop {stop}: {other}"),
        }
        // As after a crash: the journal last persisted, read back strictly, the parent
        // opened again and the registrations restored into a new registry.
        let mut recovered = store.read_back();
        assert!(matches!(recovered.phase(), RootPhase::TearingDown { .. }));
        assert_eq!(
            recovered, journal,
            "stop {stop}: every finished object was journaled"
        );
        let mut restored = ManagedObjects::new();
        recovered.restore_registrations(&mut restored).unwrap();
        let reopened = GrantedRoot::open(&tree.root).unwrap();
        let report = recover(&reopened, &restored, &mut recovered, &mut store).unwrap();
        assert!(report.teardown.torn_down, "stop {stop}: {report:?}");
        assert_eq!(report.left_at_name, LeftAtName::Directory);
        assert!(!present(&moved), "stop {stop}");
        // Only the original went: the replacement and the outside are as they were.
        assert_eq!(
            without(&snapshot(tree.dir.path()), "root/moved"),
            without(&before, "root/moved"),
            "stop {stop}"
        );
        // What the stopped run finished is reported already gone; the rest is finished now.
        let found = outcomes(&report.teardown.objects);
        for done in journal.phase().finished() {
            assert_eq!(
                found[done.name.as_str()],
                TeardownOutcome::AlreadyGone,
                "stop {stop}"
            );
        }
        assert!(report.teardown.objects.iter().all(|object| matches!(
            object.outcome,
            TeardownOutcome::Deleted { .. } | TeardownOutcome::AlreadyGone
        )));
        let finished = store.read_back();
        assert!(matches!(finished.phase(), RootPhase::TornDown { .. }));
        assert_eq!(finished.phase().finished().len(), 4);
    }
    // Twelve deletions in the entries, the root's file, and the root itself by its file ID.
    assert_eq!(interruptions, 14);
}

#[test]
#[cfg(unix)]
fn recovery_is_refused_where_nothing_opens_by_file_id() {
    let Launched {
        tree,
        parent,
        registry,
        mut store,
        mut journal,
        root,
    } = launch(&ephemeral_layout());
    assert_eq!(journal.root_raw_identity(), None);
    std::fs::rename(&root, tree.root.join("moved")).unwrap();
    std::fs::create_dir(&root).unwrap();
    let before = snapshot(tree.dir.path());
    assert_eq!(
        refusal(recover(&parent, &registry, &mut journal, &mut store)),
        RecoveryRefusal::NoOpenByFileId
    );
    assert_eq!(snapshot(tree.dir.path()), before);
}
