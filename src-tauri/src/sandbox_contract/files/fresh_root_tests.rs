//! Fresh roots, failed starts and teardown on real temporary trees (VM part §5.5, §6.1,
//! §6.4; VM-W24 acceptance "Failed starts leave no authority; user data preserved; teardown
//! cannot escape managed roots"; VM-P49).
//!
//! Directory links are junctions on Windows (`mklink /J`, no privilege needed) and symlinks
//! on Unix, made by `root_tests`' helpers. A crash is simulated with the creation and
//! deletion hooks: the run stops where the hook says, undoing nothing, and recovery reads
//! back strictly the journal last persisted, with the registrations restored into a new
//! registry.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use serde_json::json;

use super::fresh_root::{create_fresh_root_with, layout_volume_id};
use super::fsutil::{self, HandleKind};
use super::root::{identity_of, EntryProblem};
use super::root_tests::{dir_link, host, names_in, present, snapshot, tree, write, Tree, SECRET};
use super::teardown::teardown_with;
use super::*;
use crate::foundation::coordination::VmInstanceId;
use crate::foundation::ids::{digest, Digest, ExecutionId, SandboxBootGeneration, TenantId};
use crate::foundation::process::{IdentityCheck, ProcessError, ProcessIdentity, TerminationProof};

/// The VM-process evidence of a boot that started no VM: never consulted, and refusing if it
/// were.
pub(super) struct NoVmProcesses;

impl VmProcessEnds for NoVmProcesses {
    fn proof(&self, _: &VmInstanceId) -> Option<&TerminationProof> {
        None
    }

    fn check(&self, _: &ProcessIdentity) -> Result<IdentityCheck, ProcessError> {
        Ok(IdentityCheck::Same)
    }
}

/// [`super::teardown`] for a boot that started no VM.
fn teardown<J: RootJournalStore>(
    parent: &GrantedRoot,
    registry: &ManagedObjects,
    journal: &mut RootJournal,
    store: &mut J,
) -> Result<TeardownReport, TeardownError> {
    super::teardown(parent, registry, journal, store, &NoVmProcesses)
}

/// A journal store that keeps the journal as the JSON a disk would hold. With `fail_from`
/// set, every write from that one on fails (1 is the first).
#[derive(Default)]
pub(super) struct MemoryStore {
    stored: Option<String>,
    writes: usize,
    fail_from: Option<usize>,
}

impl MemoryStore {
    pub(super) fn failing_from(write: usize) -> Self {
        Self {
            fail_from: Some(write),
            ..Self::default()
        }
    }

    fn write(&mut self, journal: &RootJournal) -> Result<(), RootJournalFailure> {
        self.writes += 1;
        if self.fail_from.is_some_and(|from| self.writes >= from) {
            return Err(RootJournalFailure);
        }
        self.stored = Some(serde_json::to_string(journal).unwrap());
        Ok(())
    }

    /// The journal last persisted, read back strictly.
    pub(super) fn stored_json(&self) -> &str {
        self.stored.as_deref().unwrap()
    }

    pub(super) fn read_back(&self) -> RootJournal {
        serde_json::from_str(self.stored.as_deref().unwrap()).unwrap()
    }
}

impl RootJournalStore for MemoryStore {
    fn begin(&mut self, journal: &RootJournal) -> Result<(), RootJournalFailure> {
        if self.stored.is_some() {
            return Err(RootJournalFailure);
        }
        self.write(journal)
    }

    fn persist(&mut self, journal: &RootJournal) -> Result<(), RootJournalFailure> {
        self.write(journal)
    }
}

pub(super) fn id(name: &str) -> Digest {
    digest("yougori/test/fresh-root/v1", &[name.as_bytes()])
}

fn name(text: &str) -> GuestName {
    GuestName::parse(text).unwrap()
}

pub(super) fn boot(generation: u64) -> SandboxBoot {
    SandboxBoot {
        execution: ExecutionId::new("exe-m13a").unwrap(),
        tenant: TenantId::new("tenant-m13a").unwrap(),
        boot: SandboxBootGeneration::new(generation),
    }
}

fn entry(text: &str, entry: RootEntry) -> LayoutEntry {
    LayoutEntry {
        name: name(text),
        entry,
    }
}

fn volume(text: &str, renewal: VolumeRenewal) -> LayoutEntry {
    entry(text, RootEntry::Volume { renewal })
}

/// A layout in the strict profile.
fn layout(entries: Vec<LayoutEntry>) -> RootLayout {
    RootLayout {
        base_image: id("base-image"),
        profile: PersistenceProfile::Strict,
        entries,
    }
}

fn validated_data() -> VolumeRenewal {
    VolumeRenewal::PureApplicationData {
        validation: Some(id("check")),
        backup: Some(id("backup")),
    }
}

/// Preserved user data, two kept classes, a rebuilt environment, an overlay and scratch.
fn full_layout() -> RootLayout {
    layout(vec![
        volume("workspace", VolumeRenewal::SourceWorkspace),
        volume("data", validated_data()),
        volume("output", VolumeRenewal::UnreviewedOutput),
        volume(
            "venv",
            VolumeRenewal::ExecutableEnvironmentRebuild {
                pinned_manifest: id("lock"),
            },
        ),
        entry("overlay", RootEntry::Overlay),
        entry("scratch", RootEntry::Scratch),
    ])
}

/// Only directories teardown deletes.
pub(super) fn ephemeral_layout() -> RootLayout {
    layout(vec![
        volume(
            "venv",
            VolumeRenewal::ExecutableEnvironmentRebuild {
                pinned_manifest: id("lock"),
            },
        ),
        entry("overlay", RootEntry::Overlay),
        entry("scratch", RootEntry::Scratch),
    ])
}

/// A committed fresh root of boot 1 in a temporary managed parent (`tree.root`), whose
/// `tree.outside` links may point at.
pub(super) struct Launched {
    pub(super) tree: Tree,
    pub(super) parent: GrantedRoot,
    pub(super) registry: ManagedObjects,
    pub(super) store: MemoryStore,
    pub(super) journal: RootJournal,
    /// The sandbox root's host path, for the test's own checks only.
    pub(super) root: PathBuf,
}

pub(super) fn launch(layout: &RootLayout) -> Launched {
    let tree = tree();
    let parent = GrantedRoot::open(&tree.root).unwrap();
    let mut registry = ManagedObjects::new();
    let mut store = MemoryStore::default();
    let journal = create_fresh_root(&parent, &boot(1), layout, &mut registry, &mut store).unwrap();
    let root = tree.root.join(journal.root_name().as_str());
    Launched {
        tree,
        parent,
        registry,
        store,
        journal,
        root,
    }
}

pub(super) fn outcomes(objects: &[FinishedObject]) -> BTreeMap<String, TeardownOutcome> {
    objects
        .iter()
        .map(|object| (object.name.as_str().to_owned(), object.outcome))
        .collect()
}

fn deleted(entries: u64) -> TeardownOutcome {
    TeardownOutcome::Deleted { entries }
}

fn spared(deleted: u64, spared: u64) -> TeardownOutcome {
    TeardownOutcome::Incomplete {
        deleted,
        left: LeftBehind {
            spared,
            ..LeftBehind::default()
        },
    }
}

/// Every V05 object of a committed journal, observed as present with its root.
fn all_present(parent: &GrantedRoot, journal: &RootJournal) -> ObservedIdentities {
    let root = journal.root().identity().unwrap();
    let mut observed = ObservedIdentities::default();
    observed
        .roots
        .insert(journal.parent_root(), parent.identity().digest());
    observed
        .roots
        .insert(journal.boot().managed_root(), root.digest());
    observed.objects_present.insert(root.digest());
    for entry in journal.entries() {
        observed
            .objects_present
            .insert(entry.state.identity().unwrap().digest());
    }
    observed
}

#[test]
fn the_dispositions_are_v05s_renewal_plan() {
    use TeardownDisposition as D;
    let broker = VolumeRenewal::CredentialState {
        holder: CredentialHolder::ExternalBroker {
            broker: id("broker"),
        },
    };
    let copied = VolumeRenewal::CredentialState {
        holder: CredentialHolder::CopiedLongLived,
    };
    let cases = [
        (VolumeRenewal::SourceWorkspace, D::PreserveUserData),
        (
            validated_data(),
            D::Keep {
                class: VolumeClass::PureApplicationData,
            },
        ),
        (
            VolumeRenewal::ExecutableEnvironmentRebuild {
                pinned_manifest: id("lock"),
            },
            D::Remove,
        ),
        (
            VolumeRenewal::ExecutableEnvironmentPreserve {
                weaker_claim_acknowledged: true,
            },
            D::Keep {
                class: VolumeClass::ExecutableEnvironmentCache,
            },
        ),
        (broker, D::Remove),
        (
            VolumeRenewal::UnreviewedOutput,
            D::Keep {
                class: VolumeClass::UnreviewedOutput,
            },
        ),
    ];
    for (renewal, disposition) in cases {
        let one = layout(vec![volume("v", renewal)]);
        assert_eq!(one.dispositions().unwrap(), [disposition], "{renewal:?}");
        // Exactly what V05's own plan of the volume says.
        let summary = plan_renewal(
            &RenewalRequest {
                base_image: one.base_image,
                keep_guest_root_changes: false,
                volumes: vec![(id("any"), renewal)],
                bytes_verified_identical: false,
            },
            PersistenceProfile::Strict,
        )
        .unwrap();
        assert_eq!(TeardownDisposition::of_plan(&summary.plans[0]), disposition);
    }
    // Copied long-lived credentials only exist in the compatible profile, and are kept.
    let compatible = RootLayout {
        profile: PersistenceProfile::Compatible,
        ..layout(vec![volume("credentials", copied)])
    };
    assert_eq!(
        compatible.dispositions().unwrap(),
        [D::Keep {
            class: VolumeClass::CredentialState
        }]
    );
    assert_eq!(
        layout(vec![
            entry("overlay", RootEntry::Overlay),
            entry("scratch", RootEntry::Scratch)
        ])
        .dispositions()
        .unwrap(),
        [D::Remove, D::Remove]
    );
    // Kept and preserved volumes are of the kinds V05's cleanup check refuses to delete.
    let workspace = RootEntry::Volume {
        renewal: VolumeRenewal::SourceWorkspace,
    };
    assert_eq!(
        D::PreserveUserData.object_kind(workspace),
        ManagedObjectKind::UserSourceData
    );
    assert_eq!(
        D::Keep {
            class: VolumeClass::UnreviewedOutput
        }
        .object_kind(RootEntry::Volume {
            renewal: VolumeRenewal::UnreviewedOutput
        }),
        ManagedObjectKind::RetainedVolume
    );
    assert_eq!(
        D::Remove.object_kind(RootEntry::Overlay),
        ManagedObjectKind::Overlay
    );
    assert_eq!(
        D::Remove.object_kind(RootEntry::Volume { renewal: broker }),
        ManagedObjectKind::ScratchDirectory
    );
}

#[test]
fn a_volume_v05_refuses_is_never_launched() {
    let tree = tree();
    let parent = GrantedRoot::open(&tree.root).unwrap();
    let mut registry = ManagedObjects::new();
    let copied = VolumeRenewal::CredentialState {
        holder: CredentialHolder::CopiedLongLived,
    };
    let refused = [
        (copied, PersistenceProfile::Strict),
        (
            VolumeRenewal::ExecutableEnvironmentPreserve {
                weaker_claim_acknowledged: false,
            },
            PersistenceProfile::Compatible,
        ),
        (
            VolumeRenewal::PureApplicationData {
                validation: None,
                backup: Some(id("backup")),
            },
            PersistenceProfile::Compatible,
        ),
        (
            VolumeRenewal::PureApplicationData {
                validation: Some(id("check")),
                backup: None,
            },
            PersistenceProfile::Strict,
        ),
    ];
    for (renewal, profile) in refused {
        let layout = RootLayout {
            profile,
            ..layout(vec![
                entry("scratch", RootEntry::Scratch),
                volume("volume", renewal),
            ])
        };
        let expected = plan_renewal(
            &RenewalRequest {
                base_image: layout.base_image,
                keep_guest_root_changes: false,
                volumes: vec![(layout_volume_id(&name("volume")), renewal)],
                bytes_verified_identical: false,
            },
            profile,
        )
        .unwrap_err();
        let mut store = MemoryStore::default();
        match create_fresh_root(&parent, &boot(1), &layout, &mut registry, &mut store) {
            Err(LaunchFailure::NotStarted(LaunchRefusal::Renewal(refusal))) => {
                assert_eq!(refusal, expected)
            }
            other => panic!("expected V05's refusal of {renewal:?}, got {other:?}"),
        }
        assert_eq!(store.writes, 0);
    }
    assert!(names_in(&tree.root).is_empty());
    assert_eq!(registry, ManagedObjects::new());

    // The compatible profile takes copied credentials, and teardown keeps them.
    let Launched {
        tree: _tree,
        parent,
        registry,
        mut store,
        mut journal,
        root,
    } = launch(&RootLayout {
        profile: PersistenceProfile::Compatible,
        ..layout(vec![
            volume("credentials", copied),
            entry("scratch", RootEntry::Scratch),
        ])
    });
    write(&root, "credentials/token", b"token");
    let report = teardown(&parent, &registry, &mut journal, &mut store).unwrap();
    assert!(report.torn_down);
    assert_eq!(
        outcomes(&report.objects)["credentials"],
        TeardownOutcome::Kept {
            class: VolumeClass::CredentialState
        }
    );
    assert_eq!(fs::read(root.join("credentials/token")).unwrap(), b"token");
}

#[test]
fn a_fresh_root_is_created_once_per_boot_with_classified_registered_volumes() {
    let Launched {
        tree,
        parent,
        registry,
        mut store,
        journal,
        root,
    } = launch(&full_layout());
    assert_eq!(names_in(&tree.root), [journal.root_name().as_str()]);
    assert_eq!(
        names_in(&root),
        ["data", "output", "overlay", "scratch", "venv", "workspace"]
    );
    assert_eq!(journal.phase(), &RootPhase::Committed);
    assert_eq!(store.read_back(), journal);
    // Each identity is the one a root opened on the directory has.
    assert_eq!(
        journal.root().identity(),
        Some(GrantedRoot::open(&root).unwrap().identity())
    );
    for entry in journal.entries() {
        let opened = GrantedRoot::open(&root.join(entry.name.as_str())).unwrap();
        assert_eq!(entry.state.identity(), Some(opened.identity()));
        assert_eq!(journal.identity_of(&entry.name), Some(opened.identity()));
    }
    // V05 knows every object: what teardown removes may be cleaned up, while kept volumes
    // and user data are registered as the kind V05 itself refuses to clean up.
    let observed = all_present(&parent, &journal);
    let dispositions = journal.dispositions().unwrap();
    assert_eq!(dispositions, full_layout().dispositions().unwrap());
    for (entry, disposition) in journal.entries().iter().zip(dispositions) {
        let handle = entry.state.handle().unwrap();
        let plan = registry.validate_cleanup(&CleanupTarget::Object { handle }, &observed);
        match disposition {
            TeardownDisposition::Remove => {
                assert!(matches!(plan, Ok(CleanupPlan::Delete { .. })), "{plan:?}");
            }
            TeardownDisposition::Keep { .. } => assert_eq!(
                plan,
                Err(CleanupRefusal::RetainedByRenewal {
                    object: handle.object
                }),
                "{}",
                entry.name
            ),
            TeardownDisposition::PreserveUserData => assert_eq!(
                plan,
                Err(CleanupRefusal::PreservesUserData {
                    object: handle.object
                }),
                "{}",
                entry.name
            ),
        }
    }
    // The boot is never launched again: the store holds its journal, and a store that lost
    // it meets the existing root, which is left as it is.
    let mut again = registry.clone();
    assert!(matches!(
        create_fresh_root(&parent, &boot(1), &full_layout(), &mut again, &mut store),
        Err(LaunchFailure::NotStarted(LaunchRefusal::JournalNotBegun(_)))
    ));
    let mut forgetful = MemoryStore::default();
    match create_fresh_root(
        &parent,
        &boot(1),
        &full_layout(),
        &mut again,
        &mut forgetful,
    ) {
        Err(LaunchFailure::RolledBack {
            cause: LaunchCause::RootExists,
            compensation,
        }) => assert_eq!(
            compensation.objects,
            [CompensatedObject {
                name: journal.root_name().clone(),
                outcome: CompensationOutcome::NeverCreated
            }]
        ),
        other => panic!("expected the existing root to be refused, got {other:?}"),
    }
    assert_eq!(again, registry);
    assert_eq!(names_in(&root).len(), 6);
    // Another boot gets a root of its own.
    let next = create_fresh_root(
        &parent,
        &boot(2),
        &full_layout(),
        &mut again,
        &mut MemoryStore::default(),
    )
    .unwrap();
    assert_ne!(next.root_name(), journal.root_name());
    assert_eq!(names_in(&tree.root).len(), 2);
}

#[test]
fn a_layout_is_checked_before_anything_is_created() {
    let tree = tree();
    let parent = GrantedRoot::open(&tree.root).unwrap();
    let mut registry = ManagedObjects::new();
    let cases = [
        (
            vec![
                entry("scratch", RootEntry::Scratch),
                entry("Scratch", RootEntry::Overlay),
            ],
            "differs from",
        ),
        (
            vec![
                entry("scratch", RootEntry::Scratch),
                entry("scratch", RootEntry::Overlay),
            ],
            "twice",
        ),
        (vec![entry("a/b", RootEntry::Scratch)], "single component"),
        (
            (0..=MAX_ROOT_ENTRIES)
                .map(|index| entry(&format!("d{index}"), RootEntry::Scratch))
                .collect(),
            "at most",
        ),
    ];
    for (entries, message) in cases {
        let mut store = MemoryStore::default();
        match create_fresh_root(
            &parent,
            &boot(1),
            &layout(entries),
            &mut registry,
            &mut store,
        ) {
            Err(LaunchFailure::NotStarted(refusal @ LaunchRefusal::Layout(_))) => {
                assert!(refusal.to_string().contains(message), "{refusal}")
            }
            other => panic!("expected a layout refusal, got {other:?}"),
        }
        assert_eq!(store.writes, 0);
    }
    assert!(names_in(&tree.root).is_empty());
    assert_eq!(registry, ManagedObjects::new());
}

#[test]
fn a_failed_start_leaves_no_directory_and_no_registration() {
    let tree = tree();
    let parent = GrantedRoot::open(&tree.root).unwrap();
    // Another sandbox's root and registrations, which no failed start may touch.
    let mut registry = ManagedObjects::new();
    let neighbour = create_fresh_root(
        &parent,
        &boot(99),
        &ephemeral_layout(),
        &mut registry,
        &mut MemoryStore::default(),
    )
    .unwrap();
    let registered = registry.clone();
    let writes = {
        let probe = super::root_tests::tree();
        let mut store = MemoryStore::default();
        create_fresh_root(
            &GrantedRoot::open(&probe.root).unwrap(),
            &boot(1),
            &full_layout(),
            &mut ManagedObjects::new(),
            &mut store,
        )
        .unwrap();
        store.writes
    };
    assert_eq!(writes, 3 + 2 * full_layout().entries.len());
    // Every journal write from the first on fails in turn, as on a full disk.
    for from in 1..=writes {
        let mut store = MemoryStore::failing_from(from);
        match create_fresh_root(&parent, &boot(1), &full_layout(), &mut registry, &mut store) {
            Err(LaunchFailure::NotStarted(LaunchRefusal::JournalNotBegun(_))) => {
                assert_eq!(from, 1)
            }
            Err(LaunchFailure::RolledBack {
                cause: LaunchCause::Journal(_),
                compensation,
            }) => {
                assert!(compensation.complete(), "write {from}: {compensation:?}");
                assert!(!compensation.journal_written);
            }
            other => panic!("write {from}: expected a rollback, got {other:?}"),
        }
        assert_eq!(
            names_in(&tree.root),
            [neighbour.root_name().as_str()],
            "write {from}"
        );
        assert_eq!(registry, registered, "write {from}");
    }
}

#[test]
fn a_launch_stopped_at_any_step_is_undone_from_its_journal() {
    let tree = tree();
    let parent = GrantedRoot::open(&tree.root).unwrap();
    let mut outcomes_seen = Vec::new();
    for stop in 1.. {
        let mut store = MemoryStore::default();
        let mut registry = ManagedObjects::new();
        let mut steps = 0;
        let result = create_fresh_root_with(
            &parent,
            &boot(1),
            &full_layout(),
            &mut registry,
            &mut store,
            &mut || {
                steps += 1;
                steps < stop
            },
        );
        match result {
            Ok(_) => {
                assert!(stop > 3 + 3 * full_layout().entries.len());
                break;
            }
            Err(LaunchFailure::Interrupted) => {}
            Err(other) => panic!("stop {stop}: {other:?}"),
        }
        assert_eq!(registry, ManagedObjects::new(), "stop {stop}");
        let mut journal = store.read_back();
        assert!(journal.phase().is_compensable());
        let report = compensate_launch(&parent, &mut journal, &mut store).unwrap();
        assert!(report.complete(), "stop {stop}: {report:?}");
        assert!(report.journal_written);
        assert!(names_in(&tree.root).is_empty(), "stop {stop}");
        assert_eq!(store.read_back().phase(), &RootPhase::Compensated);
        outcomes_seen.extend(report.objects.into_iter().map(|object| object.outcome));
        // Again: nothing is left to do.
        let again = compensate_launch(&parent, &mut store.read_back(), &mut store).unwrap();
        assert!(again.objects.iter().all(|object| matches!(
            object.outcome,
            CompensationOutcome::AlreadyGone | CompensationOutcome::NeverCreated
        )));
    }
    // Stops between a creation and the journal write of its identity were met too.
    assert!(outcomes_seen.contains(&CompensationOutcome::RemovedUnconfirmed));
    assert!(outcomes_seen.contains(&CompensationOutcome::Removed));
}

#[test]
fn compensation_and_teardown_each_refuse_the_other_phase() {
    let Launched {
        tree,
        parent,
        registry,
        mut store,
        mut journal,
        root,
    } = launch(&ephemeral_layout());
    assert_eq!(
        compensate_launch(&parent, &mut journal, &mut store),
        Err(CompensationError::Committed)
    );
    assert_eq!(names_in(&root).len(), 3);
    // A launch that never committed is not torn down, nor its registrations restored.
    let mut interrupted_store = MemoryStore::default();
    let interrupted = create_fresh_root_with(
        &parent,
        &boot(2),
        &ephemeral_layout(),
        &mut ManagedObjects::new(),
        &mut interrupted_store,
        &mut || false,
    );
    assert!(matches!(interrupted, Err(LaunchFailure::Interrupted)));
    let mut never_committed = interrupted_store.read_back();
    assert!(matches!(
        teardown(
            &parent,
            &registry,
            &mut never_committed,
            &mut interrupted_store
        ),
        Err(TeardownError::NotCommitted)
    ));
    assert_eq!(
        never_committed.restore_registrations(&mut ManagedObjects::new()),
        Err(RegistrationError::NotCommitted)
    );
    // Compensation refuses another directory opened at the parent's path.
    fs::rename(&tree.root, tree.dir.path().join("parent-moved")).unwrap();
    fs::create_dir(&tree.root).unwrap();
    let impostor = GrantedRoot::open(&tree.root).unwrap();
    assert_eq!(
        compensate_launch(&impostor, &mut never_committed, &mut interrupted_store),
        Err(CompensationError::Refused(
            CleanupRefusal::RootIdentityChanged {
                root: never_committed.parent_root()
            }
        ))
    );
}

#[test]
fn a_junction_inside_a_sandbox_root_is_removed_as_itself_and_the_outside_is_unchanged() {
    let Launched {
        tree,
        parent,
        registry,
        mut store,
        mut journal,
        root,
    } = launch(&ephemeral_layout());
    write(&root, "scratch/a/b/c.txt", b"c");
    write(&root, "overlay/disk.qcow2", b"disk");
    dir_link(&host(&root, "scratch/a/escape"), &tree.outside);
    dir_link(&host(&root, "overlay/escape"), &tree.outside.join("sub"));
    dir_link(&root.join("escape-top"), &tree.outside);
    // Another name of an outside file: only this name goes.
    fs::hard_link(
        tree.outside.join("secret.txt"),
        host(&root, "scratch/twin.txt"),
    )
    .unwrap();
    let outside_before = snapshot(&tree.outside);
    let report = teardown(&parent, &registry, &mut journal, &mut store).unwrap();
    assert!(report.torn_down);
    assert!(!present(&root));
    assert_eq!(snapshot(&tree.outside), outside_before);
    assert_eq!(fs::read(tree.outside.join("secret.txt")).unwrap(), SECRET);
    let root_name = journal.root_name().as_str().to_owned();
    assert_eq!(
        outcomes(&report.objects),
        BTreeMap::from([
            ("scratch".to_owned(), deleted(6)),
            ("overlay".to_owned(), deleted(3)),
            ("venv".to_owned(), deleted(1)),
            (root_name, deleted(2)),
        ])
    );
}

#[test]
fn a_volume_swapped_for_a_junction_is_already_gone_and_the_junction_goes_as_itself() {
    let Launched {
        tree,
        parent,
        registry,
        mut store,
        mut journal,
        root,
    } = launch(&ephemeral_layout());
    write(&root, "scratch/tmp.txt", b"tmp");
    fs::rename(root.join("scratch"), root.join("moved")).unwrap();
    dir_link(&root.join("scratch"), &tree.outside);
    let outside_before = snapshot(&tree.outside);
    let report = teardown(&parent, &registry, &mut journal, &mut store).unwrap();
    let found = outcomes(&report.objects);
    assert_eq!(found["scratch"], TeardownOutcome::AlreadyGone);
    // The root's own removal took the junction as itself and the moved directory with it.
    assert_eq!(found[journal.root_name().as_str()], deleted(4));
    assert!(!present(&root));
    assert_eq!(snapshot(&tree.outside), outside_before);
}

#[test]
fn user_data_and_kept_classes_survive_teardown() {
    let Launched {
        tree,
        parent,
        registry,
        mut store,
        mut journal,
        root,
    } = launch(&full_layout());
    let files = [
        ("workspace", "src/main.rs"),
        ("data", "db.sqlite"),
        ("output", "result.txt"),
        ("venv", "bin/python"),
        ("overlay", "disk"),
        ("scratch", "tmp"),
    ];
    for (directory, file) in files {
        write(&root, &format!("{directory}/{file}"), directory.as_bytes());
    }
    // A junction inside user data is user data's own and stays; a file the backend left
    // in the root goes.
    dir_link(&host(&root, "workspace/escape"), &tree.outside);
    write(&root, "vm.sock", b"socket");
    let outside_before = snapshot(&tree.outside);
    let report = teardown(&parent, &registry, &mut journal, &mut store).unwrap();
    assert!(report.torn_down);
    let root_name = journal.root_name().as_str().to_owned();
    assert_eq!(
        outcomes(&report.objects),
        BTreeMap::from([
            ("workspace".to_owned(), TeardownOutcome::Preserved),
            (
                "data".to_owned(),
                TeardownOutcome::Kept {
                    class: VolumeClass::PureApplicationData
                }
            ),
            (
                "output".to_owned(),
                TeardownOutcome::Kept {
                    class: VolumeClass::UnreviewedOutput
                }
            ),
            ("venv".to_owned(), deleted(3)),
            ("overlay".to_owned(), deleted(2)),
            ("scratch".to_owned(), deleted(2)),
            (root_name.clone(), spared(1, 3)),
        ])
    );
    assert_eq!(names_in(&root), ["data", "output", "workspace"]);
    for (directory, file) in &files[..3] {
        assert_eq!(
            fs::read(root.join(directory).join(file)).unwrap(),
            directory.as_bytes()
        );
    }
    assert!(present(&host(&root, "workspace/escape")));
    assert_eq!(snapshot(&tree.outside), outside_before);
    // A second run deletes nothing more and keeps them still.
    let again = teardown(&parent, &registry, &mut journal, &mut store).unwrap();
    assert!(again.torn_down);
    let found = outcomes(&again.objects);
    assert_eq!(found["workspace"], TeardownOutcome::Preserved);
    assert_eq!(found["venv"], TeardownOutcome::AlreadyGone);
    assert_eq!(found[&root_name], spared(0, 3));
    assert_eq!(names_in(&root), ["data", "output", "workspace"]);
}

#[test]
fn a_kept_volume_moved_into_scratch_is_spared_by_its_identity() {
    let Launched {
        tree: _tree,
        parent,
        registry,
        mut store,
        mut journal,
        root,
    } = launch(&full_layout());
    write(&root, "data/db.sqlite", b"rows");
    write(&root, "scratch/tmp", b"tmp");
    fs::rename(root.join("data"), host(&root, "scratch/data")).unwrap();
    let report = teardown(&parent, &registry, &mut journal, &mut store).unwrap();
    let found = outcomes(&report.objects);
    assert_eq!(found["scratch"], spared(1, 1));
    assert!(report.torn_down);
    assert_eq!(
        fs::read(host(&root, "scratch/data/db.sqlite")).unwrap(),
        b"rows"
    );
    assert_eq!(names_in(&root.join("scratch")), ["data"]);
}

#[test]
fn a_second_teardown_is_a_no_op_that_reports_already_gone() {
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
    let first = teardown(&parent, &registry, &mut journal, &mut store).unwrap();
    assert!(first.torn_down);
    assert!(first
        .objects
        .iter()
        .all(|object| matches!(object.outcome, TeardownOutcome::Deleted { .. })));
    assert!(names_in(&tree.root).is_empty());
    let second = teardown(&parent, &registry, &mut journal, &mut store).unwrap();
    assert!(second.torn_down);
    assert_eq!(second.objects.len(), 4);
    assert!(second
        .objects
        .iter()
        .all(|object| object.outcome == TeardownOutcome::AlreadyGone));
    // The journal keeps what the first run did.
    let read = store.read_back();
    assert!(matches!(read.phase(), RootPhase::TornDown { .. }));
    assert_eq!(outcomes(read.phase().finished()), outcomes(&first.objects));
    // As after a restart: the journal read back and its registrations restored.
    let mut recovered = store.read_back();
    let mut restored = ManagedObjects::new();
    recovered.restore_registrations(&mut restored).unwrap();
    let third = teardown(&parent, &restored, &mut recovered, &mut store).unwrap();
    assert_eq!(third, second);
    assert!(names_in(&tree.root).is_empty());
}

#[test]
fn a_teardown_stopped_after_any_deletion_is_finished_by_recovery() {
    let mut interruptions = 0;
    for stop in 1.. {
        let Launched {
            tree,
            parent,
            registry,
            mut store,
            mut journal,
            root,
        } = launch(&ephemeral_layout());
        write(&root, "scratch/a/b/c.txt", b"c");
        write(&root, "scratch/a/d.txt", b"d");
        write(&root, "scratch/e.txt", b"e");
        write(&root, "overlay/disk", b"disk");
        write(&root, "venv/lib/x.py", b"x");
        write(&root, "vm.sock", b"socket");
        dir_link(&host(&root, "scratch/a/escape"), &tree.outside);
        let outside_before = snapshot(&tree.outside);
        let mut deletions = 0;
        let result = teardown_with(
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
                assert!(report.torn_down);
                assert!(stop > 10, "every deletion point was met");
                break;
            }
            Err(TeardownError::Interrupted { .. }) => interruptions += 1,
            Err(other) => panic!("stop {stop}: {other}"),
        }
        assert_eq!(snapshot(&tree.outside), outside_before, "stop {stop}");
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
        let report = teardown(&reopened, &restored, &mut recovered, &mut store).unwrap();
        assert!(report.torn_down, "stop {stop}: {report:?}");
        assert!(!present(&root), "stop {stop}");
        assert_eq!(snapshot(&tree.outside), outside_before, "stop {stop}");
        // What the stopped run finished is reported already gone; the rest is finished now.
        let found = outcomes(&report.objects);
        for done in journal.phase().finished() {
            assert_eq!(
                found[done.name.as_str()],
                TeardownOutcome::AlreadyGone,
                "stop {stop}"
            );
        }
        assert!(report.objects.iter().all(|object| matches!(
            object.outcome,
            TeardownOutcome::Deleted { .. } | TeardownOutcome::AlreadyGone
        )));
        let finished = store.read_back();
        assert!(matches!(finished.phase(), RootPhase::TornDown { .. }));
        assert_eq!(finished.phase().finished().len(), 4);
    }
    assert_eq!(interruptions, 14);
}

#[test]
fn a_replaced_managed_root_is_refused_and_nothing_is_deleted() {
    // The sandbox root replaced by another directory at the same path.
    let Launched {
        tree,
        parent,
        registry,
        mut store,
        mut journal,
        root,
    } = launch(&ephemeral_layout());
    write(&root, "scratch/a.txt", b"a");
    fs::rename(&root, tree.root.join("moved")).unwrap();
    fs::create_dir(&root).unwrap();
    write(&root, "scratch/a.txt", b"another");
    let before = snapshot(tree.dir.path());
    match teardown(&parent, &registry, &mut journal, &mut store) {
        Err(TeardownError::Refused {
            refusal: CleanupRefusal::RootIdentityChanged { root: refused },
            ..
        }) => assert_eq!(refused, boot(1).managed_root()),
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert_eq!(snapshot(tree.dir.path()), before);
    assert_eq!(journal.phase(), &RootPhase::Committed);

    // The sandbox root swapped for a junction to the outside.
    let Launched {
        tree,
        parent,
        registry,
        mut store,
        mut journal,
        root,
    } = launch(&ephemeral_layout());
    fs::rename(&root, tree.root.join("moved")).unwrap();
    dir_link(&root, &tree.outside);
    let before = snapshot(tree.dir.path());
    let outside_before = snapshot(&tree.outside);
    assert!(matches!(
        teardown(&parent, &registry, &mut journal, &mut store),
        Err(TeardownError::Refused {
            refusal: CleanupRefusal::RootIdentityChanged { .. },
            ..
        })
    ));
    assert_eq!(snapshot(tree.dir.path()), before);
    assert_eq!(snapshot(&tree.outside), outside_before);

    // The managed parent replaced: another directory opened at its path, holding a
    // directory of the root's name.
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
    match teardown(&impostor, &registry, &mut journal, &mut store) {
        Err(TeardownError::Refused {
            refusal: CleanupRefusal::RootIdentityChanged { root: refused },
            ..
        }) => assert_eq!(refused, journal.parent_root()),
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert_eq!(snapshot(tree.dir.path()), before);
    assert_eq!(names_in(&moved.join(journal.root_name().as_str())).len(), 3);

    // A root holding only kept volumes is verified too: replaced, it is refused, and
    // nothing is reported kept or torn down.
    let Launched {
        tree,
        parent,
        registry,
        mut store,
        mut journal,
        root,
    } = launch(&layout(vec![volume(
        "output",
        VolumeRenewal::UnreviewedOutput,
    )]));
    fs::rename(&root, tree.root.join("moved")).unwrap();
    fs::create_dir_all(root.join("output")).unwrap();
    let before = snapshot(tree.dir.path());
    assert!(matches!(
        teardown(&parent, &registry, &mut journal, &mut store),
        Err(TeardownError::Refused {
            refusal: CleanupRefusal::RootIdentityChanged { .. },
            ..
        })
    ));
    assert_eq!(snapshot(tree.dir.path()), before);
    assert_eq!(journal.phase(), &RootPhase::Committed);
}

#[test]
fn the_journal_is_read_back_strictly() {
    let Launched {
        tree: _tree,
        journal,
        ..
    } = launch(&full_layout());
    let text = serde_json::to_string(&journal).unwrap();
    assert_eq!(serde_json::from_str::<RootJournal>(&text).unwrap(), journal);
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    for pointer in [
        "",
        "/boot",
        "/root",
        "/phase",
        "/entries/0",
        "/entries/0/entry",
        "/entries/1/entry/renewal",
        "/entries/0/state",
        "/entries/0/state/handle",
    ] {
        let mut changed = value.clone();
        changed
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("unknown".into(), json!(1));
        assert!(
            serde_json::from_value::<RootJournal>(changed).is_err(),
            "an unknown field at {pointer:?} was accepted"
        );
    }
    let refused = |change: &dyn Fn(&mut serde_json::Value), message: &str| {
        let mut changed = value.clone();
        change(&mut changed);
        let error = serde_json::from_value::<RootJournal>(changed).unwrap_err();
        assert!(error.to_string().contains(message), "{error}");
    };
    refused(&|v| v["root_name"] = json!("sandbox-0"), "not the boot's");
    refused(&|v| v["profile"] = json!("lax"), "unknown variant");
    refused(
        &|v| v["entries"][1]["entry"]["renewal"]["validation"] = json!(null),
        "needs a validation",
    );
    refused(
        &|v| {
            v["entries"][2]["entry"]["renewal"] =
                json!({"class": "credential_state", "holder": {"holder": "copied_long_lived"}})
        },
        "copied long-lived credentials",
    );
    refused(&|v| v["boot"]["boot"] = json!(2), "not the boot's");
    refused(
        &|v| v["phase"] = json!({"phase": "creating"}),
        "does not fit the phase",
    );
    refused(
        &|v| v["entries"][5]["state"] = json!({"state": "creating"}),
        "does not fit the phase",
    );
    refused(
        &|v| v["entries"][2]["state"] = json!({"state": "not_created"}),
        "out of creation order",
    );
    refused(
        &|v| v["entries"][1]["name"] = json!("Workspace"),
        "differs from",
    );
    refused(
        &|v| v["entries"][1]["name"] = json!("a/b"),
        "single component",
    );
    refused(
        &|v| {
            v["phase"] = json!({
                "phase": "tearing_down",
                "finished": [{"name": "elsewhere", "outcome": {"outcome": "already_gone"}}]
            })
        },
        "does not hold once",
    );
    // A compensable journal whose entry precedes a root never created.
    let mut creating = value.clone();
    creating["phase"] = json!({"phase": "creating"});
    creating["root"] = json!({"state": "creating"});
    for entry in creating["entries"].as_array_mut().unwrap() {
        entry["state"] = json!({"state": "creating"});
    }
    let error = serde_json::from_value::<RootJournal>(creating).unwrap_err();
    assert!(
        error.to_string().contains("out of creation order"),
        "{error}"
    );
}

fn set_read_only(path: &Path, read_only: bool) {
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_readonly(read_only);
    fs::set_permissions(path, permissions).unwrap();
}

fn left(change: impl FnOnce(&mut LeftBehind)) -> LeftBehind {
    let mut left = LeftBehind::default();
    change(&mut left);
    left
}

#[test]
fn a_read_only_file_does_not_stop_teardown() {
    let Launched {
        tree,
        parent,
        registry,
        mut store,
        mut journal,
        root,
    } = launch(&ephemeral_layout());
    write(&root, "scratch/.git/objects/ab/cdef", b"object");
    write(&root, "overlay/disk", b"disk");
    set_read_only(&host(&root, "scratch/.git/objects/ab/cdef"), true);
    set_read_only(&host(&root, "overlay/disk"), true);
    let report = teardown(&parent, &registry, &mut journal, &mut store).unwrap();
    assert!(report.torn_down, "{report:?}");
    assert!(report.failures.is_empty());
    assert_eq!(outcomes(&report.objects)["scratch"], deleted(5));
    assert!(names_in(&tree.root).is_empty());

    // A granted root's removal still refuses a read-only file, as the platform does.
    let granted = tree.dir.path().join("granted");
    write(&granted, "read-only.txt", b"kept");
    set_read_only(&granted.join("read-only.txt"), true);
    let opened = GrantedRoot::open(&granted).unwrap();
    let removed = opened.remove_file(&name("read-only.txt"));
    if cfg!(windows) {
        assert!(
            matches!(&removed, Err(EntryProblem::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied),
            "{removed:?}"
        );
        assert!(present(&granted.join("read-only.txt")));
        set_read_only(&granted.join("read-only.txt"), false);
    }
}

#[test]
fn a_file_another_process_holds_open_goes_at_once() {
    let Launched {
        tree: _tree,
        parent,
        registry,
        mut store,
        mut journal,
        root,
    } = launch(&ephemeral_layout());
    write(&root, "scratch/held.txt", b"held");
    // Opened with delete sharing, as an indexer or a scanner opens files.
    let mut held = fs::File::open(host(&root, "scratch/held.txt")).unwrap();
    let report = teardown(&parent, &registry, &mut journal, &mut store).unwrap();
    assert!(report.torn_down, "{report:?}");
    assert!(!present(&root));
    // The holder still reads what it opened.
    let mut text = String::new();
    held.read_to_string(&mut text).unwrap();
    assert_eq!(text, "held");
}

#[cfg(windows)]
#[test]
fn one_objects_failure_does_not_stop_the_others_and_a_rerun_finishes() {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
    let Launched {
        tree: _tree,
        parent,
        registry,
        mut store,
        mut journal,
        root,
    } = launch(&ephemeral_layout());
    write(&root, "scratch/a/locked.txt", b"locked");
    write(&root, "scratch/a/free.txt", b"free");
    write(&root, "scratch/b.txt", b"b");
    write(&root, "overlay/disk", b"disk");
    write(&root, "venv/lib/x.py", b"x");
    write(&root, "vm.sock", b"socket");
    // Held open without delete sharing: nothing can open it to delete it meanwhile.
    let locked = fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(host(&root, "scratch/a/locked.txt"))
        .unwrap();
    let first = teardown(&parent, &registry, &mut journal, &mut store).unwrap();
    assert!(!first.torn_down);
    let root_name = journal.root_name().as_str().to_owned();
    assert_eq!(
        outcomes(&first.objects),
        BTreeMap::from([
            ("overlay".to_owned(), deleted(2)),
            ("venv".to_owned(), deleted(3)),
            (
                "scratch".to_owned(),
                TeardownOutcome::Incomplete {
                    deleted: 2,
                    left: left(|left| left.failed = 1)
                }
            ),
            // The stray file went; the root stays, empty but for the unfinished scratch.
            (
                root_name.clone(),
                TeardownOutcome::Incomplete {
                    deleted: 1,
                    left: left(|left| left.unfinished = 1)
                }
            ),
        ])
    );
    assert_eq!(first.failures.len(), 1, "{first:?}");
    assert_eq!(first.failures[0].name, name("scratch"));
    assert_eq!(names_in(&root), ["scratch"]);
    assert_eq!(names_in(&host(&root, "scratch/a")), ["locked.txt"]);
    assert!(matches!(
        store.read_back().phase(),
        RootPhase::TearingDown { .. }
    ));
    drop(locked);
    // As after a restart: the journal read back and the registrations restored.
    let mut recovered = store.read_back();
    let mut restored = ManagedObjects::new();
    recovered.restore_registrations(&mut restored).unwrap();
    let second = teardown(&parent, &restored, &mut recovered, &mut store).unwrap();
    assert!(second.torn_down, "{second:?}");
    assert!(second.failures.is_empty());
    let found = outcomes(&second.objects);
    assert_eq!(found["overlay"], TeardownOutcome::AlreadyGone);
    assert_eq!(found["scratch"], deleted(3));
    assert_eq!(found[&root_name], deleted(1));
    assert!(!present(&root));
}

#[cfg(windows)]
#[test]
fn without_posix_semantics_read_only_files_go_and_a_held_name_is_pending_until_a_rerun() {
    /// Puts the thread's removals back on the extended disposition however the test ends.
    struct Legacy;
    impl Drop for Legacy {
        fn drop(&mut self) {
            fsutil::force_legacy_disposition(false);
        }
    }
    let Launched {
        tree,
        parent,
        registry,
        mut store,
        mut journal,
        root,
    } = launch(&ephemeral_layout());
    write(&root, "scratch/read-only.txt", b"read only");
    set_read_only(&host(&root, "scratch/read-only.txt"), true);
    write(&root, "scratch/held.txt", b"held");
    write(&root, "overlay/disk", b"disk");
    let held = fs::File::open(host(&root, "scratch/held.txt")).unwrap();
    fsutil::force_legacy_disposition(true);
    let _legacy = Legacy;
    let first = teardown(&parent, &registry, &mut journal, &mut store).unwrap();
    assert!(!first.torn_down);
    assert!(first.failures.is_empty(), "{first:?}");
    let root_name = journal.root_name().as_str().to_owned();
    assert_eq!(
        outcomes(&first.objects),
        BTreeMap::from([
            ("overlay".to_owned(), deleted(2)),
            ("venv".to_owned(), deleted(1)),
            (
                "scratch".to_owned(),
                TeardownOutcome::Incomplete {
                    deleted: 1,
                    left: left(|left| left.pending = 1)
                }
            ),
            (
                root_name.clone(),
                TeardownOutcome::Incomplete {
                    deleted: 0,
                    left: left(|left| left.unfinished = 1)
                }
            ),
        ])
    );
    assert!(!present(&host(&root, "scratch/read-only.txt")));
    assert!(matches!(
        store.read_back().phase(),
        RootPhase::TearingDown { .. }
    ));
    // A granted root's removal still refuses a read-only file on this path too.
    let granted = tree.dir.path().join("granted");
    write(&granted, "read-only.txt", b"kept");
    set_read_only(&granted.join("read-only.txt"), true);
    let removed = GrantedRoot::open(&granted)
        .unwrap()
        .remove_file(&name("read-only.txt"));
    assert!(
        matches!(&removed, Err(EntryProblem::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied),
        "{removed:?}"
    );
    set_read_only(&granted.join("read-only.txt"), false);
    // Once the holder closes it the pending name is gone, and a rerun finishes.
    drop(held);
    let second = teardown(&parent, &registry, &mut journal, &mut store).unwrap();
    assert!(second.torn_down, "{second:?}");
    let found = outcomes(&second.objects);
    assert_eq!(found["scratch"], deleted(1));
    assert_eq!(found[&root_name], deleted(1));
    assert!(!present(&root));
}

#[test]
fn a_replaced_root_holding_only_user_data_or_nothing_is_refused_and_recovery_stays_open() {
    for entries in [
        vec![volume("workspace", VolumeRenewal::SourceWorkspace)],
        Vec::new(),
    ] {
        let has_workspace = !entries.is_empty();
        let Launched {
            tree,
            parent,
            registry,
            mut store,
            mut journal,
            root,
        } = launch(&layout(entries));
        if has_workspace {
            write(&root, "workspace/src/main.rs", b"fn main() {}");
        }
        let moved = tree.root.join("moved");
        fs::rename(&root, &moved).unwrap();
        fs::create_dir(&root).unwrap();
        let committed = store.read_back();
        let before = snapshot(tree.dir.path());
        match teardown(&parent, &registry, &mut journal, &mut store) {
            Err(TeardownError::Refused {
                name: refused_name,
                refusal: CleanupRefusal::RootIdentityChanged { root: refused },
            }) => {
                assert_eq!(&refused_name, journal.root_name());
                assert_eq!(refused, boot(1).managed_root());
            }
            other => panic!("expected the replaced root to be refused, got {other:?}"),
        }
        assert_eq!(snapshot(tree.dir.path()), before);
        assert_eq!(journal.phase(), &RootPhase::Committed);
        assert_eq!(store.read_back(), committed);
        // Recovery stays open: with the root back at its name, teardown finishes.
        fs::remove_dir(&root).unwrap();
        fs::rename(&moved, &root).unwrap();
        let report = teardown(&parent, &registry, &mut journal, &mut store).unwrap();
        assert!(report.torn_down, "{report:?}");
        if has_workspace {
            assert_eq!(
                outcomes(&report.objects)["workspace"],
                TeardownOutcome::Preserved
            );
            assert_eq!(
                fs::read(host(&root, "workspace/src/main.rs")).unwrap(),
                b"fn main() {}"
            );
        } else {
            assert!(!present(&root));
        }
    }
}

#[test]
fn a_created_directory_has_the_identity_of_the_handle_that_created_it() {
    let tree = tree();
    let parent = GrantedRoot::open(&tree.root).unwrap();
    let created = fsutil::create_directory(parent.dir(), "fresh").unwrap();
    assert_eq!(created.kind, HandleKind::Directory);
    let entry = fsutil::entry_info(parent.dir(), "fresh").unwrap();
    assert!(entry.is(&created));
    assert_eq!(entry.created, created.created);
    assert_eq!(
        identity_of(&created),
        GrantedRoot::open(&tree.root.join("fresh"))
            .unwrap()
            .identity()
    );
    assert_eq!(
        fsutil::create_directory(parent.dir(), "fresh")
            .unwrap_err()
            .kind(),
        io::ErrorKind::AlreadyExists
    );
}
