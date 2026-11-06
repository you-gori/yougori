//! Promotion as a transaction on temporary directories (VM part §5.2; §2.6 line 1835;
//! VM-P16, VM-P34, VM-W14 acceptance: a changed reviewed artifact or destination
//! precondition prevents apply).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;

use super::fakes::{audit_config, execution, session, MemoryAuditStore, NoSpool};
use super::*;
use crate::foundation::events::{
    AuditJournal, AuditReceipt, AuditRefusal, Durability, EventSequence, Field, JournalId,
    ProducerId,
};
use crate::foundation::ids::{
    digest, ContentKey, ExecutionCategory, ManualClock, MonotonicTime, OperationId,
    SandboxBootGeneration, TrustScope,
};

type Clock = Arc<ManualClock>;
type Journal = AuditJournal<MemoryAuditStore, NoSpool, Clock>;

struct Fixture {
    _dir: TempDir,
    source: PathBuf,
    destination: PathBuf,
    backups: PathBuf,
    clock: Clock,
    store: MemoryAuditStore,
    journal: Journal,
    authority: crate::foundation::events::AuditAppendAuthority,
}

fn name(text: &str) -> GuestName {
    GuestName::parse(text).unwrap()
}

fn write(root: &Path, text: &str, bytes: &[u8]) {
    let path = root.join(text);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

fn read(root: &Path, text: &str) -> Vec<u8> {
    fs::read(root.join(text)).unwrap()
}

fn scope() -> TrustScope {
    TrustScope::named(ExecutionCategory::VmSandbox, "sandbox-a")
}

fn provenance() -> Provenance {
    Provenance {
        execution: execution("exe-sandbox"),
        boot: SandboxBootGeneration::FIRST,
        operation: OperationId::new("op-build").unwrap(),
        scope: scope(),
    }
}

fn policy() -> PromotionPolicy {
    PromotionPolicy {
        allowed_prefixes: [
            "src",
            "docs",
            "Docs",
            ".git",
            ".github",
            ".GitHub",
            ".husky",
            ".bashrc",
            "build.rs",
            "Makefile",
            "package.json",
            "run.bat",
            ".vscode",
            "deploy.sh",
        ]
        .iter()
        .map(|text| name(text))
        .collect(),
        max_entries: 16,
        max_file_bytes: 1_024,
        max_total_bytes: 4_096,
        allow_executable: false,
        expected: ExpectedProvenance {
            execution: execution("exe-sandbox"),
            scope: scope(),
        },
    }
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("quarantine");
    let destination = dir.path().join("project");
    let backups = dir.path().join("backups");
    for path in [&source, &destination, &backups] {
        fs::create_dir(path).unwrap();
    }
    let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(1_000_000_000)));
    let store = MemoryAuditStore::default();
    let (journal, authority) = AuditJournal::open(
        JournalId::new("engine").unwrap(),
        ProducerId::new("engine").unwrap(),
        store.clone(),
        NoSpool,
        Arc::clone(&clock),
        audit_config(),
    )
    .unwrap();
    Fixture {
        _dir: dir,
        source,
        destination,
        backups,
        clock,
        store,
        journal,
        authority,
    }
}

fn proposal(names: &[&str]) -> Vec<ProposedFile> {
    names
        .iter()
        .map(|text| ProposedFile {
            name: name(text),
            declared_size_bytes: None,
            declared_content: None,
        })
        .collect()
}

struct Prepared {
    manifest: FrozenManifest,
    snapshot: DestinationSnapshot,
    review: Review,
    authorization: PromotionAuthorization,
}

impl Fixture {
    fn paths(&self) -> PromotionPaths<'_> {
        PromotionPaths {
            source_root: &self.source,
            destination_root: &self.destination,
            backup_root: &self.backups,
        }
    }

    /// Freezes, validates, observes, reviews and authorizes `names`, acknowledging every
    /// flag the review raised.
    fn prepare(&self, names: &[&str]) -> Prepared {
        let manifest = freeze(&self.source, &proposal(names), provenance(), &policy()).unwrap();
        validate_manifest(&manifest, &policy()).unwrap();
        let snapshot = observe_destination(&self.destination, &manifest).unwrap();
        let review = review(&manifest, &snapshot).unwrap();
        let authorization = authorize(
            &review,
            review.flagged(),
            OperationId::new("op-approval").unwrap(),
            &self.clock,
            session(1),
            Duration::from_secs(600),
        )
        .unwrap();
        Prepared {
            manifest,
            snapshot,
            review,
            authorization,
        }
    }

    fn apply(&mut self, prepared: &Prepared) -> Result<PromotionReceipt, PromotionRefusal> {
        let paths = PromotionPaths {
            source_root: &self.source,
            destination_root: &self.destination,
            backup_root: &self.backups,
        };
        let mut audit = JournalPromotionAudit::new(
            &mut self.journal,
            &mut self.authority,
            OperationId::new("op-promotion").unwrap(),
        );
        apply(
            &paths,
            &prepared.manifest,
            &prepared.review,
            &prepared.snapshot,
            &prepared.authorization,
            &policy(),
            &mut audit,
            &self.clock,
            session(1),
        )
    }

    fn audit_records(&self) -> usize {
        self.store.records.borrow().len()
    }
}

/// Every file beneath `root`, by relative path, with its bytes.
fn tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut files = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else {
                let relative = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                files.insert(relative, fs::read(&path).unwrap());
            }
        }
    }
    files
}

fn seeded() -> Fixture {
    let fixture = fixture();
    write(&fixture.destination, "src/lib.rs", b"pub fn old() {}\n");
    write(&fixture.destination, "README.md", b"user notes\n");
    write(&fixture.source, "src/lib.rs", b"pub fn new() {}\n");
    write(&fixture.source, "src/extra/new.rs", b"pub fn added() {}\n");
    fixture
}

#[test]
fn an_unchanged_tree_promotes_with_an_audit_receipt_and_kept_originals() {
    let mut fixture = seeded();
    let prepared = fixture.prepare(&["src/lib.rs", "src/extra/new.rs"]);
    assert_eq!(prepared.manifest.entries().len(), 2);
    assert!(prepared.review.flagged().is_empty());
    let changes: Vec<&ChangeKind> = prepared
        .review
        .changes()
        .iter()
        .map(|c| &c.change)
        .collect();
    assert_eq!(changes[0], &ChangeKind::Add);
    assert_eq!(
        changes[1],
        &ChangeKind::Modify {
            from: ContentKey::of(b"pub fn old() {}\n"),
            from_size_bytes: 16,
            from_kind: FileKind::Regular
        }
    );
    let receipt = fixture.apply(&prepared).unwrap();
    assert_eq!(receipt.manifest, prepared.manifest.digest());
    assert_eq!(receipt.authorization, prepared.authorization.digest());
    assert_eq!(receipt.admission.durability, Durability::Durable);
    assert!(receipt.outcome.is_ok());
    assert_eq!(fixture.audit_records(), 2);
    assert_eq!(
        read(&fixture.destination, "src/lib.rs"),
        b"pub fn new() {}\n"
    );
    assert_eq!(
        read(&fixture.destination, "src/extra/new.rs"),
        b"pub fn added() {}\n"
    );
    assert_eq!(read(&fixture.destination, "README.md"), b"user notes\n");
    let backup = receipt
        .applied
        .iter()
        .find_map(|change| match change {
            AppliedChange::Modified {
                name: changed,
                backup,
            } if changed == &name("src/lib.rs") => Some(backup.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(fs::read(backup).unwrap(), b"pub fn old() {}\n");
    // No staging file is left beside the targets.
    assert_eq!(
        tree(&fixture.destination)
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        vec!["README.md", "src/extra/new.rs", "src/lib.rs"]
    );
}

/// PROVES two new files in one new directory promote together: the first creates the
/// directory and the second finds it, not the absence the snapshot recorded (the staged
/// workspace's acceptance run of 31 October 2026 had such a promotion rolled back as
/// "changed after review").
#[test]
fn new_files_in_one_new_directory_promote_together() {
    let mut fixture = fixture();
    write(&fixture.source, "docs/new/a.md", b"a\n");
    write(&fixture.source, "docs/new/b.md", b"b\n");
    write(&fixture.source, "docs/new/deeper/c.md", b"c\n");
    let prepared = fixture.prepare(&["docs/new/a.md", "docs/new/b.md", "docs/new/deeper/c.md"]);
    let receipt = fixture.apply(&prepared).unwrap();
    assert_eq!(receipt.applied.len(), 3);
    assert_eq!(read(&fixture.destination, "docs/new/a.md"), b"a\n");
    assert_eq!(read(&fixture.destination, "docs/new/b.md"), b"b\n");
    assert_eq!(read(&fixture.destination, "docs/new/deeper/c.md"), b"c\n");
}

#[test]
fn a_source_byte_changed_after_approval_refuses_and_keeps_the_user_files() {
    let mut fixture = seeded();
    let prepared = fixture.prepare(&["src/lib.rs", "src/extra/new.rs"]);
    let before = tree(&fixture.destination);
    write(&fixture.source, "src/lib.rs", b"pub fn new() {}\r");
    assert_eq!(
        fixture.apply(&prepared),
        Err(PromotionRefusal::SourceChanged {
            name: name("src/lib.rs")
        })
    );
    assert_eq!(tree(&fixture.destination), before);
    assert_eq!(fixture.audit_records(), 0);
    // A removed source is a change too.
    fs::remove_file(fixture.source.join("src/extra/new.rs")).unwrap();
    write(&fixture.source, "src/lib.rs", b"pub fn new() {}\n");
    assert_eq!(
        fixture.apply(&prepared),
        Err(PromotionRefusal::SourceChanged {
            name: name("src/extra/new.rs")
        })
    );
    assert_eq!(tree(&fixture.destination), before);
}

#[test]
fn a_destination_precondition_changed_after_review_refuses_and_keeps_the_user_edit() {
    let mut fixture = seeded();
    let prepared = fixture.prepare(&["src/lib.rs", "src/extra/new.rs"]);
    write(
        &fixture.destination,
        "src/lib.rs",
        b"pub fn edited_by_user() {}\n",
    );
    assert_eq!(
        fixture.apply(&prepared),
        Err(PromotionRefusal::DestinationChanged {
            name: name("src/lib.rs")
        })
    );
    assert_eq!(
        read(&fixture.destination, "src/lib.rs"),
        b"pub fn edited_by_user() {}\n"
    );
    assert!(!fixture.destination.join("src/extra").exists());
    assert_eq!(fixture.audit_records(), 0);
}

#[test]
fn a_target_that_appears_after_review_refuses_and_is_kept() {
    let mut fixture = seeded();
    let prepared = fixture.prepare(&["src/lib.rs", "src/extra/new.rs"]);
    write(
        &fixture.destination,
        "src/extra/new.rs",
        b"the user's own file\n",
    );
    assert_eq!(
        fixture.apply(&prepared),
        Err(PromotionRefusal::TargetAppeared {
            name: name("src/extra/new.rs")
        })
    );
    assert_eq!(
        read(&fixture.destination, "src/extra/new.rs"),
        b"the user's own file\n"
    );
    assert_eq!(
        read(&fixture.destination, "src/lib.rs"),
        b"pub fn old() {}\n"
    );
}

#[test]
fn a_parent_directory_that_appears_is_a_changed_precondition() {
    let mut fixture = seeded();
    let prepared = fixture.prepare(&["src/extra/new.rs"]);
    assert_eq!(
        prepared.snapshot.state(&name("src/extra/new.rs")),
        Some(&DestinationState::Absent {
            missing_components: 2
        })
    );
    fs::create_dir(fixture.destination.join("src/extra")).unwrap();
    assert_eq!(
        fixture.apply(&prepared),
        Err(PromotionRefusal::DestinationChanged {
            name: name("src/extra/new.rs")
        })
    );
}

/// An audit port that lets a test race the destination between admission and commit.
struct RacingAudit<'a> {
    destination: &'a Path,
    outcomes: Vec<bool>,
}

impl PromotionAudit for RacingAudit<'_> {
    fn admit(&mut self, _fields: Vec<Field>) -> Result<AuditReceipt, AuditRefusal> {
        write(self.destination, "src/b.rs", b"raced in by the user\n");
        Ok(AuditReceipt {
            sequence: EventSequence::FIRST,
            digest: digest("yougori/test/receipt/v1", &[b"admit"]),
            durability: Durability::Durable,
        })
    }

    fn record_outcome(
        &mut self,
        applied: bool,
        _fields: Vec<Field>,
    ) -> Result<AuditReceipt, AuditRefusal> {
        self.outcomes.push(applied);
        Ok(AuditReceipt {
            sequence: EventSequence::FIRST,
            digest: digest("yougori/test/receipt/v1", &[b"outcome"]),
            durability: Durability::Durable,
        })
    }
}

#[test]
fn a_failure_part_way_undoes_the_applied_files_and_preserves_the_raced_one() {
    let fixture = fixture();
    write(&fixture.destination, "src/a.rs", b"a original\n");
    write(&fixture.destination, "src/b.rs", b"b original\n");
    write(&fixture.source, "src/a.rs", b"a promoted\n");
    write(&fixture.source, "src/b.rs", b"b promoted\n");
    let prepared = fixture.prepare(&["src/a.rs", "src/b.rs"]);
    let mut audit = RacingAudit {
        destination: &fixture.destination,
        outcomes: Vec::new(),
    };
    let result = apply(
        &fixture.paths(),
        &prepared.manifest,
        &prepared.review,
        &prepared.snapshot,
        &prepared.authorization,
        &policy(),
        &mut audit,
        &fixture.clock,
        session(1),
    );
    assert_eq!(
        result,
        Err(PromotionRefusal::RolledBack {
            cause: Box::new(PromotionRefusal::DestinationChanged {
                name: name("src/b.rs")
            }),
            restored: vec![name("src/a.rs")],
            unrestored: vec![],
        })
    );
    assert_eq!(audit.outcomes, vec![false]);
    assert_eq!(read(&fixture.destination, "src/a.rs"), b"a original\n");
    assert_eq!(
        read(&fixture.destination, "src/b.rs"),
        b"raced in by the user\n"
    );
    assert_eq!(
        tree(&fixture.destination)
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        vec!["src/a.rs", "src/b.rs"]
    );
}

#[test]
fn a_refused_audit_record_stops_the_promotion() {
    let mut fixture = seeded();
    let prepared = fixture.prepare(&["src/lib.rs"]);
    *fixture.store.refuse.borrow_mut() = true;
    assert!(matches!(
        fixture.apply(&prepared),
        Err(PromotionRefusal::AuditRefused { .. })
    ));
    assert_eq!(
        read(&fixture.destination, "src/lib.rs"),
        b"pub fn old() {}\n"
    );
}

#[test]
fn executable_configuration_and_hook_changes_are_flagged() {
    let fixture = fixture();
    let cases: [(&str, &[ReviewFlag]); 11] = [
        (".git/hooks/pre-commit", &[ReviewFlag::GitHook]),
        (".git/config", &[ReviewFlag::GitConfiguration]),
        (".husky/pre-push", &[ReviewFlag::GitHook]),
        (".github/workflows/ci.yml", &[ReviewFlag::CiWorkflow]),
        (".bashrc", &[ReviewFlag::ShellInit]),
        ("build.rs", &[ReviewFlag::BuildScript]),
        ("Makefile", &[ReviewFlag::BuildScript]),
        ("package.json", &[ReviewFlag::PackageLifecycle]),
        ("run.bat", &[ReviewFlag::ExecutableType]),
        ("deploy.sh", &[ReviewFlag::ExecutableType]),
        (".vscode/tasks.json", &[ReviewFlag::ToolConfiguration]),
    ];
    for (text, _) in &cases {
        write(&fixture.source, text, b"echo hi\n");
    }
    write(&fixture.source, "src/main.rs", b"fn main() {}\n");
    let mut names: Vec<&str> = cases.iter().map(|(text, _)| *text).collect();
    names.push("src/main.rs");
    let manifest = freeze(&fixture.source, &proposal(&names), provenance(), &policy()).unwrap();
    let snapshot = observe_destination(&fixture.destination, &manifest).unwrap();
    let reviewed = review(&manifest, &snapshot).unwrap();
    let flagged = reviewed.flagged();
    for (text, flags) in cases {
        assert_eq!(
            flagged.get(&name(text)),
            Some(&flags.iter().copied().collect::<BTreeSet<_>>()),
            "{text}"
        );
    }
    assert!(!flagged.contains_key(&name("src/main.rs")));
    // A differently cased spelling, which a case-insensitive volume treats as the same
    // directory, is flagged too.
    let cased = self::fixture();
    write(
        &cased.source,
        ".GitHub/Workflows/Release.yml",
        b"on: push
",
    );
    let manifest = freeze(
        &cased.source,
        &proposal(&[".GitHub/Workflows/Release.yml"]),
        provenance(),
        &policy(),
    )
    .unwrap();
    let snapshot = observe_destination(&cased.destination, &manifest).unwrap();
    assert_eq!(
        review(&manifest, &snapshot)
            .unwrap()
            .flagged()
            .get(&name(".GitHub/Workflows/Release.yml")),
        Some(&BTreeSet::from([ReviewFlag::CiWorkflow]))
    );
}

#[cfg(unix)]
#[test]
fn an_added_execute_bit_is_flagged_and_needs_policy() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = fixture();
    write(&fixture.source, "src/tool", b"#!/bin/sh\n");
    fs::set_permissions(
        fixture.source.join("src/tool"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let manifest = freeze(
        &fixture.source,
        &proposal(&["src/tool"]),
        provenance(),
        &policy(),
    )
    .unwrap();
    assert_eq!(manifest.entries()[0].kind, FileKind::Executable);
    assert_eq!(
        validate_manifest(&manifest, &policy()),
        Err(PromotionRefusal::KindNotAllowed {
            name: name("src/tool"),
            kind: FileKind::Executable
        })
    );
    let snapshot = observe_destination(&fixture.destination, &manifest).unwrap();
    let reviewed = review(&manifest, &snapshot).unwrap();
    assert_eq!(
        reviewed.flagged().get(&name("src/tool")),
        Some(&BTreeSet::from([ReviewFlag::ExecutableBit]))
    );
}

#[test]
fn every_flag_must_be_acknowledged_exactly() {
    let fixture = fixture();
    write(&fixture.source, ".git/hooks/post-checkout", b"#!/bin/sh\n");
    write(&fixture.source, "src/main.rs", b"fn main() {}\n");
    let manifest = freeze(
        &fixture.source,
        &proposal(&[".git/hooks/post-checkout", "src/main.rs"]),
        provenance(),
        &policy(),
    )
    .unwrap();
    let snapshot = observe_destination(&fixture.destination, &manifest).unwrap();
    let reviewed = review(&manifest, &snapshot).unwrap();
    let approve = |acknowledged| {
        authorize(
            &reviewed,
            acknowledged,
            OperationId::new("op-approval").unwrap(),
            &fixture.clock,
            session(1),
            Duration::from_secs(60),
        )
    };
    assert_eq!(
        approve(BTreeMap::new()),
        Err(PromotionRefusal::UnacknowledgedFlags {
            name: name(".git/hooks/post-checkout"),
            flags: vec![ReviewFlag::GitHook]
        })
    );
    let mut extra = reviewed.flagged();
    extra.insert(
        name("src/main.rs"),
        BTreeSet::from([ReviewFlag::BuildScript]),
    );
    assert_eq!(
        approve(extra),
        Err(PromotionRefusal::UnexpectedAcknowledgment {
            name: name("src/main.rs")
        })
    );
    assert!(approve(reviewed.flagged()).is_ok());
}

#[test]
fn review_and_apply_never_run_hooks_or_build_scripts() {
    let mut fixture = fixture();
    let marker = fixture.destination.join("HOOK_RAN");
    let script = format!("#!/bin/sh\ntouch '{}'\n", marker.display());
    write(
        &fixture.source,
        ".git/hooks/post-checkout",
        script.as_bytes(),
    );
    write(
        &fixture.source,
        "build.rs",
        b"fn main() { std::fs::write(\"BUILD_RAN\", \"\").unwrap(); }\n",
    );
    write(&fixture.source, "Makefile", b"all:\n\ttouch MAKE_RAN\n");
    let prepared = fixture.prepare(&[".git/hooks/post-checkout", "build.rs", "Makefile"]);
    assert_eq!(prepared.authorization.acknowledged().len(), 3);
    fixture.apply(&prepared).unwrap();
    assert!(!marker.exists());
    let files = tree(&fixture.destination);
    assert_eq!(
        files.keys().cloned().collect::<Vec<_>>(),
        vec![".git/hooks/post-checkout", "Makefile", "build.rs"]
    );
}

#[test]
fn the_authorization_binds_manifest_review_destination_clock_and_expiry() {
    let mut fixture = seeded();
    let prepared = fixture.prepare(&["src/lib.rs"]);
    let other = fixture.prepare(&["src/extra/new.rs"]);
    let swapped = Prepared {
        authorization: other.authorization.clone(),
        ..fixture.prepare(&["src/lib.rs"])
    };
    assert_eq!(
        fixture.apply(&swapped),
        Err(PromotionRefusal::AuthorizationMismatch { bound: "manifest" })
    );
    let paths = PromotionPaths {
        source_root: &fixture.source,
        destination_root: &fixture.destination,
        backup_root: &fixture.backups,
    };
    let mut audit = JournalPromotionAudit::new(
        &mut fixture.journal,
        &mut fixture.authority,
        OperationId::new("op-promotion").unwrap(),
    );
    let attempt = |audit: &mut dyn PromotionAudit, clock: &Clock, presented| {
        apply(
            &paths,
            &prepared.manifest,
            &prepared.review,
            &prepared.snapshot,
            &prepared.authorization,
            &policy(),
            audit,
            clock,
            presented,
        )
    };
    assert_eq!(
        attempt(&mut audit, &fixture.clock, session(2)),
        Err(PromotionRefusal::AuthorizationOtherClock)
    );
    fixture.clock.advance(Duration::from_secs(600));
    assert_eq!(
        attempt(&mut audit, &fixture.clock, session(1)),
        Err(PromotionRefusal::AuthorizationExpired {
            expired_at: prepared.authorization.expires_at()
        })
    );
}

#[test]
fn another_destination_root_is_refused() {
    let mut fixture = seeded();
    let prepared = fixture.prepare(&["src/lib.rs"]);
    let elsewhere = fixture._dir.path().join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    write(&elsewhere, "src/lib.rs", b"pub fn old() {}\n");
    fixture.destination = elsewhere;
    assert_eq!(
        fixture.apply(&prepared),
        Err(PromotionRefusal::DestinationRootChanged)
    );
}

#[test]
fn backups_never_go_inside_the_trees() {
    let mut fixture = seeded();
    let prepared = fixture.prepare(&["src/lib.rs"]);
    fixture.backups = fixture.destination.join("src");
    assert_eq!(
        fixture.apply(&prepared),
        Err(PromotionRefusal::BackupRootInsideTree)
    );
    fixture.backups = fixture.source.clone();
    assert_eq!(
        fixture.apply(&prepared),
        Err(PromotionRefusal::BackupRootInsideTree)
    );
}

#[test]
fn unchanged_entries_are_left_alone() {
    let mut fixture = fixture();
    write(&fixture.destination, "docs/same.md", b"same\n");
    write(&fixture.source, "docs/same.md", b"same\n");
    let prepared = fixture.prepare(&["docs/same.md"]);
    assert_eq!(prepared.review.changes()[0].change, ChangeKind::Unchanged);
    let receipt = fixture.apply(&prepared).unwrap();
    assert_eq!(
        receipt.applied,
        vec![AppliedChange::Unchanged {
            name: name("docs/same.md")
        }]
    );
    assert_eq!(fs::read_dir(&fixture.backups).unwrap().count(), 0);
}

#[test]
fn targets_that_are_not_regular_files_are_refused() {
    let fixture = fixture();
    write(&fixture.source, "src/x/file.rs", b"x\n");
    write(&fixture.source, "docs/dir", b"x\n");
    fs::create_dir_all(fixture.destination.join("docs/dir")).unwrap();
    write(
        &fixture.destination,
        "src/x",
        b"a file where a directory is needed\n",
    );
    let manifest = freeze(
        &fixture.source,
        &proposal(&["docs/dir"]),
        provenance(),
        &policy(),
    )
    .unwrap();
    let snapshot = observe_destination(&fixture.destination, &manifest).unwrap();
    assert_eq!(
        review(&manifest, &snapshot),
        Err(PromotionRefusal::TargetNotAFile {
            name: name("docs/dir"),
            state: DestinationState::Directory
        })
    );
    let manifest = freeze(
        &fixture.source,
        &proposal(&["src/x/file.rs"]),
        provenance(),
        &policy(),
    )
    .unwrap();
    let snapshot = observe_destination(&fixture.destination, &manifest).unwrap();
    assert_eq!(
        review(&manifest, &snapshot),
        Err(PromotionRefusal::TargetNotAFile {
            name: name("src/x/file.rs"),
            state: DestinationState::Blocked {
                component: 1,
                block: PathBlock::File
            }
        })
    );
}

/// PROVES a case alias in the destination is refused on every volume, as the resolver
/// refuses one (`the_resolver_matches_the_model_on_a_real_tree`): a promotion never makes
/// two names one volume folds into one (the case-sensitive branch this test once had was
/// never run before the Linux run of 31 October 2026, and expected the opposite).
#[test]
fn a_case_alias_in_the_destination_is_refused_on_every_volume() {
    let fixture = fixture();
    write(&fixture.destination, "Docs/guide.md", b"existing\n");
    write(&fixture.source, "docs/guide.md", b"new\n");
    let manifest = freeze(
        &fixture.source,
        &proposal(&["docs/guide.md"]),
        provenance(),
        &policy(),
    )
    .unwrap();
    let snapshot = observe_destination(&fixture.destination, &manifest).unwrap();
    assert_eq!(
        review(&manifest, &snapshot),
        Err(PromotionRefusal::TargetNotAFile {
            name: name("docs/guide.md"),
            state: DestinationState::Blocked {
                component: 0,
                block: PathBlock::CaseAlias
            }
        })
    );
}

#[test]
fn freezing_refuses_forged_declarations_collisions_and_oversize() {
    let fixture = fixture();
    write(&fixture.source, "src/a.rs", b"0123456789");
    write(&fixture.source, "src/big.rs", &[b'x'; 1_025]);
    let mut declared = proposal(&["src/a.rs"]);
    declared[0].declared_size_bytes = Some(9);
    assert_eq!(
        freeze(&fixture.source, &declared, provenance(), &policy()),
        Err(PromotionRefusal::DeclaredSizeMismatch {
            name: name("src/a.rs"),
            declared_bytes: 9,
            actual_bytes: 10
        })
    );
    let mut forged = proposal(&["src/a.rs"]);
    forged[0].declared_content = Some(ContentKey::of(b"something else"));
    assert_eq!(
        freeze(&fixture.source, &forged, provenance(), &policy()),
        Err(PromotionRefusal::DeclaredContentMismatch {
            name: name("src/a.rs")
        })
    );
    let mut honest = proposal(&["src/a.rs"]);
    honest[0].declared_size_bytes = Some(10);
    honest[0].declared_content = Some(ContentKey::of(b"0123456789"));
    assert!(freeze(&fixture.source, &honest, provenance(), &policy()).is_ok());
    assert!(matches!(
        freeze(
            &fixture.source,
            &proposal(&["src/a.rs", "src/A.rs"]),
            provenance(),
            &policy()
        ),
        Err(PromotionRefusal::Collision { .. })
    ));
    assert_eq!(
        freeze(
            &fixture.source,
            &proposal(&["src/big.rs"]),
            provenance(),
            &policy()
        ),
        Err(PromotionRefusal::FileTooLarge {
            name: name("src/big.rs"),
            size_bytes: 1_025,
            limit: 1_024
        })
    );
    assert_eq!(
        freeze(
            &fixture.source,
            &proposal(&["src/missing.rs"]),
            provenance(),
            &policy()
        ),
        Err(PromotionRefusal::SourceMissing {
            name: name("src/missing.rs")
        })
    );
    assert_eq!(
        freeze(
            &fixture.source,
            &proposal(&["src"]),
            provenance(),
            &policy()
        ),
        Err(PromotionRefusal::SourceNotRegularFile { name: name("src") })
    );
    assert_eq!(
        freeze(
            &fixture.source,
            &proposal(&["src/a.rs/x"]),
            provenance(),
            &policy()
        ),
        Err(PromotionRefusal::SourceBlocked {
            name: name("src/a.rs/x"),
            component: 1,
            block: PathBlock::File
        })
    );
    assert_eq!(
        freeze(&fixture.source, &[], provenance(), &policy()),
        Err(PromotionRefusal::NoFiles)
    );
    let mut small = policy();
    small.max_entries = 1;
    assert_eq!(
        freeze(
            &fixture.source,
            &proposal(&["src/a.rs", "src/b.rs"]),
            provenance(),
            &small
        ),
        Err(PromotionRefusal::TooManyEntries {
            entries: 2,
            limit: 1
        })
    );
    small = policy();
    small.max_total_bytes = 15;
    write(&fixture.source, "src/b.rs", b"0123456789");
    assert_eq!(
        freeze(
            &fixture.source,
            &proposal(&["src/a.rs", "src/b.rs"]),
            provenance(),
            &small
        ),
        Err(PromotionRefusal::TotalTooLarge {
            total_bytes: 20,
            limit: 15
        })
    );
}

#[test]
fn validation_refuses_paths_provenance_and_sizes_outside_the_policy() {
    let fixture = fixture();
    write(&fixture.source, "src/a.rs", b"a");
    write(&fixture.source, "SRC/b.rs", b"b");
    write(&fixture.source, "secrets/key", b"k");
    let manifest = freeze(
        &fixture.source,
        &proposal(&["secrets/key"]),
        provenance(),
        &policy(),
    )
    .unwrap();
    assert_eq!(
        validate_manifest(&manifest, &policy()),
        Err(PromotionRefusal::PathNotAllowed {
            name: name("secrets/key")
        })
    );
    let differently_cased = freeze(
        &fixture.source,
        &proposal(&["SRC/b.rs"]),
        provenance(),
        &policy(),
    );
    if let Ok(manifest) = differently_cased {
        assert_eq!(
            validate_manifest(&manifest, &policy()),
            Err(PromotionRefusal::PathNotAllowed {
                name: name("SRC/b.rs")
            })
        );
    }
    let manifest = freeze(
        &fixture.source,
        &proposal(&["src/a.rs"]),
        provenance(),
        &policy(),
    )
    .unwrap();
    let mut elsewhere = policy();
    elsewhere.expected.execution = execution("exe-other");
    assert_eq!(
        validate_manifest(&manifest, &elsewhere),
        Err(PromotionRefusal::ProvenanceMismatch)
    );
    let mut nothing = policy();
    nothing.allowed_prefixes.clear();
    assert_eq!(
        validate_manifest(&manifest, &nothing),
        Err(PromotionRefusal::PathNotAllowed {
            name: name("src/a.rs")
        })
    );
}

#[test]
fn records_read_back_only_with_matching_digests() {
    let fixture = seeded();
    let prepared = fixture.prepare(&["src/lib.rs", "src/extra/new.rs"]);
    let manifest_text = serde_json::to_string(&prepared.manifest).unwrap();
    assert_eq!(
        serde_json::from_str::<FrozenManifest>(&manifest_text).unwrap(),
        prepared.manifest
    );
    let tampered = manifest_text.replace("\"size_bytes\":16", "\"size_bytes\":17");
    assert_ne!(tampered, manifest_text);
    assert!(serde_json::from_str::<FrozenManifest>(&tampered).is_err());
    let snapshot_text = serde_json::to_string(&prepared.snapshot).unwrap();
    assert_eq!(
        serde_json::from_str::<DestinationSnapshot>(&snapshot_text).unwrap(),
        prepared.snapshot
    );
    let absent = snapshot_text.replace("\"missing_components\":2", "\"missing_components\":1");
    assert!(serde_json::from_str::<DestinationSnapshot>(&absent).is_err());
    let review_text = serde_json::to_string(&prepared.review).unwrap();
    assert_eq!(
        serde_json::from_str::<Review>(&review_text).unwrap(),
        prepared.review
    );
    let unflagged = review_text.replace("\"change\":\"add\"", "\"change\":\"unchanged\"");
    assert!(serde_json::from_str::<Review>(&unflagged).is_err());
    let authorization_text = serde_json::to_string(&prepared.authorization).unwrap();
    assert_eq!(
        serde_json::from_str::<PromotionAuthorization>(&authorization_text).unwrap(),
        prepared.authorization
    );
    let extended =
        authorization_text.replace("\"expires_at\":601000000000", "\"expires_at\":999000000000");
    assert_ne!(extended, authorization_text);
    assert!(serde_json::from_str::<PromotionAuthorization>(&extended).is_err());
    let unknown = serde_json::json!({"state": "directory", "extra": 1});
    assert!(serde_json::from_value::<DestinationState>(unknown).is_err());
    let unknown = serde_json::json!({"change": "add", "extra": 1});
    assert!(serde_json::from_value::<ChangeKind>(unknown).is_err());
}

/// Bytes that differ along their whole length, so a copy that drops or repeats a chunk
/// differs too.
fn large_bytes(length: usize, seed: u8) -> Vec<u8> {
    (0..length).map(|at| (at as u64).wrapping_mul(2_654_435_761).to_le_bytes()[0] ^ seed).collect()
}

/// PROVES files past the old whole-file bounds promote exactly: a 9 MiB added file and a
/// 12 MiB modified one are hashed and copied in bounded chunks, land under their names only
/// as reviewed (the original kept in the backup), and leave no staging file behind; a source
/// that differs from its review by one byte refuses before anything is written.
#[test]
fn files_larger_than_the_old_bounds_promote_exactly_in_bounded_chunks() {
    let mut fixture = fixture();
    let added = large_bytes(9 * 1024 * 1024 + 3, 7);
    let original = large_bytes(12 * 1024 * 1024, 1);
    let modified = large_bytes(12 * 1024 * 1024 + 17, 2);
    write(&fixture.destination, "src/model.bin", &original);
    write(&fixture.source, "src/model.bin", &modified);
    write(&fixture.source, "src/data/big.bin", &added);
    let large = PromotionPolicy { max_file_bytes: 64 * 1024 * 1024, max_total_bytes: 128 * 1024 * 1024, ..policy() };
    let names = ["src/data/big.bin", "src/model.bin"];
    let manifest = freeze(&fixture.source, &proposal(&names), provenance(), &large).unwrap();
    assert_eq!(manifest.entries().iter().map(|entry| entry.size_bytes).collect::<Vec<_>>(), vec![added.len() as u64, modified.len() as u64]);
    assert_eq!(manifest.entries()[0].content, ContentKey::of(&added));
    validate_manifest(&manifest, &large).unwrap();
    let snapshot = observe_destination(&fixture.destination, &manifest).unwrap();
    let reviewed = review(&manifest, &snapshot).unwrap();
    let authorization = authorize(&reviewed, reviewed.flagged(), OperationId::new("op-approval").unwrap(), &fixture.clock, session(1), Duration::from_secs(600)).unwrap();
    let apply_with = |fixture: &mut Fixture| {
        let paths = PromotionPaths { source_root: &fixture.source, destination_root: &fixture.destination, backup_root: &fixture.backups };
        let mut audit = JournalPromotionAudit::new(&mut fixture.journal, &mut fixture.authority, OperationId::new("op-promotion").unwrap());
        apply(&paths, &manifest, &reviewed, &snapshot, &authorization, &large, &mut audit, &fixture.clock, session(1))
    };
    // One byte of the large source changed after the review: refused, nothing written.
    let mut tampered = modified.clone();
    tampered[5 * 1024 * 1024] ^= 0xff;
    write(&fixture.source, "src/model.bin", &tampered);
    let before = tree(&fixture.destination);
    assert_eq!(apply_with(&mut fixture).map(|_| ()), Err(PromotionRefusal::SourceChanged { name: name("src/model.bin") }));
    assert_eq!(tree(&fixture.destination), before);
    write(&fixture.source, "src/model.bin", &modified);
    let receipt = apply_with(&mut fixture).unwrap();
    assert_eq!(receipt.applied.len(), 2);
    assert_eq!(read(&fixture.destination, "src/data/big.bin"), added);
    assert_eq!(read(&fixture.destination, "src/model.bin"), modified);
    let kept = tree(&fixture.backups);
    assert!(kept.values().any(|bytes| *bytes == original), "the original is kept in the backup");
    assert!(tree(&fixture.destination).keys().all(|name| !name.contains(".yougori-")), "no staging file is left");
}
