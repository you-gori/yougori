//! The host file service over one grant on real temporary trees (VM part §5.1: "A grant
//! binds a host-selected root handle, permitted operations, trust scope, expiry and quota";
//! the three modes; VM-W14; M12).
//!
//! Directory links are junctions on Windows and symlinks on Unix ([`dir_link`]).

use std::collections::BTreeSet;
use std::fs;

use super::fakes::{at, session};
use super::root_tests::{
    dir_link, host, name, names_in, present, snapshot, tree, write, Tree, DIR_LINK, SECRET,
};
use super::*;
use crate::foundation::ids::{digest, ExecutionCategory, TrustScope};

const ALL: [FileOperation; 7] = [
    FileOperation::Read,
    FileOperation::List,
    FileOperation::Create,
    FileOperation::Write,
    FileOperation::Delete,
    FileOperation::Rename,
    FileOperation::SetExecutable,
];

/// A service and the tree it serves; the service is dropped first, closing its handles
/// before the temporary directory goes.
struct Served {
    service: FileService,
    tree: Tree,
}

fn scope() -> TrustScope {
    TrustScope::named(ExecutionCategory::VmSandbox, "sandbox-a")
}

fn context() -> RequestContext {
    RequestContext {
        scope: scope(),
        now: at(1),
        session: session(1),
    }
}

fn quota(max_total_bytes: u64, max_entries: u64, max_file_bytes: u64) -> FileQuota {
    FileQuota {
        max_total_bytes,
        max_entries,
        max_file_bytes,
    }
}

fn roomy() -> FileQuota {
    quota(10_000, 100, 1_000)
}

fn read_only() -> GrantMode {
    GrantMode::ReadOnlySnapshot {
        snapshot: digest("yougori/test/snapshot/v1", &[b"v1"]),
    }
}

fn live() -> GrantMode {
    GrantMode::LiveWorkspace {
        acknowledgment: DisclosureAcknowledgment::of_current_statement(),
    }
}

fn grant_for(
    root: RootHandle,
    mode: GrantMode,
    operations: &[FileOperation],
    quota: FileQuota,
) -> FileGrant {
    FileGrant::new(
        root,
        mode,
        operations.iter().copied().collect::<BTreeSet<_>>(),
        scope(),
        session(1),
        at(100),
        quota,
    )
    .unwrap()
}

fn serve(tree: Tree, mode: GrantMode, operations: &[FileOperation], quota: FileQuota) -> Served {
    let root = GrantedRoot::open(&tree.root).unwrap();
    let grant = grant_for(root.handle(), mode, operations, quota);
    let service = FileService::new(grant, root).unwrap();
    Served { service, tree }
}

fn output(tree: Tree, quota: FileQuota) -> Served {
    serve(tree, GrantMode::QuarantineOutput, &ALL, quota)
}

fn usage(total_bytes: u64, entries: u64) -> Option<QuotaUsage> {
    Some(QuotaUsage {
        total_bytes,
        entries,
    })
}

fn grant_refusal(refusal: GrantRefusal) -> ServiceRefusal {
    ServiceRefusal::Grant { refusal }
}

fn not_granted(operation: FileOperation) -> ServiceRefusal {
    grant_refusal(GrantRefusal::OperationNotGranted { operation })
}

fn resolve_refusal(refusal: ResolveRefusal) -> ServiceRefusal {
    ServiceRefusal::Resolve { refusal }
}

fn link_refused(at: &str, link: LinkKind) -> ServiceRefusal {
    resolve_refusal(ResolveRefusal::LinkRefused { at: name(at), link })
}

fn not_found(at: &str) -> ServiceRefusal {
    resolve_refusal(ResolveRefusal::NotFound { at: name(at) })
}

fn already_exists(text: &str) -> ServiceRefusal {
    ServiceRefusal::AlreadyExists { name: name(text) }
}

fn listed_file(text: &str, size_bytes: u64) -> ListedEntry {
    ListedEntry {
        name: name(text),
        kind: ListedKind::File {
            size_bytes,
            executable: false,
        },
    }
}

fn listed(text: &str, kind: ListedKind) -> ListedEntry {
    ListedEntry {
        name: name(text),
        kind,
    }
}

/// Every refusal a service gives `context` for each operation, on names that exist.
fn refusals_for(served: &mut Served, context: &RequestContext) -> Vec<ServiceRefusal> {
    let service = &mut served.service;
    vec![
        service.read(context, &name("a.txt"), 1_000).unwrap_err(),
        service.list(context, None).unwrap_err(),
        service.list(context, Some(&name("dir"))).unwrap_err(),
        service
            .create(context, &name("new.txt"), b"new")
            .unwrap_err(),
        service
            .write(context, &name("a.txt"), b"rewritten")
            .unwrap_err(),
        service.delete(context, &name("a.txt")).unwrap_err(),
        service
            .rename(context, &name("a.txt"), &name("b.txt"))
            .unwrap_err(),
        service
            .set_executable(context, &name("a.txt"), true)
            .unwrap_err(),
    ]
}

#[test]
fn a_grant_for_another_root_is_refused() {
    let tree = tree();
    let root = GrantedRoot::open(&tree.root).unwrap();
    let elsewhere = GrantedRoot::open(&tree.outside).unwrap();
    let grant = grant_for(
        elsewhere.handle(),
        GrantMode::QuarantineOutput,
        &ALL,
        roomy(),
    );
    assert_eq!(
        FileService::new(grant, root).unwrap_err(),
        ServiceRefusal::RootMismatch
    );
    let made_up = grant_for(
        RootHandle::from_host(digest("yougori/test/root/v1", &[b"workspace"])),
        GrantMode::QuarantineOutput,
        &ALL,
        roomy(),
    );
    assert_eq!(
        FileService::new(made_up, GrantedRoot::open(&tree.root).unwrap()).unwrap_err(),
        ServiceRefusal::RootMismatch
    );
    // A grant for the directory once at this path does not serve what is there now.
    let before = GrantedRoot::open(&tree.root).unwrap().handle();
    fs::rename(&tree.root, tree.dir.path().join("root-moved")).unwrap();
    fs::create_dir(&tree.root).unwrap();
    let stale = grant_for(before, GrantMode::QuarantineOutput, &ALL, roomy());
    assert_eq!(
        FileService::new(stale, GrantedRoot::open(&tree.root).unwrap()).unwrap_err(),
        ServiceRefusal::RootMismatch
    );
    let fresh = GrantedRoot::open(&tree.root).unwrap();
    let grant = grant_for(fresh.handle(), GrantMode::QuarantineOutput, &ALL, roomy());
    assert!(FileService::new(grant, fresh).is_ok());
}

#[test]
fn a_read_only_snapshot_reads_and_lists_but_never_changes_the_tree() {
    let tree = tree();
    write(&tree.root, "a.txt", b"alpha");
    write(&tree.root, "dir/b.txt", b"beta");
    assert_eq!(
        FileGrant::new(
            RootHandle::from_host(digest("yougori/test/root/v1", &[b"x"])),
            read_only(),
            BTreeSet::from([FileOperation::Read, FileOperation::Write]),
            scope(),
            session(1),
            at(100),
            roomy(),
        ),
        Err(GrantProblem::OperationOutsideMode {
            operation: FileOperation::Write
        })
    );
    let mut served = serve(
        tree,
        read_only(),
        &[FileOperation::Read, FileOperation::List],
        roomy(),
    );
    let before = snapshot(&served.tree.root);
    let context = context();
    let service = &mut served.service;
    assert_eq!(service.host_state_claim(), HostStateClaim::InputImmutable);
    assert_eq!(
        service.read(&context, &name("a.txt"), 1_000),
        Ok(b"alpha".to_vec())
    );
    assert_eq!(
        service.read(&context, &name("dir/b.txt"), 1_000),
        Ok(b"beta".to_vec())
    );
    assert_eq!(
        service.list(&context, None).unwrap().entries,
        [
            listed_file("a.txt", 5),
            listed("dir", ListedKind::Directory)
        ]
    );
    assert_eq!(
        service.list(&context, Some(&name("dir"))).unwrap().entries,
        [listed_file("b.txt", 4)]
    );
    assert_eq!(
        service.create(&context, &name("new.txt"), b"new"),
        Err(not_granted(FileOperation::Create))
    );
    assert_eq!(
        service.write(&context, &name("a.txt"), b"changed"),
        Err(not_granted(FileOperation::Write))
    );
    assert_eq!(
        service.delete(&context, &name("a.txt")),
        Err(not_granted(FileOperation::Delete))
    );
    assert_eq!(
        service.delete(&context, &name("dir/b.txt")),
        Err(not_granted(FileOperation::Delete))
    );
    assert_eq!(
        service.rename(&context, &name("a.txt"), &name("z.txt")),
        Err(not_granted(FileOperation::Rename))
    );
    assert_eq!(
        service.set_executable(&context, &name("a.txt"), true),
        Err(not_granted(FileOperation::SetExecutable))
    );
    assert_eq!(snapshot(&served.tree.root), before);
}

#[test]
fn reads_return_exact_bytes_within_the_read_limit() {
    let tree = tree();
    write(&tree.root, "a.txt", b"abc");
    write(&tree.root, "dir/empty.txt", b"");
    let served = output(tree, roomy());
    let context = context();
    let service = &served.service;
    assert_eq!(
        service.read(&context, &name("a.txt"), 3),
        Ok(b"abc".to_vec())
    );
    assert_eq!(
        service.read(&context, &name("a.txt"), 2),
        Err(ServiceRefusal::ReadTooLarge {
            name: name("a.txt"),
            size_bytes: 3,
            limit: 2
        })
    );
    assert_eq!(
        service.read(&context, &name("dir/empty.txt"), 0),
        Ok(Vec::new())
    );
    assert_eq!(
        service.read(&context, &name("missing.txt"), 10),
        Err(not_found("missing.txt"))
    );
    assert_eq!(
        service.read(&context, &name("dir"), 10),
        Err(ServiceRefusal::NotAFile { name: name("dir") })
    );
    assert_eq!(
        service.read(&context, &name("a.txt/x"), 10),
        Err(resolve_refusal(ResolveRefusal::NotADirectory {
            at: name("a.txt")
        }))
    );
}

#[test]
fn a_create_beyond_the_entry_quota_is_refused() {
    let tree = tree();
    write(&tree.root, "a.txt", b"a");
    let mut served = output(tree, quota(1_000, 3, 100));
    let context = context();
    assert_eq!(served.service.usage(), usage(1, 1));
    served
        .service
        .create(&context, &name("b.txt"), b"b")
        .unwrap();
    served
        .service
        .create(&context, &name("c.txt"), b"c")
        .unwrap();
    assert_eq!(served.service.usage(), usage(3, 3));
    assert_eq!(
        served.service.create(&context, &name("d.txt"), b"d"),
        Err(grant_refusal(GrantRefusal::EntryQuotaExceeded {
            max_entries: 3
        }))
    );
    assert!(!present(&served.tree.root.join("d.txt")));
    assert_eq!(served.service.usage(), usage(3, 3));
    // A write adds no entry, so a full root can still be rewritten.
    served
        .service
        .write(&context, &name("a.txt"), b"aa")
        .unwrap();
    assert_eq!(served.service.usage(), usage(4, 3));
    // Deleting frees an entry.
    served.service.delete(&context, &name("b.txt")).unwrap();
    served
        .service
        .create(&context, &name("d.txt"), b"d")
        .unwrap();
    assert_eq!(served.service.usage(), usage(4, 3));
}

#[test]
fn a_file_beyond_the_file_size_quota_is_refused() {
    let tree = tree();
    write(&tree.root, "a.txt", b"a");
    let mut served = output(tree, quota(1_000, 10, 10));
    let context = context();
    assert_eq!(
        served
            .service
            .create(&context, &name("big.txt"), &[b'x'; 11]),
        Err(grant_refusal(GrantRefusal::FileTooLarge {
            resulting_file_bytes: 11,
            max_file_bytes: 10
        }))
    );
    assert!(!present(&served.tree.root.join("big.txt")));
    served
        .service
        .create(&context, &name("full.txt"), &[b'x'; 10])
        .unwrap();
    assert_eq!(
        served.service.write(&context, &name("a.txt"), &[b'y'; 11]),
        Err(grant_refusal(GrantRefusal::FileTooLarge {
            resulting_file_bytes: 11,
            max_file_bytes: 10
        }))
    );
    assert_eq!(fs::read(served.tree.root.join("a.txt")).unwrap(), b"a");
    assert_eq!(served.service.usage(), usage(11, 2));
}

#[test]
fn growth_beyond_the_total_quota_is_refused() {
    let tree = tree();
    write(&tree.root, "a.txt", &[b'a'; 10]);
    let mut served = output(tree, quota(30, 10, 25));
    let context = context();
    assert_eq!(
        served.service.create(&context, &name("b.txt"), &[b'b'; 21]),
        Err(grant_refusal(GrantRefusal::TotalQuotaExceeded {
            resulting_total_bytes: 31,
            max_total_bytes: 30
        }))
    );
    served
        .service
        .create(&context, &name("b.txt"), &[b'b'; 20])
        .unwrap();
    assert_eq!(served.service.usage(), usage(30, 2));
    assert_eq!(
        served.service.write(&context, &name("a.txt"), &[b'a'; 11]),
        Err(grant_refusal(GrantRefusal::TotalQuotaExceeded {
            resulting_total_bytes: 31,
            max_total_bytes: 30
        }))
    );
    assert_eq!(
        fs::read(served.tree.root.join("a.txt")).unwrap(),
        [b'a'; 10]
    );
    // Shrinking makes room.
    served
        .service
        .write(&context, &name("a.txt"), &[b'a'; 5])
        .unwrap();
    served
        .service
        .create(&context, &name("c.txt"), &[b'c'; 5])
        .unwrap();
    assert_eq!(served.service.usage(), usage(30, 3));
    assert_eq!(
        served.service.create(&context, &name("d.txt"), b"d"),
        Err(grant_refusal(GrantRefusal::TotalQuotaExceeded {
            resulting_total_bytes: 31,
            max_total_bytes: 30
        }))
    );
}

#[test]
fn usage_tracks_creates_writes_deletes_and_renames_exactly() {
    let tree = tree();
    write(&tree.root, "a.txt", &[b'a'; 10]);
    write(&tree.root, "dir/b.txt", &[b'b'; 5]);
    let mut served = output(tree, roomy());
    let context = context();
    let check = |served: &mut Served, expected: Option<QuotaUsage>| {
        assert_eq!(served.service.usage(), expected);
        assert_eq!(served.service.recount(), Ok(expected));
    };
    check(&mut served, usage(15, 3));
    served
        .service
        .create(&context, &name("dir/c.txt"), &[b'c'; 20])
        .unwrap();
    check(&mut served, usage(35, 4));
    served
        .service
        .write(&context, &name("a.txt"), &[b'a'; 4])
        .unwrap();
    check(&mut served, usage(29, 4));
    served
        .service
        .write(&context, &name("dir/c.txt"), &[b'c'; 100])
        .unwrap();
    check(&mut served, usage(109, 4));
    served
        .service
        .rename(&context, &name("a.txt"), &name("dir/a.txt"))
        .unwrap();
    check(&mut served, usage(109, 4));
    served.service.delete(&context, &name("dir/b.txt")).unwrap();
    check(&mut served, usage(104, 3));
    served.service.delete(&context, &name("dir/c.txt")).unwrap();
    check(&mut served, usage(4, 2));
    served
        .service
        .rename(&context, &name("dir/a.txt"), &name("a.txt"))
        .unwrap();
    served.service.delete(&context, &name("dir")).unwrap();
    check(&mut served, usage(4, 1));
    served
        .service
        .create(&context, &name("empty.txt"), b"")
        .unwrap();
    check(&mut served, usage(4, 2));
}

#[test]
fn recount_matches_after_outside_changes_and_never_counts_behind_a_link() {
    let tree = tree();
    write(&tree.root, "a.txt", &[b'a'; 10]);
    let mut served = output(tree, roomy());
    assert_eq!(served.service.usage(), usage(10, 1));
    // The user changes the live tree behind the service's back.
    fs::remove_file(served.tree.root.join("a.txt")).unwrap();
    write(&served.tree.root, "x.txt", &[b'x'; 7]);
    write(&served.tree.root, "sub/y.txt", &[b'y'; 3]);
    dir_link(&served.tree.root.join("link"), &served.tree.outside);
    // The count is the service's own until a recount.
    assert_eq!(served.service.usage(), usage(10, 1));
    // x.txt, sub, sub/y.txt and the link as one entry; nothing behind the link.
    assert_eq!(served.service.recount(), Ok(usage(10, 4)));
    assert_eq!(served.service.usage(), usage(10, 4));
}

#[test]
fn a_root_too_large_to_count_refuses_every_change_but_still_reads() {
    let tree = tree();
    for text in ["a.txt", "b.txt", "c.txt", "d.txt"] {
        write(&tree.root, text, text.as_bytes());
    }
    let mut served = output(tree, quota(1_000, 3, 100));
    let before = snapshot(&served.tree.root);
    let context = context();
    assert_eq!(served.service.usage(), None);
    let service = &mut served.service;
    assert_eq!(
        service.create(&context, &name("e.txt"), b"e"),
        Err(ServiceRefusal::UsageUnknown)
    );
    assert_eq!(
        service.write(&context, &name("a.txt"), b"x"),
        Err(ServiceRefusal::UsageUnknown)
    );
    assert_eq!(
        service.delete(&context, &name("a.txt")),
        Err(ServiceRefusal::UsageUnknown)
    );
    assert_eq!(
        service.rename(&context, &name("a.txt"), &name("z.txt")),
        Err(ServiceRefusal::UsageUnknown)
    );
    assert_eq!(
        service.set_executable(&context, &name("a.txt"), true),
        Err(ServiceRefusal::UsageUnknown)
    );
    assert_eq!(
        service.read(&context, &name("a.txt"), 100),
        Ok(b"a.txt".to_vec())
    );
    assert_eq!(service.list(&context, None).unwrap().entries.len(), 4);
    assert_eq!(snapshot(&served.tree.root), before);
    // Once the root fits the count again, changes are judged against it.
    fs::remove_file(served.tree.root.join("d.txt")).unwrap();
    assert_eq!(served.service.recount(), Ok(usage(15, 3)));
    assert_eq!(
        served.service.create(&context, &name("e.txt"), b"e"),
        Err(grant_refusal(GrantRefusal::EntryQuotaExceeded {
            max_entries: 3
        }))
    );
    served
        .service
        .write(&context, &name("a.txt"), b"x")
        .unwrap();
    assert_eq!(served.service.usage(), usage(11, 3));
}

#[test]
fn an_expired_grant_is_refused_for_every_operation() {
    let tree = tree();
    write(&tree.root, "a.txt", b"a");
    fs::create_dir(tree.root.join("dir")).unwrap();
    let mut served = output(tree, roomy());
    let before = snapshot(&served.tree.root);
    let expired = RequestContext {
        now: at(100),
        ..context()
    };
    let expected = grant_refusal(GrantRefusal::Expired {
        expired_at: at(100),
    });
    for refusal in refusals_for(&mut served, &expired) {
        assert_eq!(refusal, expected);
    }
    assert_eq!(snapshot(&served.tree.root), before);
    let late = RequestContext {
        now: at(1_000),
        ..context()
    };
    for refusal in refusals_for(&mut served, &late) {
        assert_eq!(refusal, expected);
    }
}

#[test]
fn another_clock_session_or_trust_scope_is_refused() {
    let tree = tree();
    write(&tree.root, "a.txt", b"a");
    fs::create_dir(tree.root.join("dir")).unwrap();
    let mut served = output(tree, roomy());
    let before = snapshot(&served.tree.root);
    let restarted = RequestContext {
        session: session(2),
        ..context()
    };
    for refusal in refusals_for(&mut served, &restarted) {
        assert_eq!(refusal, grant_refusal(GrantRefusal::OtherClock));
    }
    for scope in [
        TrustScope::named(ExecutionCategory::VmSandbox, "sandbox-b"),
        TrustScope::named(ExecutionCategory::SharedKernelGpuRuntime, "sandbox-a"),
    ] {
        let stranger = RequestContext { scope, ..context() };
        for refusal in refusals_for(&mut served, &stranger) {
            assert_eq!(refusal, grant_refusal(GrantRefusal::WrongScope));
        }
    }
    assert_eq!(snapshot(&served.tree.root), before);
}

#[test]
fn a_write_is_authorized_before_the_name_is_resolved() {
    let tree = tree();
    dir_link(&tree.root.join("link"), &tree.outside);
    let mut served = output(tree, roomy());
    let expired = RequestContext {
        now: at(100),
        ..context()
    };
    let expected = grant_refusal(GrantRefusal::Expired {
        expired_at: at(100),
    });
    for text in ["missing.txt", "link", "link/secret.txt"] {
        assert_eq!(
            served.service.write(&expired, &name(text), b"x"),
            Err(expected.clone()),
            "{text}"
        );
    }
    let mut snapshot_served = serve(
        tree_with_file(),
        read_only(),
        &[FileOperation::Read, FileOperation::List],
        roomy(),
    );
    assert_eq!(
        snapshot_served
            .service
            .write(&context(), &name("missing.txt"), b"x"),
        Err(not_granted(FileOperation::Write))
    );
}

fn tree_with_file() -> Tree {
    let tree = tree();
    write(&tree.root, "a.txt", b"a");
    tree
}

#[test]
fn every_operation_through_or_of_a_link_is_refused() {
    let tree = tree();
    write(&tree.root, "a.txt", b"a");
    dir_link(&tree.root.join("link"), &tree.outside);
    fs::hard_link(
        tree.outside.join("secret.txt"),
        tree.root.join("shadow.txt"),
    )
    .unwrap();
    let mut served = output(tree, roomy());
    let before = snapshot(&served.tree.root);
    let outside_before = snapshot(&served.tree.outside);
    let context = context();
    let link = link_refused("link", DIR_LINK);
    let shadow = link_refused("shadow.txt", LinkKind::HardLink);
    let service = &mut served.service;
    for text in ["link", "link/secret.txt", "link/sub/deeper.txt"] {
        assert_eq!(
            service.read(&context, &name(text), 1_000),
            Err(link.clone())
        );
        assert_eq!(
            service.write(&context, &name(text), b"x"),
            Err(link.clone())
        );
        assert_eq!(service.delete(&context, &name(text)), Err(link.clone()));
        assert_eq!(
            service.rename(&context, &name(text), &name("moved")),
            Err(link.clone())
        );
        assert_eq!(
            service.set_executable(&context, &name(text), true),
            Err(link.clone())
        );
        assert_eq!(service.list(&context, Some(&name(text))), Err(link.clone()));
    }
    assert_eq!(
        service.create(&context, &name("link/new.txt"), b"x"),
        Err(link.clone())
    );
    assert_eq!(
        service.create(&context, &name("link"), b"x"),
        Err(link.clone())
    );
    assert_eq!(
        service.rename(&context, &name("a.txt"), &name("link/a.txt")),
        Err(link.clone())
    );
    assert_eq!(
        service.read(&context, &name("shadow.txt"), 1_000),
        Err(shadow.clone())
    );
    assert_eq!(
        service.write(&context, &name("shadow.txt"), b"x"),
        Err(shadow.clone())
    );
    assert_eq!(
        service.delete(&context, &name("shadow.txt")),
        Err(shadow.clone())
    );
    assert_eq!(
        service.rename(&context, &name("shadow.txt"), &name("moved")),
        Err(shadow.clone())
    );
    assert_eq!(
        service.create(&context, &name("shadow.txt/x"), b"x"),
        Err(shadow)
    );
    assert_eq!(snapshot(&served.tree.root), before);
    assert_eq!(snapshot(&served.tree.outside), outside_before);
    assert_eq!(
        fs::read(served.tree.outside.join("secret.txt")).unwrap(),
        SECRET
    );
}

#[test]
fn a_listing_shows_links_as_links_and_counts_unaddressable_names() {
    let tree = tree();
    write(&tree.root, "a.txt", b"abc");
    fs::create_dir(tree.root.join("dir")).unwrap();
    dir_link(&tree.root.join("link"), &tree.outside);
    fs::hard_link(
        tree.outside.join("secret.txt"),
        tree.root.join("shadow.txt"),
    )
    .unwrap();
    // Not valid guest names: non-ASCII and a short-name alias.
    write(&tree.root, "na\u{ef}ve.txt", b"x");
    write(&tree.root, "backup~1.txt", b"x");
    let served = output(tree, roomy());
    let listing = served.service.list(&context(), None).unwrap();
    assert_eq!(
        listing.entries,
        [
            listed_file("a.txt", 3),
            listed("dir", ListedKind::Directory),
            listed("link", ListedKind::Link { link: DIR_LINK }),
            listed(
                "shadow.txt",
                ListedKind::Link {
                    link: LinkKind::HardLink
                }
            ),
        ]
    );
    assert_eq!(listing.unaddressable, 2);
    assert!(!listing.truncated);
    let inner = served.service.list(&context(), Some(&name("dir"))).unwrap();
    assert_eq!(
        inner,
        Listing {
            entries: Vec::new(),
            unaddressable: 0,
            truncated: false
        }
    );
    assert_eq!(
        served.service.list(&context(), Some(&name("missing"))),
        Err(not_found("missing"))
    );
    assert!(matches!(
        served.service.list(&context(), Some(&name("a.txt"))),
        Err(ServiceRefusal::Resolve { .. })
    ));
}

#[test]
fn a_write_replaces_the_whole_file_and_leaves_no_staging_file() {
    let tree = tree();
    write(&tree.root, "dir/f.txt", b"the old content");
    let mut served = output(tree, roomy());
    let context = context();
    served
        .service
        .write(&context, &name("dir/f.txt"), b"new")
        .unwrap();
    assert_eq!(
        fs::read(host(&served.tree.root, "dir/f.txt")).unwrap(),
        b"new"
    );
    assert_eq!(names_in(&served.tree.root.join("dir")), ["f.txt"]);
    assert_eq!(names_in(&served.tree.root), ["dir"]);
    assert_eq!(served.service.usage(), usage(3, 2));
    served
        .service
        .write(&context, &name("dir/f.txt"), b"")
        .unwrap();
    assert_eq!(fs::read(host(&served.tree.root, "dir/f.txt")).unwrap(), b"");
    assert_eq!(names_in(&served.tree.root.join("dir")), ["f.txt"]);
    assert_eq!(served.service.usage(), usage(0, 2));
    assert_eq!(
        served
            .service
            .write(&context, &name("dir/missing.txt"), b"x"),
        Err(not_found("dir/missing.txt"))
    );
    assert_eq!(
        served.service.write(&context, &name("dir"), b"x"),
        Err(ServiceRefusal::NotAFile { name: name("dir") })
    );
    assert_eq!(names_in(&served.tree.root.join("dir")), ["f.txt"]);
}

#[test]
fn a_write_steps_past_a_taken_staging_name() {
    let tree = tree();
    write(&tree.root, "dir/f.txt", b"old");
    write(&tree.root, "dir/.yougori-write-1.tmp", b"not ours");
    let mut served = output(tree, roomy());
    assert_eq!(served.service.usage(), usage(11, 3));
    served
        .service
        .write(&context(), &name("dir/f.txt"), b"fresh")
        .unwrap();
    assert_eq!(
        fs::read(host(&served.tree.root, "dir/f.txt")).unwrap(),
        b"fresh"
    );
    assert_eq!(
        fs::read(host(&served.tree.root, "dir/.yougori-write-1.tmp")).unwrap(),
        b"not ours"
    );
    assert_eq!(
        names_in(&served.tree.root.join("dir")),
        [".yougori-write-1.tmp", "f.txt"]
    );
    assert_eq!(served.service.usage(), usage(13, 3));
    assert_eq!(served.service.recount(), Ok(usage(13, 3)));
}

#[test]
fn create_refuses_an_existing_name_and_needs_a_real_parent() {
    let tree = tree();
    write(&tree.root, "a.txt", b"keep");
    fs::create_dir(tree.root.join("dir")).unwrap();
    let mut served = output(tree, roomy());
    let context = context();
    let service = &mut served.service;
    service
        .create(&context, &name("dir/new.txt"), b"new")
        .unwrap();
    assert_eq!(
        fs::read(host(&served.tree.root, "dir/new.txt")).unwrap(),
        b"new"
    );
    let service = &mut served.service;
    assert_eq!(
        service.create(&context, &name("a.txt"), b"clobber"),
        Err(already_exists("a.txt"))
    );
    assert_eq!(
        service.create(&context, &name("dir"), b"clobber"),
        Err(already_exists("dir"))
    );
    assert_eq!(
        service.create(&context, &name("dir/new.txt"), b"clobber"),
        Err(already_exists("dir/new.txt"))
    );
    assert_eq!(
        service.create(&context, &name("missing/x.txt"), b"x"),
        Err(not_found("missing"))
    );
    assert_eq!(
        service.create(&context, &name("a.txt/x"), b"x"),
        Err(resolve_refusal(ResolveRefusal::NotADirectory {
            at: name("a.txt")
        }))
    );
    if cfg!(windows) {
        assert_eq!(
            service.create(&context, &name("A.TXT"), b"alias"),
            Err(resolve_refusal(ResolveRefusal::CaseAlias {
                requested: name("A.TXT"),
                stored: name("a.txt")
            }))
        );
    }
    assert_eq!(fs::read(served.tree.root.join("a.txt")).unwrap(), b"keep");
    assert_eq!(served.service.usage(), usage(7, 3));
}

#[test]
fn rename_moves_entries_and_refuses_taken_targets_and_links() {
    let tree = tree();
    write(&tree.root, "a.txt", b"alpha");
    write(&tree.root, "b.txt", b"beta");
    write(&tree.root, "dir/inner.txt", b"inner");
    fs::create_dir(tree.root.join("to")).unwrap();
    dir_link(&tree.root.join("link"), &tree.outside);
    let mut served = output(tree, roomy());
    let context = context();
    let service = &mut served.service;
    assert_eq!(
        service.rename(&context, &name("a.txt"), &name("b.txt")),
        Err(already_exists("b.txt"))
    );
    assert_eq!(
        service.rename(&context, &name("a.txt"), &name("dir")),
        Err(already_exists("dir"))
    );
    assert_eq!(
        service.rename(&context, &name("link"), &name("moved")),
        Err(link_refused("link", DIR_LINK))
    );
    assert_eq!(
        service.rename(&context, &name("missing.txt"), &name("moved")),
        Err(not_found("missing.txt"))
    );
    assert_eq!(
        service.rename(&context, &name("a.txt"), &name("nowhere/a.txt")),
        Err(not_found("nowhere"))
    );
    assert_eq!(fs::read(served.tree.root.join("a.txt")).unwrap(), b"alpha");
    assert_eq!(fs::read(served.tree.root.join("b.txt")).unwrap(), b"beta");
    let service = &mut served.service;
    service
        .rename(&context, &name("a.txt"), &name("to/a.txt"))
        .unwrap();
    service
        .rename(&context, &name("dir"), &name("to/dir"))
        .unwrap();
    assert!(!present(&served.tree.root.join("a.txt")));
    assert_eq!(
        fs::read(host(&served.tree.root, "to/a.txt")).unwrap(),
        b"alpha"
    );
    assert_eq!(
        fs::read(host(&served.tree.root, "to/dir/inner.txt")).unwrap(),
        b"inner"
    );
    assert_eq!(names_in(&served.tree.root), ["b.txt", "link", "to"]);
}

#[test]
fn delete_removes_files_and_empty_directories_only() {
    let tree = tree();
    write(&tree.root, "a.txt", b"alpha");
    write(&tree.root, "full/inner.txt", b"inner");
    fs::create_dir(tree.root.join("empty")).unwrap();
    let mut served = output(tree, roomy());
    let context = context();
    assert_eq!(served.service.usage(), usage(10, 4));
    assert_eq!(
        served.service.delete(&context, &name("full")),
        Err(ServiceRefusal::DirectoryNotEmpty { name: name("full") })
    );
    assert_eq!(
        fs::read(host(&served.tree.root, "full/inner.txt")).unwrap(),
        b"inner"
    );
    assert_eq!(served.service.usage(), usage(10, 4));
    served.service.delete(&context, &name("empty")).unwrap();
    assert!(!present(&served.tree.root.join("empty")));
    assert_eq!(served.service.usage(), usage(10, 3));
    served.service.delete(&context, &name("a.txt")).unwrap();
    assert!(!present(&served.tree.root.join("a.txt")));
    assert_eq!(served.service.usage(), usage(5, 2));
    assert_eq!(
        served.service.delete(&context, &name("a.txt")),
        Err(not_found("a.txt"))
    );
    assert_eq!(served.service.recount(), Ok(usage(5, 2)));
}

#[test]
fn set_executable_reaches_regular_files_only() {
    let tree = tree();
    write(&tree.root, "tool", b"#!/bin/sh\n");
    fs::create_dir(tree.root.join("dir")).unwrap();
    let mut served = output(tree, roomy());
    let context = context();
    served
        .service
        .set_executable(&context, &name("tool"), true)
        .unwrap();
    let listing = served.service.list(&context, None).unwrap();
    assert_eq!(
        listing.entries[1],
        listed(
            "tool",
            ListedKind::File {
                size_bytes: 10,
                // Windows has no execute bit.
                executable: cfg!(unix)
            }
        )
    );
    assert_eq!(
        served.service.set_executable(&context, &name("dir"), true),
        Err(ServiceRefusal::NotAFile { name: name("dir") })
    );
    assert_eq!(
        served
            .service
            .set_executable(&context, &name("missing"), true),
        Err(not_found("missing"))
    );
}

#[test]
fn a_live_workspace_never_claims_unchanged_host_state() {
    let tree = tree();
    write(&tree.root, "a.txt", b"a");
    let mut served = serve(tree, live(), &ALL, roomy());
    assert!(!served
        .service
        .host_state_claim()
        .host_executed_state_unchanged());
    served
        .service
        .write(&context(), &name("a.txt"), b"changed")
        .unwrap();
    assert_eq!(
        fs::read(served.tree.root.join("a.txt")).unwrap(),
        b"changed"
    );
    let quarantine = output(tree_with_file(), roomy());
    assert_eq!(
        quarantine.service.host_state_claim(),
        HostStateClaim::IsolatedUntilPromotion
    );
}

#[test]
fn the_opened_root_stays_scoped_when_its_path_is_replaced() {
    let tree = tree();
    write(&tree.root, "a.txt", b"original");
    write(&tree.root, "dir/b.txt", b"b");
    let mut served = output(tree, roomy());
    let context = context();
    let moved = served.tree.dir.path().join("root-moved");
    if let Err(error) = fs::rename(&served.tree.root, &moved) {
        eprintln!("the open root could not be renamed: {error}");
        assert_eq!(
            served.service.read(&context, &name("a.txt"), 100),
            Ok(b"original".to_vec())
        );
        return;
    }
    write(&served.tree.root, "a.txt", b"impostor");
    write(&served.tree.root, "planted.txt", b"planted");
    assert_eq!(
        served.service.read(&context, &name("a.txt"), 100),
        Ok(b"original".to_vec())
    );
    let names: Vec<String> = served
        .service
        .list(&context, None)
        .unwrap()
        .entries
        .into_iter()
        .map(|entry| entry.name.as_str().to_owned())
        .collect();
    assert_eq!(names, ["a.txt", "dir"]);
    assert_eq!(
        served.service.read(&context, &name("planted.txt"), 100),
        Err(not_found("planted.txt"))
    );
    served
        .service
        .create(&context, &name("new.txt"), b"new")
        .unwrap();
    served
        .service
        .write(&context, &name("dir/b.txt"), b"bb")
        .unwrap();
    served.service.delete(&context, &name("a.txt")).unwrap();
    assert_eq!(fs::read(moved.join("new.txt")).unwrap(), b"new");
    assert_eq!(fs::read(host(&moved, "dir/b.txt")).unwrap(), b"bb");
    assert!(!present(&moved.join("a.txt")));
    assert_eq!(names_in(&served.tree.root), ["a.txt", "planted.txt"]);
    assert_eq!(
        fs::read(served.tree.root.join("a.txt")).unwrap(),
        b"impostor"
    );
    assert_eq!(served.service.usage(), usage(5, 3));
    assert_eq!(served.service.recount(), Ok(usage(5, 3)));
}

#[test]
fn a_directory_read_or_written_as_a_file_is_refused_as_not_a_file() {
    let tree = tree();
    fs::create_dir(tree.root.join("dir")).unwrap();
    let mut served = output(tree, roomy());
    let context = context();
    let expected = ServiceRefusal::NotAFile { name: name("dir") };
    assert_eq!(
        served.service.read(&context, &name("dir"), 100),
        Err(expected.clone())
    );
    assert_eq!(
        served.service.write(&context, &name("dir"), b"x"),
        Err(expected.clone())
    );
    assert_eq!(
        served.service.set_executable(&context, &name("dir"), true),
        Err(expected)
    );
}

/// A file another process holds open without sharing (a running build, an editor's lock).
#[cfg(windows)]
fn locked(path: &std::path::Path) -> fs::File {
    use std::os::windows::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(path)
        .unwrap()
}

#[cfg(windows)]
#[test]
fn a_file_locked_by_another_handle_still_counts_toward_the_quota() {
    let tree = tree();
    write(&tree.root, "a.txt", b"abc");
    write(&tree.root, "locked.bin", &[0; 50]);
    let lock = locked(&tree.root.join("locked.bin"));
    let served = output(tree, roomy());
    let counted = served.service.usage();
    drop(lock);
    assert_eq!(counted, usage(53, 2));
}

#[cfg(windows)]
#[test]
fn a_file_locked_by_another_handle_does_not_stop_a_listing() {
    let tree = tree();
    write(&tree.root, "a.txt", b"abc");
    write(&tree.root, "locked.bin", &[0; 50]);
    let lock = locked(&tree.root.join("locked.bin"));
    let served = output(tree, roomy());
    let listing = served.service.list(&context(), None);
    drop(lock);
    let listing = listing.unwrap();
    assert_eq!(listing.entries[0], listed_file("a.txt", 3));
    assert_eq!(listing.entries.len(), 2);
}

#[test]
fn a_directory_is_created_as_a_counted_create_and_holds_new_files() {
    let tree = tree();
    write(&tree.root, "a.txt", b"abc");
    let mut served = output(tree, roomy());
    let context = context();
    assert_eq!(served.service.usage(), usage(3, 1));
    served
        .service
        .create_directory(&context, &name("out"))
        .unwrap();
    served
        .service
        .create_directory(&context, &name("out/nested"))
        .unwrap();
    served
        .service
        .create(&context, &name("out/nested/result.txt"), b"done")
        .unwrap();
    assert_eq!(
        fs::read(host(&served.tree.root, "out/nested/result.txt")).unwrap(),
        b"done"
    );
    assert_eq!(served.service.usage(), usage(7, 4));
    assert_eq!(served.service.recount(), Ok(usage(7, 4)));
    assert_eq!(
        served.service.create_directory(&context, &name("out")),
        Err(already_exists("out"))
    );
    assert_eq!(
        served.service.create_directory(&context, &name("a.txt")),
        Err(already_exists("a.txt"))
    );
    assert_eq!(
        served
            .service
            .create_directory(&context, &name("missing/x")),
        Err(not_found("missing"))
    );
    assert_eq!(
        served.service.create_directory(&context, &name("a.txt/x")),
        Err(resolve_refusal(ResolveRefusal::NotADirectory {
            at: name("a.txt")
        }))
    );
    assert_eq!(served.service.usage(), usage(7, 4));
}

#[test]
fn a_directory_is_never_created_through_a_link_beyond_the_quota_or_without_the_grant() {
    let linked = tree();
    dir_link(&linked.root.join("link"), &linked.outside);
    let outside_before = snapshot(&linked.outside);
    let mut served = output(linked, quota(1000, 2, 1000));
    let context = context();
    assert_eq!(
        served.service.create_directory(&context, &name("link/x")),
        Err(link_refused("link", DIR_LINK))
    );
    assert_eq!(
        served.service.create_directory(&context, &name("link")),
        Err(link_refused("link", DIR_LINK))
    );
    served
        .service
        .create_directory(&context, &name("one"))
        .unwrap();
    assert_eq!(
        served.service.create_directory(&context, &name("two")),
        Err(grant_refusal(GrantRefusal::EntryQuotaExceeded {
            max_entries: 2
        }))
    );
    let expired = RequestContext {
        now: at(100),
        ..context
    };
    assert_eq!(
        served.service.create_directory(&expired, &name("late")),
        Err(grant_refusal(GrantRefusal::Expired {
            expired_at: at(100)
        }))
    );
    assert_eq!(names_in(&served.tree.root), ["link", "one"]);
    assert_eq!(snapshot(&served.tree.outside), outside_before);

    let mut snapshot_served = serve(
        tree(),
        read_only(),
        &[FileOperation::Read, FileOperation::List],
        roomy(),
    );
    assert_eq!(
        snapshot_served
            .service
            .create_directory(&context, &name("new")),
        Err(not_granted(FileOperation::Create))
    );
    assert!(names_in(&snapshot_served.tree.root).is_empty());
}

#[test]
fn a_rename_onto_a_taken_name_is_refused_and_keeps_both_entries() {
    let tree = tree();
    write(&tree.root, "a.txt", b"a");
    write(&tree.root, "b.txt", b"b");
    write(&tree.root, "d/c.txt", b"c");
    let mut served = output(tree, roomy());
    let context = context();
    let before = snapshot(&served.tree.root);
    for (from, to) in [("a.txt", "b.txt"), ("a.txt", "d"), ("d", "b.txt")] {
        assert_eq!(
            served.service.rename(&context, &name(from), &name(to)),
            Err(already_exists(to)),
            "{from} -> {to}"
        );
    }
    assert_eq!(snapshot(&served.tree.root), before);
    served
        .service
        .rename(&context, &name("d"), &name("e"))
        .unwrap();
    assert_eq!(names_in(&served.tree.root), ["a.txt", "b.txt", "e"]);
    assert_eq!(served.service.usage(), usage(3, 4));
}

#[cfg(windows)]
#[test]
fn an_entry_no_guest_name_addresses_still_counts_and_is_not_listed() {
    use std::os::windows::ffi::OsStringExt;
    let tree = tree();
    write(&tree.root, "a.txt", b"abc");
    // An unpaired surrogate: a valid NTFS name that is no string at all.
    let unpaired = std::ffi::OsString::from_wide(&[0xD800, u16::from(b'x')]);
    fs::write(tree.root.join(&unpaired), [0u8; 40]).unwrap();
    let served = output(tree, roomy());
    assert_eq!(served.service.usage(), usage(43, 2));
    let listing = served.service.list(&context(), None).unwrap();
    assert_eq!(listing.entries, [listed_file("a.txt", 3)]);
    assert_eq!(listing.unaddressable, 1);
}

/// A quarantine output service with an upload area beside its root.
fn with_uploads(tree: Tree, quota: FileQuota) -> (Served, std::path::PathBuf) {
    let area = tree.dir.path().join("uploads");
    fs::create_dir(&area).unwrap();
    let root = GrantedRoot::open(&tree.root).unwrap();
    let grant = grant_for(root.handle(), GrantMode::QuarantineOutput, &ALL, quota);
    let service = FileService::new(grant, root).unwrap().with_uploads(&area).unwrap();
    (Served { service, tree }, area)
}

fn entries_in(path: &std::path::Path) -> usize {
    fs::read_dir(path).unwrap().count()
}

/// PROVES a file of any size reads in bounded ranges with a version that changes when the
/// file is replaced, and an offset past the end reads nothing.
#[test]
fn ranges_read_a_file_in_pieces_and_name_its_version() {
    let tree = tree();
    let bytes: Vec<u8> = (0..3_000_000u32).map(|at| (at % 251) as u8).collect();
    write(&tree.root, "big.bin", &bytes);
    let mut served = output(tree, quota(100_000_000, 100, 10_000_000));
    let mut read = Vec::new();
    let mut version = None;
    while (read.len() as u64) < bytes.len() as u64 {
        let range = served.service.read_range(&context(), &name("big.bin"), read.len() as u64, MAX_RANGE_BYTES * 2).unwrap();
        assert!(range.content.len() as u64 <= MAX_RANGE_BYTES, "a range never passes its bound");
        assert_eq!(range.size_bytes, bytes.len() as u64);
        assert!(version.as_ref().is_none_or(|seen| *seen == range.version), "one file throughout");
        version = Some(range.version);
        read.extend(range.content);
    }
    assert_eq!(read, bytes);
    assert!(served.service.read_range(&context(), &name("big.bin"), u64::MAX, 10).unwrap().content.is_empty());
    // Replaced: another version.
    served.service.write(&context(), &name("big.bin"), b"short").unwrap();
    let after = served.service.read_range(&context(), &name("big.bin"), 0, 10).unwrap();
    assert_eq!((after.content.as_slice(), after.size_bytes), (&b"short"[..], 5));
    assert_ne!(Some(after.version), version);
}

/// PROVES an upload assembles a file outside the tree in bounded chunks written in any
/// order, reads back what was written, and replaces the file in one atomic rename at
/// commit, keeping the quota count; until then the file is untouched, and an abort or the
/// end of the grant leaves nothing behind.
#[test]
fn an_upload_replaces_a_file_whole_only_at_its_commit() {
    let tree = tree();
    write(&tree.root, "data.bin", b"old content");
    let (mut served, area) = with_uploads(tree, quota(100_000_000, 100, 10_000_000));
    let file = name("data.bin");
    // From the existing content: an edit in the middle.
    let (upload, size) = served.service.upload_begin(&context(), &file, true).unwrap();
    assert_eq!(size, 11);
    assert_eq!(served.service.upload_write(&context(), &file, upload, 4, b"NEW").unwrap(), 11);
    assert_eq!(served.service.read_upload_range(&context(), &file, upload, 0, 100).unwrap().content, b"old NEWtent");
    assert_eq!(fs::read(host(&served.tree.root, "data.bin")).unwrap(), b"old content", "untouched before the commit");
    // Chunks of a larger file, out of order, past the old end.
    let chunk = vec![7u8; MAX_RANGE_BYTES as usize];
    served.service.upload_write(&context(), &file, upload, 2 * MAX_RANGE_BYTES, &chunk).unwrap();
    served.service.upload_write(&context(), &file, upload, MAX_RANGE_BYTES, &chunk).unwrap();
    assert_eq!(served.service.upload_truncate(&context(), &file, upload, 3 * MAX_RANGE_BYTES - 1).unwrap(), 3 * MAX_RANGE_BYTES - 1);
    let (size, content) = served.service.upload_commit(&context(), &file, upload).unwrap();
    let on_disk = fs::read(host(&served.tree.root, "data.bin")).unwrap();
    assert_eq!(size, on_disk.len() as u64);
    assert_eq!(content, crate::foundation::ids::ContentKey::of(&on_disk));
    assert_eq!(&on_disk[..11], b"old NEWtent");
    assert!(on_disk[11..MAX_RANGE_BYTES as usize].iter().all(|byte| *byte == 0), "a gap reads as zeros");
    assert_eq!(served.service.usage(), usage(size, 1));
    assert_eq!(entries_in(&area), 0, "the upload left the area with its commit");
    // An abort, and an upload the end of the grant takes with it.
    let (aborted, _) = served.service.upload_begin(&context(), &file, false).unwrap();
    served.service.upload_write(&context(), &file, aborted, 0, b"never").unwrap();
    served.service.upload_abort(&context(), &file, aborted).unwrap();
    assert_eq!(served.service.upload_write(&context(), &file, aborted, 0, b"x"), Err(ServiceRefusal::UnknownUpload { upload: aborted }));
    let (_, _) = served.service.upload_begin(&context(), &file, false).unwrap();
    assert_eq!(entries_in(&area), 1);
    let Served { service, tree } = served;
    drop(service);
    assert_eq!(entries_in(&area), 0, "nothing half assembled outlives the grant");
    assert_eq!(fs::read(host(&tree.root, "data.bin")).unwrap(), on_disk);
}

/// PROVES the upload refusals: the per-file quota as if committed, another file name, too
/// many open, a grant without uploads, and what a crash left removed at open.
#[test]
fn uploads_keep_the_quota_and_their_own_file() {
    let tree = tree();
    write(&tree.root, "a.bin", b"a");
    write(&tree.root, "b.bin", b"b");
    let area = tree.dir.path().join("uploads");
    fs::create_dir(&area).unwrap();
    fs::write(area.join("upload-9.part"), b"left by a crash").unwrap();
    let root = GrantedRoot::open(&tree.root).unwrap();
    let grant = grant_for(root.handle(), GrantMode::QuarantineOutput, &ALL, quota(1_000, 100, 600));
    let service = FileService::new(grant, root).unwrap().with_uploads(&area).unwrap();
    let mut served = Served { service, tree };
    assert_eq!(entries_in(&area), 0, "what a crash left is removed at open");
    let (upload, _) = served.service.upload_begin(&context(), &name("a.bin"), false).unwrap();
    assert!(matches!(served.service.upload_write(&context(), &name("a.bin"), upload, 0, &[1u8; 601]), Err(ServiceRefusal::Grant { refusal: GrantRefusal::FileTooLarge { .. } })));
    assert_eq!(served.service.upload_write(&context(), &name("b.bin"), upload, 0, b"x"), Err(ServiceRefusal::UploadNameMismatch { upload }));
    for _ in 1..MAX_UPLOADS {
        served.service.upload_begin(&context(), &name("b.bin"), false).unwrap();
    }
    assert_eq!(served.service.upload_begin(&context(), &name("b.bin"), false), Err(ServiceRefusal::TooManyUploads { limit: MAX_UPLOADS }));
    let plain_tree = super::root_tests::tree();
    write(&plain_tree.root, "c.bin", b"c");
    let mut plain = output(plain_tree, roomy());
    assert_eq!(plain.service.upload_begin(&context(), &name("c.bin"), false), Err(ServiceRefusal::UploadsUnavailable));
}

/// PROVES a replacing rename puts a regular file over a regular file in one step and counts
/// it, and never replaces a directory.
#[test]
fn a_replacing_rename_puts_a_file_over_a_file_only() {
    let tree = tree();
    write(&tree.root, "edit.tmp", b"new text");
    write(&tree.root, "notes.txt", b"old");
    write(&tree.root, "dir/inner.txt", b"x");
    let mut served = output(tree, roomy());
    let before = served.service.usage().unwrap();
    served.service.rename_replacing(&context(), &name("edit.tmp"), &name("notes.txt")).unwrap();
    assert_eq!(fs::read(host(&served.tree.root, "notes.txt")).unwrap(), b"new text");
    assert!(!host(&served.tree.root, "edit.tmp").exists());
    assert_eq!(served.service.usage(), usage(before.total_bytes - 3, before.entries - 1));
    write(&served.tree.root, "other.tmp", b"o");
    served.service.recount().unwrap();
    assert_eq!(served.service.rename_replacing(&context(), &name("other.tmp"), &name("dir")), Err(ServiceRefusal::NotAFile { name: name("dir") }));
    // To a free name it is a plain rename.
    served.service.rename_replacing(&context(), &name("other.tmp"), &name("fresh.txt")).unwrap();
    assert_eq!(fs::read(host(&served.tree.root, "fresh.txt")).unwrap(), b"o");
}

/// PROVES a replacing rename lands over a file another handle holds open for reading, as
/// the service's own ranged reads and a host program do: the name holds the new content at
/// once and the open handle reads on the replaced one, as on Unix. On Windows a volume
/// without POSIX rename semantics (FAT, here forced) refuses instead and changes nothing.
#[test]
fn a_replacing_rename_lands_over_a_file_held_open_for_reading() {
    use std::io::Read as _;
    let tree = tree();
    write(&tree.root, "edit.tmp", b"new text");
    write(&tree.root, "notes.txt", b"old text");
    let mut served = output(tree, roomy());
    let mut held = fs::File::open(host(&served.tree.root, "notes.txt")).unwrap();
    served.service.rename_replacing(&context(), &name("edit.tmp"), &name("notes.txt")).unwrap();
    assert_eq!(fs::read(host(&served.tree.root, "notes.txt")).unwrap(), b"new text");
    let mut old = String::new();
    held.read_to_string(&mut old).unwrap();
    assert_eq!(old, "old text");
    drop(held);
    #[cfg(windows)]
    {
        write(&served.tree.root, "again.tmp", b"again");
        served.service.recount().unwrap();
        let held = fs::File::open(host(&served.tree.root, "notes.txt")).unwrap();
        super::fsutil::force_legacy_rename(true);
        let refused = served.service.rename_replacing(&context(), &name("again.tmp"), &name("notes.txt"));
        super::fsutil::force_legacy_rename(false);
        assert!(matches!(refused, Err(ServiceRefusal::Io { .. })), "{refused:?}");
        drop(held);
        assert_eq!(fs::read(host(&served.tree.root, "notes.txt")).unwrap(), b"new text");
        assert_eq!(fs::read(host(&served.tree.root, "again.tmp")).unwrap(), b"again");
    }
}
