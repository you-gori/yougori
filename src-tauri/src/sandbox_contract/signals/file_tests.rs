//! The file service adapter: every class of [`ServiceRefusal`] under every grant mode, fed
//! through V14's assessment and responder (VM part §5.1; VM-P15; VM-W43).

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use super::fixtures::*;
use super::*;
use crate::foundation::ids::{digest, Clock, ManualClock};
use crate::sandbox_contract::files::{
    DisclosureAcknowledgment, FileGrant, FileOperation, FileQuota, FileService, GrantMode,
    GrantRefusal, GrantedRoot, GuestName, LinkKind, RequestContext, ResolveRefusal, RootHandle,
    SandboxClass, ServiceRefusal, ViolationAction,
};
use crate::sandbox_contract::response::{
    DecisionReason, HostObserver, Preserved, Reading, ResponseAction, SignalClass, SignalSource,
    TargetRole, ViolationKind,
};

const LINK_KINDS: [LinkKind; 5] = [
    LinkKind::Symlink,
    LinkKind::HardLink,
    LinkKind::Junction,
    LinkKind::ReparsePoint,
    LinkKind::MountCrossing,
];

fn name(text: &str) -> GuestName {
    GuestName::parse(text).unwrap()
}

fn root() -> RootHandle {
    RootHandle::from_host(digest("yougori/test/root/v1", &[b"workspace"]))
}

fn live() -> GrantMode {
    GrantMode::LiveWorkspace {
        acknowledgment: DisclosureAcknowledgment::of_current_statement(),
    }
}

fn snapshot() -> GrantMode {
    GrantMode::ReadOnlySnapshot {
        snapshot: digest("yougori/test/snapshot/v1", &[b"v1"]),
    }
}

fn context(sandbox: &str, mode: GrantMode, now: &ManualClock) -> FileServiceContext {
    FileServiceContext {
        observed: observed(sandbox, now),
        root: root(),
        mode,
        grant: grant("files-workspace"),
    }
}

fn link_refused(at: &str, link: LinkKind) -> ServiceRefusal {
    ServiceRefusal::Resolve {
        refusal: ResolveRefusal::LinkRefused { at: name(at), link },
    }
}

fn grant_refused(refusal: GrantRefusal) -> ServiceRefusal {
    ServiceRefusal::Grant { refusal }
}

/// A service over `path` for sandbox `exe-a`, reading and listing under `mode`.
fn serve(path: &Path, mode: GrantMode) -> FileService {
    let opened = GrantedRoot::open(path).unwrap();
    let file_grant = FileGrant::new(
        opened.handle(),
        mode,
        BTreeSet::from([FileOperation::Read, FileOperation::List]),
        scope_of("exe-a"),
        host_session(),
        at(START_SECONDS + 3_600),
        FileQuota {
            max_total_bytes: 1_000_000,
            max_entries: 100,
            max_file_bytes: 100_000,
        },
    )
    .unwrap();
    FileService::new(file_grant, opened).unwrap()
}

fn request(now: &ManualClock) -> RequestContext {
    RequestContext {
        scope: scope_of("exe-a"),
        now: now.now(),
        session: host_session(),
    }
}

/// A root holding `shadow.txt`, a second name of a file outside it.
fn tree_with_hard_link() -> (tempfile::TempDir, std::path::PathBuf) {
    let tree = tempfile::tempdir().unwrap();
    let inside = tree.path().join("granted");
    let outside = tree.path().join("outside");
    fs::create_dir(&inside).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("secret.txt"), b"secret").unwrap();
    fs::hard_link(outside.join("secret.txt"), inside.join("shadow.txt")).unwrap();
    (tree, inside)
}

#[cfg(windows)]
#[test]
fn a_case_slip_on_an_ordinary_file_is_an_ordinary_spelling_refusal() {
    let now = clock();
    let tree = tempfile::tempdir().unwrap();
    fs::write(tree.path().join("README.md"), b"hello").unwrap();
    let service = serve(tree.path(), GrantMode::QuarantineOutput);
    let request = request(&now);
    let refusal = service.read(&request, &name("README.MD"), 100).unwrap_err();
    assert!(matches!(
        refusal,
        ServiceRefusal::Resolve {
            refusal: ResolveRefusal::CaseAlias { .. }
        }
    ));
    let seen = FileServiceContext::of_request(
        execution("exe-a"),
        scope_of("exe-a"),
        &request,
        &service,
        grant("f"),
    )
    .unwrap();
    let outcome = file_refusal_signal(&refusal, &seen);
    assert_eq!(outcome.ordinary(), Some(Ordinary::CaseSpelling));
    assert!(outcome.draft().is_none());
    assert!(outcome.anomaly().is_none());
}

#[test]
fn a_hard_link_in_a_live_workspace_is_ordinary() {
    let now = clock();
    let (_tree, inside) = tree_with_hard_link();
    let service = serve(&inside, live());
    let request = request(&now);
    let refusal = service
        .read(&request, &name("shadow.txt"), 1_000)
        .unwrap_err();
    assert_eq!(refusal, link_refused("shadow.txt", LinkKind::HardLink));
    let seen = FileServiceContext::of_request(
        execution("exe-a"),
        scope_of("exe-a"),
        &request,
        &service,
        grant("files-exe-a"),
    )
    .unwrap();
    assert_eq!(seen.mode, live());
    assert_eq!(
        file_refusal_signal(&refusal, &seen),
        Classification::Ordinary {
            reason: Ordinary::WorkspaceEntry
        }
    );
}

#[test]
fn a_hard_link_beneath_quarantine_output_is_a_host_anomaly_never_a_violation() {
    let now = clock();
    let (tree, inside) = tree_with_hard_link();
    let service = serve(&inside, GrantMode::QuarantineOutput);
    let request = request(&now);
    let refusal = service
        .read(&request, &name("shadow.txt"), 1_000)
        .unwrap_err();
    let seen = FileServiceContext::of_request(
        execution("exe-a"),
        scope_of("exe-a"),
        &request,
        &service,
        grant("files-exe-a"),
    )
    .unwrap();
    let outcome = file_refusal_signal(&refusal, &seen);
    assert!(!outcome.is_violation());
    assert!(outcome.draft().is_none());
    let notice = outcome.anomaly().unwrap();
    assert_eq!(
        notice.anomaly,
        HostAnomaly::LinkInHostRoot {
            link: LinkKind::HardLink
        }
    );
    assert_eq!(notice.sandbox, execution("exe-a"));
    assert_eq!(notice.observer, HostObserver::Supervisor);
    assert_eq!(notice.observed_at, now.now());
    assert_eq!(notice.session, host_session());
    assert_eq!(
        notice.subject,
        file_subject(service.grant().root(), Some(&name("shadow.txt")))
    );
    // V14's uncertain result: notify and deny new high-impact operations, never more.
    assert_eq!(notice.actions(), uncertain_actions());
    drop(service);
    assert_eq!(
        fs::read(tree.path().join("outside").join("secret.txt")).unwrap(),
        b"secret"
    );
}

#[test]
fn links_and_devices_are_classified_by_who_writes_the_root() {
    let now = clock();
    let mut refusals: Vec<(ServiceRefusal, HostAnomaly)> = LINK_KINDS
        .iter()
        .map(|&link| {
            (
                link_refused("src/escape", link),
                HostAnomaly::LinkInHostRoot { link },
            )
        })
        .collect();
    refusals.push((
        ServiceRefusal::Resolve {
            refusal: ResolveRefusal::DeviceRefused { at: name("fifo") },
        },
        HostAnomaly::DeviceInHostRoot,
    ));
    for (refusal, anomaly) in refusals {
        for mode in [snapshot(), GrantMode::QuarantineOutput] {
            let outcome = file_refusal_signal(&refusal, &context("exe-a", mode, &now));
            assert_eq!(
                outcome.anomaly().map(|notice| notice.anomaly),
                Some(anomaly),
                "{refusal:?} under {mode:?}"
            );
            assert!(outcome.draft().is_none());
        }
        assert_eq!(
            file_refusal_signal(&refusal, &context("exe-a", live(), &now)).ordinary(),
            Some(Ordinary::WorkspaceEntry)
        );
    }
}

#[test]
fn a_grant_presented_from_another_scope_is_a_violation_naming_the_compromised_grant() {
    let now = clock();
    let shared = grant("files-workspace");
    for mode in [live(), snapshot(), GrantMode::QuarantineOutput] {
        let outcome = file_refusal_signal(
            &grant_refused(GrantRefusal::WrongScope),
            &context("exe-b", mode, &now),
        );
        assert_eq!(outcome.cause(), Some(&FileViolation::ForeignScope));
        let draft = outcome.into_draft().unwrap();
        assert_eq!(
            draft.class,
            SignalClass::Violation {
                kind: ViolationKind::FileRootEscape
            }
        );
        assert_eq!(
            draft.source,
            SignalSource::HostObserved {
                observer: HostObserver::Supervisor
            }
        );
        assert_eq!(draft.reading, Reading::ViolationObserved);
        assert_eq!(draft.subject, file_subject(root(), None));
        assert_eq!(draft.violated_grant, Some(shared));
    }
    let draft = file_refusal_signal(
        &grant_refused(GrantRefusal::WrongScope),
        &context("exe-b", live(), &now),
    )
    .into_draft()
    .unwrap();
    let assessment = assess(&[signal(draft)], &now);
    // exe-b presented exe-a's grant: exe-b stops, and exe-a loses that grant only.
    let mut responder = responder_with(
        &now,
        &[
            ("exe-b", SandboxClass::Task, &[]),
            ("exe-a", SandboxClass::Service, &[shared, grant("other")]),
        ],
    );
    let record = responded(responder.respond_to(&assessment).unwrap());
    let observed = record.observed().unwrap();
    assert_eq!(observed.sandbox, execution("exe-b"));
    assert_eq!(observed.actions, violation_actions(true));
    assert_eq!(observed.class_response, Some(ViolationAction::Stop));
    assert_eq!(
        record.decision.reason,
        DecisionReason::KnownViolation {
            kind: ViolationKind::FileRootEscape,
            observer: HostObserver::Supervisor,
            meaning: None
        }
    );
    assert!(record
        .decision
        .preserves
        .contains(&Preserved::HostWorkspaces));
    let holder = &record.targets[1];
    assert_eq!(holder.sandbox, execution("exe-a"));
    assert_eq!(
        holder.role,
        TargetRole::SharesViolatedGrant { grant: shared }
    );
    assert_eq!(
        holder.actions,
        BTreeSet::from([ResponseAction::NotifyUser, ResponseAction::RevokeGrant])
    );
}

#[test]
fn other_grant_refusals_are_ordinary() {
    let now = clock();
    let seen = context("exe-a", live(), &now);
    for (refusal, reason) in [
        (GrantRefusal::OtherClock, Ordinary::NotCurrent),
        (
            GrantRefusal::Expired {
                expired_at: at(START_SECONDS),
            },
            Ordinary::NotCurrent,
        ),
        (GrantRefusal::WrongRoot, Ordinary::HostConfiguration),
        (
            GrantRefusal::OperationNotGranted {
                operation: FileOperation::Write,
            },
            Ordinary::NotPermitted,
        ),
        (
            GrantRefusal::FileTooLarge {
                resulting_file_bytes: 11,
                max_file_bytes: 10,
            },
            Ordinary::LimitReached,
        ),
        (
            GrantRefusal::TotalQuotaExceeded {
                resulting_total_bytes: 11,
                max_total_bytes: 10,
            },
            Ordinary::LimitReached,
        ),
        (
            GrantRefusal::EntryQuotaExceeded { max_entries: 10 },
            Ordinary::LimitReached,
        ),
    ] {
        let outcome = file_refusal_signal(&grant_refused(refusal.clone()), &seen);
        assert_eq!(outcome.ordinary(), Some(reason), "{refusal:?}");
        assert!(outcome.draft().is_none());
    }
}

#[test]
fn ordinary_file_refusals_draft_no_signal() {
    let now = clock();
    let cases = [
        (
            ServiceRefusal::Resolve {
                refusal: ResolveRefusal::CaseAlias {
                    requested: name("README.MD"),
                    stored: name("README.md"),
                },
            },
            Ordinary::CaseSpelling,
        ),
        (
            ServiceRefusal::Resolve {
                refusal: ResolveRefusal::NotFound {
                    at: name("missing"),
                },
            },
            Ordinary::NotFound,
        ),
        (
            ServiceRefusal::Resolve {
                refusal: ResolveRefusal::NotADirectory { at: name("a.txt") },
            },
            Ordinary::NotFound,
        ),
        (
            ServiceRefusal::Resolve {
                refusal: ResolveRefusal::Io {
                    at: name("a.txt"),
                    detail: "PermissionDenied".into(),
                },
            },
            Ordinary::HostFault,
        ),
        (ServiceRefusal::RootMismatch, Ordinary::HostConfiguration),
        (
            ServiceRefusal::NotAFile { name: name("src") },
            Ordinary::EntryState,
        ),
        (
            ServiceRefusal::AlreadyExists {
                name: name("a.txt"),
            },
            Ordinary::EntryState,
        ),
        (
            ServiceRefusal::DirectoryNotEmpty { name: name("src") },
            Ordinary::EntryState,
        ),
        (
            ServiceRefusal::ReadTooLarge {
                name: name("big.bin"),
                size_bytes: 11,
                limit: 10,
            },
            Ordinary::LimitReached,
        ),
        (
            ServiceRefusal::Changed {
                name: name("a.txt"),
            },
            Ordinary::ChangedDuringRequest,
        ),
        (ServiceRefusal::UsageUnknown, Ordinary::HostFault),
        (
            ServiceRefusal::Io {
                operation: FileOperation::Read,
                name: None,
                detail: "Other".into(),
            },
            Ordinary::HostFault,
        ),
    ];
    for (refusal, reason) in cases {
        for mode in [live(), snapshot(), GrantMode::QuarantineOutput] {
            let outcome = file_refusal_signal(&refusal, &context("exe-a", mode, &now));
            assert_eq!(outcome, Classification::Ordinary { reason }, "{refusal:?}");
        }
    }
    // A real missing file is refused as not found and drafts nothing.
    let tree = tempfile::tempdir().unwrap();
    let service = serve(tree.path(), GrantMode::QuarantineOutput);
    let request = request(&now);
    let refusal = service
        .read(&request, &name("missing.txt"), 10)
        .unwrap_err();
    let seen = FileServiceContext::of_request(
        execution("exe-a"),
        scope_of("exe-a"),
        &request,
        &service,
        grant("g"),
    )
    .unwrap();
    assert_eq!(
        file_refusal_signal(&refusal, &seen).ordinary(),
        Some(Ordinary::NotFound)
    );
}

#[test]
fn observing_a_request_checks_the_sandbox_against_the_requests_scope() {
    let now = clock();
    let request = request(&now);
    assert_eq!(
        Observed::of_request(execution("exe-a"), scope_of("exe-a"), &request),
        Ok(observed("exe-a", &now))
    );
    let mismatch =
        Observed::of_request(execution("exe-b"), scope_of("exe-b"), &request).unwrap_err();
    assert_eq!(
        mismatch,
        ScopeMismatch {
            sandbox: execution("exe-b"),
            expected: scope_of("exe-b"),
            request: scope_of("exe-a"),
        }
    );
    let tree = tempfile::tempdir().unwrap();
    let service = serve(tree.path(), GrantMode::QuarantineOutput);
    assert!(FileServiceContext::of_request(
        execution("exe-b"),
        scope_of("exe-b"),
        &request,
        &service,
        grant("g"),
    )
    .is_err());
}

#[test]
fn a_stale_foreign_scope_refusal_is_an_uncertain_result_never_a_pass() {
    let now = clock();
    let draft = file_refusal_signal(
        &grant_refused(GrantRefusal::WrongScope),
        &context("exe-a", live(), &now),
    )
    .into_draft()
    .unwrap();
    now.advance(31 * SECOND);
    let record = respond_alone(draft.clone(), &now);
    assert_eq!(record.decision.actions, uncertain_actions());
    assert!(matches!(
        record.decision.reason,
        DecisionReason::Uncertain {
            observer: HostObserver::Supervisor,
            ..
        }
    ));
    // A stamp from another clock session is stale too: its age cannot be known.
    let mut other = draft;
    other.session = session(2);
    other.observed_at = now.now();
    let record = respond_alone(other, &now);
    assert_eq!(record.decision.actions, uncertain_actions());
}

#[test]
fn subjects_are_digests_and_the_guest_name_reaches_no_audit_field() {
    let now = clock();
    let planted = "deploy-token-AKIAEXAMPLE";
    let outcome = file_refusal_signal(
        &link_refused(planted, LinkKind::Symlink),
        &context("exe-a", GrantMode::QuarantineOutput, &now),
    );
    let notice = outcome.anomaly().unwrap();
    assert!(!format!("{notice:?}").contains("AKIA"));
    assert_eq!(notice.subject, file_subject(root(), Some(&name(planted))));
    assert_ne!(notice.subject, file_subject(root(), Some(&name("other"))));
    assert_ne!(notice.subject, file_subject(root(), None));
    let elsewhere = RootHandle::from_host(digest("yougori/test/root/v1", &[b"other"]));
    assert_ne!(
        notice.subject,
        file_subject(elsewhere, Some(&name(planted)))
    );
    let draft = file_refusal_signal(
        &grant_refused(GrantRefusal::WrongScope),
        &context("exe-a", live(), &now),
    )
    .into_draft()
    .unwrap();
    // A field's Debug output shows every metadata value.
    let fields = format!("{:?}", signal(draft).audit_fields());
    assert!(fields.contains("file_root_escape"), "{fields}");
    assert!(!fields.contains("AKIA"), "{fields}");
}
