//! The host end to end on the fake backend (VM part §3.2 lines 2059–2077; §6.1–§6.4 lines
//! 2284–2326; §8.1 line 2439; §8.2 lines 2441–2449): the real supervisor over the real
//! CORE-04 coordinator and CORE-03 ledger, integration's port and its sink on the durable
//! spooled stream, a real host link driven by a scripted guest end, and the guest-file
//! adapter over a real dispatcher and file service on temporary roots, all on a manual
//! clock.

use std::collections::BTreeSet;
use std::fs;
use std::time::Duration;

use serde_json::json;

use super::fakes::*;
use super::{ChannelsAcknowledged, ClosureCause, HostError, RefusedOpen};
use crate::foundation::coordination::{LeaseKind, SandboxState};
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{ContentKey, SandboxBootGeneration};
use crate::foundation::transfer::{AuthorityPort, ParentStatus};
use crate::sandbox::audit::verify_segments;
use crate::sandbox::backend::VmBackend as _;
use crate::sandbox::guest_files::{BodyPhase, FilesEvent};
use crate::sandbox::lifecycle::{
    AckEffect, Acknowledgment, CleanupReport, LaunchReceipt, LogicalCleanupAction,
    ObservedReadiness, RevocationCause, SandboxClass, SupervisorError,
};
use crate::sandbox::link::{
    CancelCause, CloseReason, FileMode, LinkMessage, OpenRefusalCause, ReportBody,
};

/// The whole life of one task sandbox through the host: the launch transaction, its
/// channels bound to the VM the coordinator recorded, guest-file traffic over the link, the
/// first command, a revocation that closes the channels and, once the lease holder let go,
/// stops the VM through its handle, the cleanup and the teardown, with every lifecycle
/// receipt and the launch record in the durable audit stream under one operation.
#[test]
fn a_task_runs_from_launch_to_first_command_to_revocation_to_teardown() {
    let mut world = World::new();
    let exe = execution("exe-task");
    let boot = world.launch("exe-task", SandboxClass::Task);
    let vm = world.vm("exe-task");
    assert!(
        world.host().session(&exe).is_none(),
        "no channel before it is opened"
    );

    // The channels are the boot's: the VM instance and boot the coordinator recorded, the
    // handle the supervisor keeps, the sandbox's tenant and execution.
    let hello = world.open("exe-task");
    let session = world.host().session(&exe).unwrap();
    assert_eq!(session.vm(), vm);
    assert_eq!(session.boot(), boot);
    assert_eq!(
        session.handle(),
        world.host().supervisor().handles().get(&vm).unwrap()
    );
    let link = session.link().unwrap();
    assert_eq!(link.binding().vm(), vm);
    assert_eq!(link.binding().boot(), boot);
    let identity = session.files().identity();
    assert_eq!(identity.parent, exe);
    assert_eq!(identity.tenant, tenant());
    assert_eq!((identity.vm, identity.boot), (vm, boot));
    assert!(session.link_is_open());
    // The guest's hello is its word, a guest report.
    assert_eq!(hello.reports.len(), 1);
    assert_eq!(hello.reports[0].source(), SourceClass::GuestReport);
    assert!(matches!(hello.reports[0].body(), ReportBody::Hello(_)));

    // Guest-file traffic: a create on its own stream reaches the file service and is
    // answered on the same link.
    let text = b"notes from the guest".to_vec();
    let events = world.call("exe-task", 1, 7, create("notes.txt", &text));
    assert_eq!(
        events,
        vec![
            FilesEvent::Opened {
                grant: GRANT,
                stream: stream(1)
            },
            FilesEvent::Performed {
                grant: GRANT,
                stream: stream(1),
                request: id(7)
            },
        ]
    );
    assert_eq!(
        outcome(&world.drain("exe-task"), 1),
        json!({"kind": "created"})
    );
    assert_eq!(
        fs::read(world.root("exe-task").join("notes.txt")).unwrap(),
        text
    );

    // The first command, over the open link; then child work on fresh readiness.
    world.advance(2 * SECOND);
    assert_eq!(world.host_mut().first_command(&exe).unwrap(), 2 * SECOND);
    assert_eq!(world.state("exe-task"), SandboxState::Running);
    let lease = world
        .host_mut()
        .authorize_work(
            &exe,
            operation("op-tool"),
            LeaseKind::ChildWork,
            call(),
            BTreeSet::new(),
        )
        .unwrap();
    world.host_mut().take_log();

    // The revocation: the channels close at once and are acknowledged as closed; the VM
    // waits for the lease holder.
    world.advance(SECOND);
    let progress = world
        .host_mut()
        .revoke(&exe, RevocationCause::UserRequested)
        .unwrap();
    assert!(!progress.acknowledged.contains(&Acknowledgment::VmStopped));
    assert!(progress
        .acknowledged
        .contains(&Acknowledgment::ChannelsClosed));
    let log = world.host_mut().take_log();
    let closure = log.closure_of(&exe).unwrap();
    assert_eq!(closure.cause, ClosureCause::Revoked);
    assert_eq!((closure.vm, closure.boot), (vm, boot));
    assert_eq!(closure.at, at(103));
    assert_eq!(closure.grants, vec![GRANT]);
    assert_eq!(closure.files.last(), Some(&FilesEvent::LinkLost));
    assert_eq!(closure.link_closed_before, None);
    assert_eq!(closure.close_refused, None);
    // The guest reads the close frame, and nothing queued before it.
    let messages = world.guest("exe-task").read(&closure.final_frames);
    assert_eq!(
        messages,
        vec![LinkMessage::Close {
            reason: CloseReason::Revoked
        }]
    );
    assert_eq!(
        log.acknowledgments,
        vec![ChannelsAcknowledged {
            execution: exe.clone(),
            at: at(103),
            transport_end: None,
            outcome: Ok(AckEffect::Recorded)
        }]
    );
    let run = world.host().supervisor().revocation(&exe).unwrap();
    assert_eq!(
        run.elapsed(Acknowledgment::ChannelsClosed),
        Some(Duration::ZERO)
    );
    // The boot takes no further guest byte, and no new work is authorized.
    assert_eq!(
        world.try_send("exe-task", LinkMessage::Ping { nonce: 1 }),
        Err(HostError::ChannelsClosed {
            execution: exe.clone(),
            boot
        })
    );
    assert!(matches!(
        world.host_mut().authorize_work(
            &exe,
            operation("op-late"),
            LeaseKind::ChildWork,
            call(),
            BTreeSet::new()
        ),
        Err(HostError::Supervisor(SupervisorError::Revoked { .. }))
    ));
    assert_eq!(
        world.stops_of("exe-task"),
        0,
        "nothing stops before the gate"
    );

    // The lease holder lets go; the VM stops through its handle.
    world.advance(SECOND);
    world
        .host_mut()
        .with_supervisor(|supervisor, _, _| {
            supervisor
                .coordinator_mut()
                .acknowledge_cancellation(lease.id())
        })
        .unwrap();
    let progress = world.host_mut().advance(&exe).unwrap();
    assert!(progress.acknowledged.contains(&Acknowledgment::VmStopped));
    assert_eq!(world.state("exe-task"), SandboxState::Stopped);
    assert_eq!(world.stops_of("exe-task"), 1);
    assert!(!world.host().backend().running().contains(&vm));

    // Cleanup, then teardown of the boot's objects.
    world.advance(SECOND);
    let late = world.host_mut().with_supervisor(|supervisor, _, _| {
        supervisor.finish_cleanup(
            &exe,
            CleanupReport::logical([LogicalCleanupAction::OverlayDeleted]),
        )
    });
    assert_eq!(late, Ok(false));
    let report = world.host_mut().teardown(&exe).unwrap();
    assert_eq!((report.vm, report.boot), (vm, boot));
    assert_eq!(report.counters.opened, 1);
    assert_eq!(report.counters.performed, 1);
    assert_eq!(report.closed_at, Some(at(103)));
    assert!(world.host().session(&exe).is_none());

    // The durable stream holds the whole lifecycle, chained from genesis, under one
    // operation, and the sink refused nothing.
    let log = world.host_mut().take_log();
    assert_eq!(log.audit.refused(), 0);
    verify_segments(&genesis(), &world.segments()).unwrap();
    assert_eq!(
        world.labels(),
        [
            "launched",
            "launch_record",
            "first_command",
            "revocation",
            "acknowledged channels_closed",
            "acknowledged new_authorizations_denied",
            "vm_stopped",
            "cleanup_finished",
        ]
    );
    let operations: BTreeSet<_> = world
        .records()
        .iter()
        .map(|record| record.event().operation().clone())
        .collect();
    assert_eq!(operations.len(), 1);
    assert_eq!(world.host().sink().totals().uncorrelated, 0);
}

/// A revocation while the guest moves a large body: taking the grant off the file channel
/// cancels the stream as revoked and ends the body's CORE-05 transfer, its reservation is
/// released and nothing is written; the link closes with the revocation, so the guest's
/// next part never reaches the adapter, and with no lease outstanding the VM stops in the
/// same call. The transfer's own authority port was never told: the closure ended it.
#[test]
fn a_revocation_during_a_guest_file_body_cancels_it_and_writes_nothing() {
    let mut world = World::new();
    let exe = execution("exe-task");
    world.launch("exe-task", SandboxClass::Task);
    world.open("exe-task");
    let body = pattern(200_000, 1);
    let parts = messages(9, create("big.bin", &body));
    assert!(parts.len() >= 4);
    let opened = world.open_file("exe-task", 1, content_entry(&body), FileMode::Write);
    assert_eq!(
        opened.files,
        vec![FilesEvent::Opened {
            grant: GRANT,
            stream: stream(1)
        }]
    );
    let first = world.data("exe-task", 1, &parts[0]);
    assert_eq!(
        phases(&first.files),
        vec![BodyPhase::Opened {
            length_bytes: 200_000
        }]
    );
    world.data("exe-task", 1, &parts[1]);
    assert_eq!(world.ledger.held_bytes(), 200_000);
    let requested = world.issuer.requests();
    assert_eq!(requested.len(), 1);
    assert_eq!(requested[0].parent, exe);
    assert_eq!(requested[0].object, ContentKey::of(&body));
    let view = world
        .host()
        .session(&exe)
        .unwrap()
        .files()
        .body(GRANT, id(9))
        .unwrap();
    assert!(view.held_bytes > 0 && view.held_bytes < 200_000);
    world.host_mut().take_log();

    world.advance(SECOND);
    let progress = world
        .host_mut()
        .revoke(&exe, RevocationCause::Violation)
        .unwrap();
    assert!(progress
        .acknowledged
        .contains(&Acknowledgment::ChannelsClosed));
    assert!(progress.acknowledged.contains(&Acknowledgment::VmStopped));
    assert_eq!(world.state("exe-task"), SandboxState::Stopped);
    assert_eq!(world.stops_of("exe-task"), 1);

    let log = world.host_mut().take_log();
    let closure = log.closure_of(&exe).unwrap();
    assert_eq!(closure.cause, ClosureCause::Revoked);
    assert!(closure.files.contains(&FilesEvent::HostCancelled {
        grant: GRANT,
        stream: stream(1),
        cause: CancelCause::Revoked
    }));
    assert_eq!(phases(&closure.files), vec![BodyPhase::Cancelled]);
    assert_eq!(world.ledger.held_bytes(), 0);
    assert_eq!(world.ledger.releases().len(), 1);
    assert!(!world.root("exe-task").join("big.bin").exists());
    // The cancel the adapter queued went with the link: the guest reads only the close.
    let messages = world.guest("exe-task").read(&closure.final_frames);
    assert_eq!(cancel_of(&messages, 1), None);
    assert_eq!(close_reason(&messages), Some(CloseReason::Revoked));
    assert!(matches!(
        world.try_data("exe-task", 1, &parts[2]),
        Err(HostError::ChannelsClosed { .. })
    ));
    assert!(world.authority.calls() > 0);
    assert!(matches!(
        world.authority.parent_status(&exe),
        ParentStatus::Authorized { .. }
    ));

    // The revocation, its acknowledgment and the stop are in the durable stream.
    verify_segments(&genesis(), &world.segments()).unwrap();
    let labels = world.labels();
    let tail: Vec<&str> = labels[2..].iter().map(String::as_str).collect();
    assert_eq!(
        tail,
        ["revocation", "acknowledged channels_closed", "vm_stopped"]
    );
}

/// Launch-time evidence goes stale: the host asks the backend to observe again before it
/// authorizes work, finds the VM not ready and refuses; a guest's new file stream is then
/// refused by the host itself while the channels stay open, and guest traffic never makes
/// the host observe again. Once the probe and the backend observe again, work and new file
/// streams are served.
#[test]
fn stale_evidence_refuses_new_work_and_new_file_streams_until_observed_again() {
    let mut world = World::new();
    let exe = execution("exe-task");
    world.launch("exe-task", SandboxClass::Task);
    world.open("exe-task");
    assert_eq!(
        world.call("exe-task", 1, 1, list()).last(),
        Some(&FilesEvent::Performed {
            grant: GRANT,
            stream: stream(1),
            request: id(1)
        })
    );
    world.drain("exe-task");

    // The record's facts and the CORE-01 evidence age past the minute the profile needs.
    world.advance(MINUTE + SECOND);
    let before = world.reobserves();
    let refused = world
        .host_mut()
        .authorize_work(
            &exe,
            operation("op-stale"),
            LeaseKind::ChildWork,
            call(),
            BTreeSet::new(),
        )
        .unwrap_err();
    assert!(
        matches!(
            &refused,
            HostError::Supervisor(SupervisorError::ReadinessUnavailable { .. })
        ),
        "{refused:?}"
    );
    assert_eq!(world.reobserves(), before + 1);
    assert!(world
        .host()
        .supervisor()
        .sandbox(&exe)
        .unwrap()
        .readiness
        .is_unavailable());

    let opened_before = world
        .host()
        .session(&exe)
        .unwrap()
        .files()
        .counters()
        .opened;
    let delivery = world.open_file("exe-task", 3, entry("list"), FileMode::Read);
    assert_eq!(
        delivery.refused_opens,
        vec![RefusedOpen {
            stream: stream(3),
            grant: GRANT,
            unsent: None
        }]
    );
    assert!(delivery.files.is_empty());
    assert_eq!(
        open_refused(&world.drain("exe-task"), 3),
        Some(OpenRefusalCause::Unavailable)
    );
    let session = world.host().session(&exe).unwrap();
    assert_eq!(session.files().counters().opened, opened_before);
    assert!(session.is_open() && session.link_is_open());
    assert_eq!(
        world.reobserves(),
        before + 1,
        "guest traffic observes nothing"
    );
    assert_eq!(world.state("exe-task"), SandboxState::AuthorityActive);

    // Fresh evidence: the probe observes again, then the backend; work and streams resume.
    world.observe_hypervisor(true);
    assert!(matches!(
        world.host_mut().observe_readiness(&exe).unwrap(),
        ObservedReadiness::Ready { .. }
    ));
    assert!(world
        .host_mut()
        .authorize_work(
            &exe,
            operation("op-fresh"),
            LeaseKind::ChildWork,
            call(),
            BTreeSet::new()
        )
        .is_ok());
    assert_eq!(
        world.call("exe-task", 5, 2, list()).last(),
        Some(&FilesEvent::Performed {
            grant: GRANT,
            stream: stream(5),
            request: id(2)
        })
    );
    assert_eq!(outcome(&world.drain("exe-task"), 5)["kind"], "listed");
}

/// A restart of the supervisor's process: shutting down closes every channel with a
/// shutdown frame; recovery checks every handle through the backend, ends the task found
/// alive and keeps the service without authority, so no channel opens until the service is
/// reauthorized. New channels then bind the same VM instance and boot, the file the guest
/// wrote before the restart is read back over them, and the audit stream continues the
/// same chain without giving a launch record twice.
#[test]
fn recovery_after_a_supervisor_restart_reopens_only_reauthorized_channels() {
    let mut world = World::new();
    let task = execution("exe-task");
    let service = execution("exe-service");
    world.launch("exe-task", SandboxClass::Task);
    world.open("exe-task");
    let boot = world.launch("exe-service", SandboxClass::Service);
    world.open("exe-service");
    let text = b"kept across the restart".to_vec();
    world.call("exe-service", 1, 1, create("kept.txt", &text));
    assert_eq!(
        outcome(&world.drain("exe-service"), 1),
        json!({"kind": "created"})
    );
    let (task_vm, service_vm) = (world.vm("exe-task"), world.vm("exe-service"));
    world.host_mut().take_log();
    world.advance(10 * SECOND);

    let (report, shutdown) = world.restart();
    assert_eq!(shutdown.closures.len(), 2);
    assert!(shutdown
        .closures
        .iter()
        .all(|closure| closure.cause == ClosureCause::Shutdown && closure.close_refused.is_none()));
    let closure = shutdown.closure_of(&service).unwrap();
    assert_eq!(
        GuestEnd::new(service_vm, boot, secret("exe-service")).read(&closure.final_frames),
        vec![LinkMessage::Close {
            reason: CloseReason::Shutdown
        }]
    );

    assert_eq!(report.tasks_ended, std::slice::from_ref(&task));
    assert_eq!(
        report.services_awaiting_reauthorization,
        std::slice::from_ref(&service)
    );
    assert!(report.handles_reused.is_empty() && report.handles_gone.is_empty());
    assert!(!world.host().backend().running().contains(&task_vm));
    assert!(world.host().backend().running().contains(&service_vm));
    assert_eq!(world.host().sessions().count(), 0);
    assert_eq!(world.state("exe-service"), SandboxState::VmCreated);
    let setup = world.setup("exe-service");
    assert_eq!(
        world.host_mut().open_channels(&service, setup),
        Err(HostError::NoAuthority {
            execution: service.clone(),
            state: SandboxState::VmCreated
        })
    );

    let admitted = world.admit();
    assert!(matches!(
        world.host_mut().reauthorize(&service, admitted).unwrap(),
        LaunchReceipt::AuthorityActive { boot: again, .. } if again == boot
    ));
    world.open("exe-service");
    let session = world.host().session(&service).unwrap();
    assert_eq!((session.vm(), session.boot()), (service_vm, boot));
    world.call("exe-service", 1, 2, read("kept.txt"));
    assert_eq!(content(&world.drain("exe-service"), 1), text);
    let setup = world.setup("exe-task");
    assert_eq!(
        world.host_mut().open_channels(&task, setup),
        Err(HostError::NoAuthority {
            execution: task.clone(),
            state: SandboxState::Stopped
        })
    );

    verify_segments(&genesis(), &world.segments()).unwrap();
    let labels = world.labels();
    assert_eq!(
        labels
            .iter()
            .filter(|label| *label == "launch_record")
            .count(),
        2,
        "{labels:?}"
    );
    assert_eq!(world.host_mut().take_log().audit.refused(), 0);
}

/// A revocation the supervisor decides itself, here the engine's death through
/// `with_supervisor`, closes that boot's channels and acknowledges them closed like the
/// host's own revocation; the service the engine's death leaves running keeps its channels
/// and its guest keeps reaching its files.
#[test]
fn a_revocation_the_supervisor_decides_itself_closes_only_that_boots_channels() {
    let mut world = World::new();
    let task = execution("exe-task");
    let service = execution("exe-service");
    world.launch("exe-task", SandboxClass::Task);
    world.open("exe-task");
    world.launch("exe-service", SandboxClass::Service);
    world.open("exe-service");
    world.host_mut().take_log();

    world.advance(SECOND);
    let report = world
        .host_mut()
        .with_supervisor(|supervisor, port, _| supervisor.engine_died(port))
        .unwrap();
    assert_eq!(report.ended, std::slice::from_ref(&task));
    assert_eq!(report.continued, std::slice::from_ref(&service));
    let log = world.host_mut().take_log();
    assert_eq!(log.closures.len(), 1);
    assert_eq!(log.closures[0].execution, task);
    assert_eq!(log.closures[0].cause, ClosureCause::Revoked);
    assert_eq!(
        log.acknowledgments,
        vec![ChannelsAcknowledged {
            execution: task.clone(),
            at: at(101),
            transport_end: None,
            outcome: Ok(AckEffect::Recorded)
        }]
    );
    assert_eq!(log.advances.len(), 1);
    assert!(log.advances[0].outcome.is_ok());
    assert_eq!(world.state("exe-task"), SandboxState::Stopped);
    assert!(matches!(
        world.try_send("exe-task", LinkMessage::Ping { nonce: 2 }),
        Err(HostError::ChannelsClosed { .. })
    ));

    assert!(world.host().session(&service).unwrap().is_open());
    assert_eq!(
        world.call("exe-service", 1, 1, list()).last(),
        Some(&FilesEvent::Performed {
            grant: GRANT,
            stream: stream(1),
            request: id(1)
        })
    );
    assert!(world.host_mut().teardown(&task).is_ok());
    assert!(matches!(
        world.host_mut().teardown(&service),
        Err(HostError::NotStopped { .. })
    ));
}

/// A boot's channels open once, only while it holds authority, bound to its identity: a
/// guest end keyed for another boot of the same instance is not the bound guest and the
/// link closes on its first frame; no command counts while the link is closed; a new link
/// of the same boot replaces the closed one and the file channel follows it; and once the
/// host closed the boot's channels nothing opens them again.
#[test]
fn channels_open_once_for_a_boot_that_holds_authority_and_bind_its_identity() {
    let mut world = World::new();
    let exe = execution("exe-task");
    let setup = world.setup("exe-task");
    assert_eq!(
        world.host_mut().open_channels(&exe, setup),
        Err(HostError::UnknownSandbox {
            execution: exe.clone()
        })
    );
    let boot = world.launch("exe-task", SandboxClass::Task);
    world.open("exe-task");
    let setup = world.setup("exe-task");
    assert_eq!(
        world.host_mut().open_channels(&exe, setup),
        Err(HostError::ChannelsOpen {
            execution: exe.clone(),
            boot
        })
    );

    let other_boot = SandboxBootGeneration::new(boot.get() + 1);
    let mut stranger = GuestEnd::new(world.vm("exe-task"), other_boot, secret("exe-task"));
    let frame = stranger.frame(&LinkMessage::Ping { nonce: 9 });
    let delivery = world.host_mut().receive(&exe, &frame).unwrap();
    assert!(delivery.closed.is_some(), "{delivery:?}");
    assert!(delivery.files.contains(&FilesEvent::LinkLost));
    let session = world.host().session(&exe).unwrap();
    assert!(session.is_open() && !session.link_is_open());
    assert_eq!(
        world.host_mut().first_command(&exe),
        Err(HostError::LinkNotOpen {
            execution: exe.clone()
        })
    );

    world.reconnect("exe-task");
    let nonce = world.next_nonce("exe-task");
    assert_eq!(
        world.host_mut().reconnect(&exe, secret("exe-task"), nonce),
        Err(HostError::LinkOpen {
            execution: exe.clone(),
            boot
        })
    );
    assert_eq!(world.host_mut().first_command(&exe), Ok(Duration::ZERO));
    assert_eq!(
        world.call("exe-task", 1, 1, list()).last(),
        Some(&FilesEvent::Performed {
            grant: GRANT,
            stream: stream(1),
            request: id(1)
        })
    );

    world
        .host_mut()
        .revoke(&exe, RevocationCause::UserRequested)
        .unwrap();
    let closure = world.host_mut().take_log().closures.remove(0);
    assert_eq!(closure.link_closed_before, None);
    assert_eq!(
        close_reason(&world.guest("exe-task").read(&closure.final_frames)),
        Some(CloseReason::Revoked)
    );
    assert_eq!(world.state("exe-task"), SandboxState::Stopped);
    let setup = world.setup("exe-task");
    assert_eq!(
        world.host_mut().open_channels(&exe, setup),
        Err(HostError::NoAuthority {
            execution: exe.clone(),
            state: SandboxState::Stopped
        })
    );
    let nonce = world.next_nonce("exe-task");
    assert_eq!(
        world.host_mut().reconnect(&exe, secret("exe-task"), nonce),
        Err(HostError::ChannelsClosed {
            execution: exe.clone(),
            boot
        })
    );
}
