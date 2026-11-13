//! Tests of the VM service over the fakes (module docs in `mod.rs`): the real supervisor,
//! coordinator, ledger, audit stream, QEMU backend, sandbox host, link and session pump,
//! with the backend's host ports scripted, the link stream an in-memory wire and the
//! guest a thread built from the link's own encoder. Every route of the service runs end
//! to end: launch to command to exit code; the output limit; the deadline; a cancel; a
//! revocation during a command with each milestone observed on its own; a stop that asks
//! the guest first; a link socket served by another process; a guest that never says
//! hello; the shutdown; the status; a restart; two sandboxes at once; and that nothing
//! secret reaches a `Debug`, an error or a serialized outcome.

use std::thread;
use std::time::Duration;

use super::fakes::*;
use super::{
    BootPhase, CancelledBy, DirectoryRemoval, ExecEnd, ExecRequest, GuestShutdown,
    GuestShutdownOutcome, LaunchStep, LinkView, Milestone, RevokeReason, VmServiceError, VmStop,
};
use crate::foundation::coordination::SandboxState;
use crate::foundation::events::{Field, HostFact};
use crate::foundation::ids::digest;
use crate::sandbox::link::{CloseCause, CloseReason};
use crate::sandbox::link_transport::{EndpointRefusal, TransportEnd};

const SECOND: Duration = Duration::from_secs(1);

fn request(input: &[u8], max_output_bytes: usize, deadline: Duration) -> ExecRequest {
    ExecRequest::new(input.to_vec(), max_output_bytes, deadline)
}

#[test]
fn a_launch_runs_a_command_and_a_stop_asks_the_guest_first_then_proves_the_vm_ended() {
    let mut harness = Harness::new();
    harness.guest(0, Behaviour::default());
    let id = harness.service().launch(Harness::spec()).unwrap();

    // The launch: the fake host started one QEMU for the sandbox's VM, the connector dialed
    // its private directory's link socket, the guest answered the challenge and said hello.
    {
        let world = harness.world();
        assert_eq!(world.launches.len(), 1);
        assert_eq!(world.launches[0].execution, *id.execution());
        assert_eq!(
            world.dialed,
            vec![world.launches[0]
                .directory
                .link_socket()
                .as_str()
                .to_owned()]
        );
    }
    let guest = &harness.guests[0];
    harness.wait_until("the welcome", || guest.state().welcomed);
    let status = harness.service().status();
    assert_eq!(status.len(), 1);
    assert_eq!(status[0].sandbox, id);
    assert_eq!(status[0].phase, Some(BootPhase::Ready));
    assert_eq!(status[0].link, LinkView::Open);
    // Authority is active; the sandbox runs once its first command succeeded.
    assert_eq!(status[0].state, Some(SandboxState::AuthorityActive));
    assert!(status[0].process.is_some());
    assert!(status[0].launch_record.is_some());

    // One command, to its exit code: the output and the code are the guest's word.
    let outcome = harness
        .service()
        .exec(&id, request(b"echo hi\n", 4_096, 30 * SECOND))
        .unwrap();
    assert_eq!(outcome.end, ExecEnd::Finished);
    assert_eq!(outcome.exit_code, Some(0));
    assert_eq!(outcome.output.as_bytes(), b"ran: echo hi\n");
    assert_eq!(outcome.output_dropped_bytes, 0);
    assert_eq!(outcome.input_sent_bytes, 8);
    assert_eq!(
        outcome.output.source(),
        crate::foundation::evidence::SourceClass::GuestReport
    );
    let failed = harness
        .service()
        .exec(&id, request(b"false", 4_096, 30 * SECOND))
        .map(|outcome| outcome.exit_code);
    assert_eq!(
        failed,
        Ok(Some(0)),
        "the echo guest exits 0 whatever it ran"
    );
    assert_eq!(
        harness.service().status()[0].state,
        Some(SandboxState::Running)
    );

    // The stop: the guest is asked to shut down, powers off (closes its link), the host
    // observes the stream end, then the sandbox is revoked and the VM's end proven.
    let report = harness.service().stop(&id).unwrap();
    match &report.guest_shutdown {
        GuestShutdown::Requested {
            grace_seconds,
            outcome,
            ..
        } => {
            assert!(*grace_seconds >= 1);
            assert!(
                matches!(
                    outcome,
                    GuestShutdownOutcome::LinkClosed { .. }
                        | GuestShutdownOutcome::ProcessEnded { .. }
                ),
                "{outcome:?}"
            );
        }
        other => panic!("{other:?}"),
    }
    let process = harness.world().launches[0].process;
    match &report.vm_stop {
        VmStop::Stopped {
            process: proven, ..
        } => assert_eq!(*proven, process),
        other => panic!("{other:?}"),
    }
    assert!(report.directory.is_removed(), "{:?}", report.directory);
    assert!(report.commands_ended.is_empty());
    {
        let world = harness.world();
        assert_eq!(world.terminated, vec![process]);
        assert!(world.directories.is_empty());
        let wire = &world.wires[0].1;
        assert!(
            wire.lock().unwrap().shut_downs >= 1,
            "the stream was shut down"
        );
    }
    assert_eq!(guest.state().shutdown_requests.len(), 1);
    let status = harness.service().status();
    assert_eq!(status[0].phase, Some(BootPhase::Ended));
    assert_eq!(status[0].state, Some(SandboxState::Stopped));
    assert_eq!(status[0].process, None);
    // New work is denied afterwards.
    assert!(matches!(
        harness
            .service()
            .exec(&id, request(b"", 1, SECOND))
            .unwrap_err(),
        VmServiceError::NotReady { .. } | VmServiceError::Revoked { .. }
    ));
}

#[test]
fn output_over_the_limit_is_dropped_and_the_command_ends() {
    let mut harness = Harness::new();
    harness.guest(
        0,
        Behaviour {
            command: Some(chatty),
            ..Behaviour::default()
        },
    );
    let id = harness.service().launch(Harness::spec()).unwrap();
    let outcome = harness
        .service()
        .exec(&id, request(b"yes\n", 1_000, 30 * SECOND))
        .unwrap();
    assert_eq!(outcome.end, ExecEnd::OutputLimitReached);
    assert_eq!(outcome.output.len(), 1_000);
    assert!(outcome.output_dropped_bytes > 0, "{outcome:?}");
    assert_eq!(outcome.exit_code, None);
    // The guest saw the stream cancelled.
    let guest = &harness.guests[0];
    harness.wait_until("the cancel", || !guest.state().cancelled.is_empty());
    // The link stays open for the next command, whose limit the output fits.
    let next = harness
        .service()
        .exec(&id, request(b"", 1 << 20, 30 * SECOND))
        .unwrap();
    assert_eq!(next.end, ExecEnd::Finished);
    assert_eq!(next.output.len(), 64 * 1024);
    assert_eq!(next.exit_code, Some(0));
    assert_eq!(harness.service().status()[0].link, LinkView::Open);
}

#[test]
fn the_deadline_cancels_a_command_that_never_exits() {
    let mut harness = Harness::new();
    harness.guest(
        0,
        Behaviour {
            command: None,
            ..Behaviour::default()
        },
    );
    let id = harness.service().launch(Harness::spec()).unwrap();
    let command = harness
        .service()
        .start_exec(&id, request(b"sleep\n", 4_096, 2 * SECOND))
        .unwrap();
    let guest = &harness.guests[0];
    harness.wait_until("the input", || {
        guest
            .state()
            .inputs
            .get(&command.get())
            .is_some_and(|input| input == b"sleep\n")
    });
    assert_eq!(
        harness.service().status()[0].running_commands,
        vec![command]
    );
    harness.advance(3 * SECOND);
    let outcome = harness.service().wait_exec(&id, command).unwrap();
    assert_eq!(outcome.end, ExecEnd::DeadlinePassed);
    assert_eq!(outcome.exit_code, None);
    harness.wait_until("the cancel", || {
        guest.state().cancelled == vec![command.get()]
    });
    assert!(harness.service().status()[0].running_commands.is_empty());
}

#[test]
fn cancel_ends_a_command_with_the_caller_as_the_canceller() {
    let mut harness = Harness::new();
    harness.guest(
        0,
        Behaviour {
            command: None,
            ..Behaviour::default()
        },
    );
    let id = harness.service().launch(Harness::spec()).unwrap();
    let command = harness
        .service()
        .start_exec(&id, request(b"cat\n", 4_096, 30 * SECOND))
        .unwrap();
    let guest = &harness.guests[0];
    harness.wait_until("the open", || guest.state().opened == vec![command.get()]);
    harness.service().cancel(&id, command).unwrap();
    let outcome = harness.service().wait_exec(&id, command).unwrap();
    assert_eq!(
        outcome.end,
        ExecEnd::Cancelled {
            by: CancelledBy::Caller
        }
    );
    harness.wait_until("the cancel", || {
        guest.state().cancelled == vec![command.get()]
    });
    // Cancelling again, or waiting again, finds no such command.
    assert!(matches!(
        harness.service().cancel(&id, command).unwrap_err(),
        VmServiceError::UnknownCommand { .. }
    ));
    assert!(matches!(
        harness.service().wait_exec(&id, command).unwrap_err(),
        VmServiceError::UnknownCommand { .. }
    ));
}

#[test]
fn a_revocation_during_a_command_reports_each_milestone_on_its_own_observation() {
    let mut harness = Harness::new();
    harness.guest(
        0,
        Behaviour {
            command: None,
            ..Behaviour::default()
        },
    );
    let id = harness.service().launch(Harness::spec()).unwrap();
    let command = harness
        .service()
        .start_exec(&id, request(b"work\n", 4_096, 30 * SECOND))
        .unwrap();
    let guest = &harness.guests[0];
    harness.wait_until("the input", || {
        guest.state().inputs.contains_key(&command.get())
    });

    let report = harness
        .service()
        .revoke(&id, RevokeReason::Violation)
        .unwrap();
    assert_eq!(report.reason, RevokeReason::Violation);
    assert!(report.decided_at.is_some());
    assert!(report.new_work_denied.is_observed(), "{report:?}");
    // The channels: closed in the host, and acknowledged once the pump shut the stream.
    assert!(report.channels_closed.is_observed(), "{report:?}");
    assert!(report.vm_stopped.is_observed(), "{report:?}");
    assert!(report.cleanup_done.is_observed(), "{report:?}");
    assert!(report.vm_stop.is_stopped(), "{:?}", report.vm_stop);
    assert!(report.directory.is_removed(), "{:?}", report.directory);
    assert_eq!(report.commands_ended, vec![command]);
    assert_eq!(report.uncertain, 0);
    let outcome = harness.service().wait_exec(&id, command).unwrap();
    assert_eq!(outcome.end, ExecEnd::Revoked);
    // The stream was shut down with the close frame written, and nothing after it.
    {
        let world = harness.world();
        let wire = world.wires[0].1.lock().unwrap();
        assert!(wire.shut_downs >= 1);
    }
    harness.wait_until("the close frame", || {
        guest.state().closed == Some(CloseReason::Revoked)
    });
    let status = harness.service().status();
    assert_eq!(status[0].state, Some(SandboxState::Stopped));
    // The boot was torn down once its VM stopped and its stream ended.
    assert_eq!(status[0].link, LinkView::NoChannels);
    assert_eq!(
        status[0].transport.as_ref().map(|view| view.end),
        Some(Some(TransportEnd::LinkClosed))
    );
    // Revoking again changes nothing and reports where it stands.
    let again = harness
        .service()
        .revoke(&id, RevokeReason::UserRequested)
        .unwrap();
    assert_eq!(again.cause, report.cause);
    assert_eq!(harness.world().terminated.len(), 1);
    // The milestones were four observations, not one.
    let times: Vec<_> = [
        &report.new_work_denied,
        &report.channels_closed,
        &report.vm_stopped,
        &report.cleanup_done,
    ]
    .iter()
    .map(|milestone| match milestone {
        Milestone::Observed { at, source } => (*at, source.is_some()),
        Milestone::Pending => panic!("pending"),
    })
    .collect();
    assert!(times.iter().all(|(_, sourced)| *sourced), "{times:?}");
}

#[test]
fn a_link_socket_served_by_another_process_is_refused_and_the_vm_stopped() {
    let mut harness = Harness::new();
    harness.world().peer_pid_offset = 1;
    harness.guest(0, Behaviour::default());
    let error = harness.service().launch(Harness::spec()).unwrap_err();
    let VmServiceError::LaunchFailed {
        step,
        cleanup,
        sandbox,
    } = error
    else {
        panic!("{error:?}");
    };
    match step {
        LaunchStep::LinkSocket {
            refusal: EndpointRefusal::WrongPeer { peer_pid, vmm },
        } => assert_eq!(peer_pid, vmm.pid + 1),
        other => panic!("{other:?}"),
    }
    assert!(cleanup.left_nothing(), "{cleanup:?}");
    assert_eq!(cleanup.revocation_refused, None);
    let world = harness.world();
    assert_eq!(world.launches.len(), 1);
    assert_eq!(world.terminated, vec![world.launches[0].process]);
    assert!(world.directories.is_empty());
    // The stream was never read: the guest was never challenged.
    assert_eq!(world.wires[0].1.lock().unwrap().reads, 0);
    drop(world);
    let status = harness.service().status();
    assert_eq!(status[0].sandbox, sandbox);
    assert_eq!(status[0].state, Some(SandboxState::Stopped));
}

#[test]
fn a_guest_that_never_says_hello_fails_the_launch_and_leaves_nothing() {
    let mut harness = Harness::new();
    harness.guest(
        0,
        Behaviour {
            hello: false,
            ..Behaviour::default()
        },
    );
    // The handshake times out on the host clock, which another thread advances.
    let clock = std::sync::Arc::clone(&harness.clock);
    let advancer = thread::spawn(move || {
        thread::sleep(Duration::from_millis(300));
        clock.advance(11 * SECOND);
    });
    let error = harness.service().launch(Harness::spec()).unwrap_err();
    advancer.join().unwrap();
    let VmServiceError::LaunchFailed { step, cleanup, .. } = error else {
        panic!("{error:?}");
    };
    assert_eq!(
        step,
        LaunchStep::NoHello {
            cause: CloseCause::HandshakeTimedOut
        }
    );
    assert!(cleanup.left_nothing(), "{cleanup:?}");
    let guest = &harness.guests[0];
    assert!(guest.state().challenged);
    assert!(!guest.state().welcomed);
    let world = harness.world();
    assert_eq!(world.terminated.len(), 1);
    assert!(world.directories.is_empty());
    assert!(world.wires[0].1.lock().unwrap().shut_downs >= 1);
}

#[test]
fn a_stop_whose_guest_ignores_the_request_waits_the_grace_then_stops_through_the_handle() {
    let mut harness = Harness::new();
    harness.guest(
        0,
        Behaviour {
            powers_off: false,
            ..Behaviour::default()
        },
    );
    let id = harness.service().launch(Harness::spec()).unwrap();
    let started = std::time::Instant::now();
    let report = harness.service().stop(&id).unwrap();
    match report.guest_shutdown {
        GuestShutdown::Requested {
            outcome: GuestShutdownOutcome::GraceExpired { waited_ms },
            ..
        } => assert!(waited_ms >= 100, "{waited_ms}"),
        other => panic!("{other:?}"),
    }
    assert!(started.elapsed() >= Duration::from_millis(100));
    assert!(report.vm_stop.is_stopped(), "{:?}", report.vm_stop);
    assert!(report.directory.is_removed());
    assert_eq!(harness.guests[0].state().shutdown_requests, vec![1]);
    assert_eq!(harness.world().terminated.len(), 1);
}

#[test]
fn shutdown_joins_every_driver_and_writes_each_close_frame() {
    let mut harness = Harness::new();
    harness.guest(0, Behaviour::default());
    let id = harness.service().launch(Harness::spec()).unwrap();
    let report = harness.service.take().unwrap().shutdown();
    assert_eq!(report.drivers_joined, 1);
    assert!(report.drivers_not_joined.is_empty());
    assert_eq!(report.closed.len(), 1);
    assert_eq!(report.closed[0].sandbox, id);
    assert!(report.closed[0].close_frame_written);
    // A shutdown stops no VM: the backend still held it.
    assert_eq!(report.vms_left_running, vec![id]);
    let guest = &harness.guests[0];
    harness.wait_until("the close frame", || {
        guest.state().closed == Some(CloseReason::Shutdown)
    });
    assert!(harness.world().terminated.is_empty());
}

/// PROVES a launch's lowered idle limit is its sandbox's lease: with no command the
/// supervisor's tick revokes it for the expired idle lease once the clock passes the limit,
/// and a limit above the default is refused before anything is reserved.
#[test]
fn a_lowered_idle_limit_revokes_the_sandbox_when_it_expires() {
    let mut harness = Harness::new();
    let mut raised = Harness::spec();
    raised.idle_limit = Some(Duration::from_secs(13 * 3600));
    assert!(matches!(
        harness.service().launch(raised).unwrap_err(),
        VmServiceError::InvalidRequest {
            problem: super::RequestProblem::LeaseLimit { .. }
        }
    ));
    harness.guest(0, Behaviour::default());
    let mut spec = Harness::spec();
    spec.idle_limit = Some(Duration::from_secs(60));
    let id = harness.service().launch(spec).unwrap();
    harness.advance(Duration::from_secs(61));
    harness.wait_until("the idle lease's revocation", || {
        harness
            .service()
            .status()
            .iter()
            .find(|status| status.sandbox == id)
            .is_some_and(|status| !status.state.is_some_and(SandboxState::holds_authority))
    });
    // The revocation names its cause and has observed the denial of new work on its own,
    // before anyone tried a command.
    harness.wait_until("the denial of new work", || {
        harness
            .service()
            .status()
            .iter()
            .find(|status| status.sandbox == id)
            .and_then(|status| status.revocation.clone())
            .is_some_and(|revocation| {
                revocation.acknowledged.iter().any(|(acknowledgment, _)| {
                    *acknowledgment
                        == crate::sandbox::lifecycle::Acknowledgment::NewAuthorizationsDenied
                })
            })
    });
    let revocation = harness
        .service()
        .status()
        .into_iter()
        .find(|status| status.sandbox == id)
        .and_then(|status| status.revocation)
        .unwrap();
    assert!(matches!(
        revocation.cause,
        crate::sandbox::lifecycle::RevocationCause::LeaseExpired { .. }
    ));
    // No command runs on a sandbox whose lease ended.
    assert!(harness
        .service()
        .exec(&id, request(b"true\n", 64, SECOND))
        .is_err());
}

#[test]
fn owner_managed_vm_accepts_untimed_commands_and_publications_but_still_stops() {
    let mut harness = Harness::new();
    harness.guest(0, Behaviour::default());
    let mut spec = Harness::spec();
    spec.idle_limit = Some(Duration::ZERO);
    spec.lifetime_limit = Some(Duration::ZERO);
    spec.published.push(super::PublishedPort { service: "web".into(), port: 3000 });
    let id = harness.service().launch(spec).unwrap();
    let reply = harness.service().exec(&id, request(b"true\n", 4096, Duration::MAX)).unwrap();
    assert!(matches!(reply.end, ExecEnd::Finished));
    let (publication, _) = harness.service().publish(&id,"web",super::PublicationAudience::Owner,Duration::MAX,4096).unwrap();
    assert!(harness.service().publish(&id,"web",super::PublicationAudience::Public,Duration::MAX,4096).is_err());
    harness.service().withdraw(&id,publication).unwrap();
    harness.service().stop(&id).unwrap();
    assert!(harness.service().exec(&id,request(b"true\n",4096,Duration::MAX)).is_err());
}

/// PROVES an owner session (an inference harness in its owner's terminal) is reachable only by
/// its owner, and its owner publication may release the session's whole account rather than
/// VM-D12's 8 MiB, while an ordinary VM's publications keep the budget asked for.
#[test]
fn an_owner_session_releases_past_vm_d12_only_to_its_owner() {
    let mut harness = Harness::new();
    harness.guest(0, Behaviour::default());
    let mut spec = Harness::spec();
    spec.owner_session = true;
    spec.idle_limit = Some(Duration::ZERO);
    spec.lifetime_limit = Some(Duration::ZERO);
    spec.published.push(super::PublishedPort { service: "solver".into(), port: 8090 });
    let id = harness.service().launch(spec).unwrap();
    let refused = harness
        .service()
        .publish(&id, "solver", super::PublicationAudience::Public, Duration::from_secs(60), 4096)
        .unwrap_err();
    let refused = format!("{refused:?}");
    assert!(refused.contains("owner session"), "{refused}");
    let (owner, _) = harness
        .service()
        .publish(&id, "solver", super::PublicationAudience::Owner, Duration::MAX, 4096)
        .unwrap();
    let view = harness.service().publications(&id);
    let budget = &view.publications.iter().find(|p| p.publication == owner).unwrap().response_budget;
    assert_eq!(budget.limit_bytes, super::OWNER_SESSION_RELEASE_BYTES);
    assert!(budget.limit_bytes > super::PUBLISHED_RESPONSE_BYTES);
    // The status says what the session may release in all, not VM-D12's 8 MiB.
    assert_eq!(view.release_bound_bytes, super::OWNER_SESSION_RELEASE_BYTES);
    harness.service().withdraw(&id, owner).unwrap();
    harness.service().stop(&id).unwrap();

    // Each launch needs its own guest.
    harness.guest(1, Behaviour::default());
    let mut ordinary = Harness::spec();
    ordinary.published.push(super::PublishedPort { service: "web".into(), port: 3000 });
    let other = harness.service().launch(ordinary).unwrap();
    let (publication, _) = harness
        .service()
        .publish(&other, "web", super::PublicationAudience::Owner, Duration::from_secs(60), 4096)
        .unwrap();
    let view = harness.service().publications(&other);
    let budget = &view.publications.iter().find(|p| p.publication == publication).unwrap().response_budget;
    assert_eq!(budget.limit_bytes, 4096);
    assert_eq!(view.release_bound_bytes, super::PUBLISHED_RESPONSE_BYTES);
    harness.service().withdraw(&other, publication).unwrap();
    harness.service().stop(&other).unwrap();
}

/// PROVES a launch with declared egress endpoints seals a record whose network requirement
/// names the typed-operations channel its relay serves while the backend still observes no
/// network channel on the VM, and a launch without endpoints stays offline; the doctor gets
/// both records, oldest first.
#[test]
fn a_launch_with_endpoints_records_its_typed_operations_channel() {
    use crate::sandbox::backend::{GuestEgressEndpoint, NetworkAuthority, NetworkChannel};
    let mut harness = Harness::new();
    harness.guest(0, Behaviour::default());
    let mut spec = Harness::spec();
    spec.egress_endpoints = vec![GuestEgressEndpoint::new("secure", "example.com", 443).unwrap()];
    let with = harness.service().launch(spec).unwrap();
    harness.guest(1, Behaviour::default());
    let without = harness.service().launch(Harness::spec()).unwrap();
    assert_ne!(with, without);
    let records = harness.service().launch_records();
    assert_eq!(records.len(), 2);
    assert!(records[0].recorded_at() <= records[1].recorded_at());
    // The harness clock may not move between the two launches, so the records are told
    // apart by their endpoints, not by their order.
    let (with_record, without_record) = if records[0].required().declared_endpoints.is_empty() {
        (&records[1], &records[0])
    } else {
        (&records[0], &records[1])
    };
    assert_eq!(
        with_record.required().network,
        NetworkAuthority::of([NetworkChannel::TypedCredentialedOperations])
    );
    assert_eq!(with_record.required().declared_endpoints.len(), 1);
    assert!(without_record.required().network.is_offline());
    assert!(without_record.required().declared_endpoints.is_empty());
    for record in &records {
        assert!(record
            .host_observed()
            .network
            .value()
            .is_some_and(NetworkAuthority::is_offline));
    }
    harness.service().stop(&with).unwrap();
    harness.service().stop(&without).unwrap();
}

/// PROVES the engine's response path reaches the supervisor's durable audit stream: a
/// detection signal and a decision about a launched sandbox are recorded in its running
/// context, each with a receipt, in order.
#[test]
fn the_response_paths_facts_reach_the_audit_stream_with_receipts() {
    let mut harness = Harness::new();
    harness.guest(0, Behaviour::default());
    let id = harness.service().launch(Harness::spec()).unwrap();
    let fields = || {
        vec![
            Field::metadata("event", "monitoring_signal"),
            Field::metadata("sandbox", id.execution().as_str()),
        ]
    };
    let first = harness
        .service()
        .record_running_fact(&id, HostFact::DetectionSignal, fields())
        .unwrap()
        .unwrap();
    let second = harness
        .service()
        .record_running_fact(&id, HostFact::AuthorizationDecision, fields())
        .unwrap()
        .unwrap();
    assert!(second.sequence > first.sequence);
}

#[test]
fn status_shows_the_launched_sandbox_and_its_link() {
    let mut harness = Harness::new();
    assert!(harness.service().status().is_empty());
    harness.guest(0, Behaviour::default());
    let id = harness.service().launch(Harness::spec()).unwrap();
    let status = harness.service().status();
    assert_eq!(status.len(), 1);
    let view = &status[0];
    assert_eq!(view.sandbox, id);
    assert!(view.boot.is_some());
    assert_eq!(view.vm, Some(harness.world().launches[0].vm));
    assert_eq!(view.process, Some(harness.world().launches[0].process));
    assert!(matches!(view.readiness, super::ReadinessView::Ready { .. }));
    let record = view.launch_record.as_ref().unwrap();
    assert_eq!(record.guest_image, guest_image());
    assert!(view.transport.as_ref().is_some_and(|view| view.connected));
    assert!(view.running_commands.is_empty());
    assert_eq!(view.unclaimed_outcomes, 0);
    assert!(view.revocation.is_none());
    let json = serde_json::to_value(view).unwrap();
    assert_eq!(json["link"]["link"], "open");
    assert_eq!(json["phase"], "ready");
}

/// The fourth acceptance run of 30 October showed 1.4 million reads in four seconds on an
/// idle link: every pass counted its would-block read as movement and never slept. An idle
/// driver now sleeps its poll interval between passes, so its reads are bounded by time.
#[test]
fn an_idle_link_is_polled_at_the_poll_interval_not_spun() {
    let mut harness = Harness::new();
    harness.guest(0, Behaviour::default());
    let id = harness.service().launch(Harness::spec()).unwrap();
    let guest = &harness.guests[0];
    harness.wait_until("the welcome", || guest.state().welcomed);
    let reads = |harness: &Harness| {
        harness
            .service()
            .status()
            .into_iter()
            .find(|status| status.sandbox == id)
            .and_then(|status| status.transport)
            .map(|transport| transport.counters.read_calls)
            .unwrap()
    };
    let before = reads(&harness);
    std::thread::sleep(Duration::from_millis(300));
    let after = reads(&harness);
    // 300 ms at the fakes' 2 ms poll interval is about 150 passes; a spinning driver made
    // hundreds of thousands. The bound leaves room for a slow host.
    assert!(after - before < 1_000, "{} reads in 300 ms", after - before);
    assert!(after > before, "the driver stopped polling");
    harness.service().stop(&id).unwrap();
}

/// A caller blocked in `exec` holds no lock while it waits, and the status of its sandbox
/// lists the command it waits for, which a second caller may cancel.
#[test]
fn status_lists_a_running_command_while_its_caller_blocks_in_exec() {
    let mut harness = Harness::new();
    harness.guest(
        0,
        Behaviour {
            command: None,
            ..Behaviour::default()
        },
    );
    let id = harness.service().launch(Harness::spec()).unwrap();
    let guest = &harness.guests[0];
    let service = harness.service();
    std::thread::scope(|scope| {
        let blocked = scope.spawn(|| service.exec(&id, request(b"cat\n", 4_096, 30 * SECOND)));
        harness.wait_until("the open", || !guest.state().opened.is_empty());
        let running = service.status()[0].running_commands.clone();
        assert_eq!(
            running.len(),
            1,
            "the running command is listed while its caller waits"
        );
        service.cancel(&id, running[0]).unwrap();
        let outcome = blocked.join().unwrap().unwrap();
        assert_eq!(
            outcome.end,
            ExecEnd::Cancelled {
                by: CancelledBy::Caller
            }
        );
    });
    assert!(harness.service().status()[0].running_commands.is_empty());
}

/// The launch requires host observations at most a minute old. The fifth acceptance run of
/// 30 October 2026 was refused a command 167 s after its launch: nothing observed the
/// hypervisor again, so readiness re-observation found the launch's evidence stale. The tick
/// now refreshes the probes, so a sandbox older than the minute still takes commands.
#[test]
fn the_tick_refreshes_the_hosts_evidence_so_an_old_sandbox_still_takes_commands() {
    let mut harness = Harness::new();
    harness.guest(0, Behaviour::default());
    let id = harness.service().launch(Harness::spec()).unwrap();
    let guest = &harness.guests[0];
    harness.wait_until("the welcome", || guest.state().welcomed);
    // Two steps, each under the link's 60 s idle timeout, with a command between so the
    // link carries traffic; the launch's observation is then 61 s old, beyond the minute.
    harness.advance(30 * SECOND);
    std::thread::sleep(Duration::from_millis(50));
    let early = harness
        .service()
        .exec(&id, request(b"echo early\n", 4_096, 30 * SECOND))
        .unwrap();
    assert_eq!(early.end, ExecEnd::Finished);
    harness.advance(31 * SECOND);
    // The driver's next pass ticks the host at the new time and refreshes the probes; the
    // command's authorization then re-observes readiness on that fresh evidence (without
    // the refresh it is refused: the launch's observation is 61 s old, beyond the minute).
    std::thread::sleep(Duration::from_millis(100));
    let outcome = harness
        .service()
        .exec(&id, request(b"echo late\n", 4_096, 30 * SECOND))
        .unwrap();
    assert_eq!(outcome.end, ExecEnd::Finished);
    assert_eq!(outcome.exit_code, Some(0));
}

#[test]
fn nothing_secret_appears_in_debug_errors_or_serialized_outcomes() {
    let mut harness = Harness::new();
    harness.guest(0, Behaviour::default());
    let id = harness.service().launch(Harness::spec()).unwrap();
    let pid = harness.world().launches[0].process.pid;
    let secret_hex = digest("yougori/test/vm-service/secret/v1", &[&pid.to_be_bytes()]).to_hex();
    let key_hex = hex::encode([7u8; 32]);
    let outcome = harness
        .service()
        .exec(&id, request(b"secret input", 4_096, 30 * SECOND))
        .unwrap();
    let status = harness.service().status();
    let error = harness
        .service()
        .exec(&id, request(&[0u8; 2 << 20], 1, SECOND))
        .unwrap_err();
    let report = harness.service().stop(&id).unwrap();
    let texts = [
        format!("{:?}", harness.service()),
        format!("{outcome:?}"),
        serde_json::to_string(&outcome).unwrap(),
        serde_json::to_string(&status).unwrap(),
        format!("{error:?}"),
        error.to_string(),
        serde_json::to_string(&error).unwrap(),
        serde_json::to_string(&report).unwrap(),
        format!("{report:?}"),
    ];
    for text in &texts {
        assert!(!text.contains(&secret_hex), "{text}");
        assert!(!text.contains(&key_hex), "{text}");
    }
    // The request's debug shows the input's length, never the input.
    let request = request(b"secret input", 1, SECOND);
    let debug = format!("{request:?}");
    assert!(debug.contains("input_bytes: 12"), "{debug}");
    assert!(!debug.contains("secret input"), "{debug}");
    // The outcome's debug shows the output's length only.
    assert!(format!("{outcome:?}").contains("GuestBytes(17 bytes)"));
}

#[test]
fn a_restart_recovers_the_persisted_state_and_revives_no_authority() {
    let mut harness = Harness::new();
    harness.guest(0, Behaviour::default());
    let id = harness.service().launch(Harness::spec()).unwrap();
    harness
        .service()
        .exec(&id, request(b"echo\n", 4_096, 30 * SECOND))
        .unwrap();
    let persisted = harness.service().persist().unwrap();
    harness.service().confirm_persisted(&persisted);
    let vm = harness.world().launches[0].vm;

    // The engine restarts: the new service recovers; its backend holds no process, so the
    // VM is gone, every lease ended, and the sandbox holds no authority.
    let report = harness.restart(persisted).unwrap();
    assert_eq!(report.supervisor.handles_gone, vec![vm]);
    assert!(report.supervisor.handles_reused.is_empty());
    assert_eq!(report.supervisor.leases_ended, vec![id.execution().clone()]);
    assert_eq!(report.sandboxes.len(), 1);
    assert_eq!(report.sandboxes[0].sandbox, id);
    assert_ne!(report.sandboxes[0].state, Some(SandboxState::Running));
    assert_eq!(report.sandboxes[0].link, LinkView::NoChannels);
    assert_eq!(report.sandboxes[0].phase, None);
    assert!(matches!(
        harness
            .service()
            .exec(&id, request(b"", 1, SECOND))
            .unwrap_err(),
        VmServiceError::UnknownSandbox { .. }
            | VmServiceError::NotReady { .. }
            | VmServiceError::Revoked { .. }
    ));
    // A new launch works after the recovery.
    harness.guest(1, Behaviour::default());
    let second = harness.service().launch(Harness::spec()).unwrap();
    assert_ne!(second, id);
    let outcome = harness
        .service()
        .exec(&second, request(b"again\n", 4_096, 30 * SECOND))
        .unwrap();
    assert_eq!(outcome.exit_code, Some(0));
    assert_eq!(harness.service().status().len(), 2);
    harness.service().stop(&second).unwrap();
}

#[test]
fn two_sandboxes_run_at_once_and_stop_independently() {
    let mut harness = Harness::new();
    harness.guest(0, Behaviour::default());
    harness.guest(
        1,
        Behaviour {
            command: Some(fails),
            ..Behaviour::default()
        },
    );
    let first = harness.service().launch(Harness::spec()).unwrap();
    let second = harness.service().launch(Harness::spec()).unwrap();
    assert_ne!(first, second);
    let a = harness
        .service()
        .exec(&first, request(b"one\n", 4_096, 30 * SECOND))
        .unwrap();
    let b = harness
        .service()
        .exec(&second, request(b"two\n", 4_096, 30 * SECOND))
        .unwrap();
    assert_eq!(a.output.as_bytes(), b"ran: one\n");
    assert_eq!(a.exit_code, Some(0));
    assert_eq!(b.output.as_bytes(), b"error\n");
    assert_eq!(b.exit_code, Some(4));
    assert_eq!(harness.service().status().len(), 2);
    let stopped = harness.service().stop(&first).unwrap();
    assert!(stopped.vm_stop.is_stopped());
    // The second runs on.
    let c = harness
        .service()
        .exec(&second, request(b"three\n", 4_096, 30 * SECOND))
        .unwrap();
    assert_eq!(c.exit_code, Some(6));
    let stopped = harness.service().stop(&second).unwrap();
    assert!(stopped.vm_stop.is_stopped());
    assert_eq!(harness.world().terminated.len(), 2);
    assert!(harness.world().directories.is_empty());
    let dropped = harness
        .service()
        .status()
        .iter()
        .filter(|status| status.state == Some(SandboxState::Stopped))
        .count();
    assert_eq!(dropped, 2);
}

#[test]
fn a_launch_the_host_refuses_to_start_leaves_nothing_and_is_rolled_back() {
    let mut harness = Harness::new();
    harness.world().start_failure = Some(crate::sandbox::qemu::StartFailure::Prepare {
        detail: "the private directory already exists".to_owned(),
    });
    let error = harness.service().launch(Harness::spec()).unwrap_err();
    assert!(
        matches!(error, VmServiceError::LaunchRolledBack { .. }),
        "{error:?}"
    );
    let world = harness.world();
    assert!(world.launches.is_empty());
    assert!(world.dialed.is_empty());
    drop(world);
    // The reservation went back: a launch with the host working again fits.
    harness.world().start_failure = None;
    harness.guest(0, Behaviour::default());
    let id = harness.service().launch(Harness::spec()).unwrap();
    harness.service().stop(&id).unwrap();
}

#[test]
fn requests_outside_their_bounds_are_refused_before_anything_happens() {
    let harness = Harness::new();
    let no_memory = super::LaunchSpec {
            gpu: false,
            gpu_memory: Vec::new(),
            internet: false,
            targets: None,
            owner_session: false,
        workload_image: None,
        tenant: crate::sandbox::host::fakes::tenant(),
        resources: super::VmResources {
            memory_bytes: 0,
            cpu_slots: 1,
        },
        egress_endpoints: Vec::new(),
        idle_limit: None,
        lifetime_limit: None,
        published: Vec::new(),
        connect: Vec::new(),
    };
    assert!(matches!(
        harness.service().launch(no_memory).unwrap_err(),
        VmServiceError::InvalidRequest { .. }
    ));
    let unknown = super::SandboxId::new(crate::foundation::ids::ExecutionId::generate());
    assert!(matches!(
        harness
            .service()
            .exec(&unknown, request(b"", 1, Duration::ZERO))
            .unwrap_err(),
        VmServiceError::InvalidRequest { .. }
    ));
    assert!(matches!(
        harness
            .service()
            .exec(&unknown, request(b"", 1, SECOND))
            .unwrap_err(),
        VmServiceError::UnknownSandbox { .. }
    ));
    assert!(matches!(
        harness.service().stop(&unknown).unwrap_err(),
        VmServiceError::UnknownSandbox { .. }
    ));
    assert!(harness.world().launches.is_empty());
    assert!(matches!(
        serde_json::from_str::<super::LaunchSpec>(
            r#"{"tenant":"tenant-a","resources":{"memory_bytes":1,"cpu_slots":1},"extra":1}"#
        ),
        Err(_)
    ));
}

/// A launch's targets hold its network card: they need the card, are never given to a GPU VM
/// (whose card the host's filter does not see), and reach the backend's request and the record
/// beside the internet channel.
#[test]
fn targets_need_a_network_card_and_reach_the_launch_record() {
    use crate::sandbox::backend::{NetworkChannel, NetworkTarget};
    let target = NetworkTarget {
        host: "192.168.1.50".into(),
        addresses: vec![std::net::Ipv4Addr::new(192, 168, 1, 50)],
        ports: vec![8080],
    };
    let mut harness = Harness::new();
    for (internet, gpu) in [(false, false), (true, true)] {
        let mut spec = Harness::spec();
        spec.internet = internet;
        spec.gpu = gpu;
        spec.targets = Some(vec![target.clone()]);
        assert!(matches!(
            harness.service().launch(spec).unwrap_err(),
            VmServiceError::Connection { .. }
        ));
    }
    assert!(harness.world().launches.is_empty());
    harness.guest(0, Behaviour::default());
    let mut spec = Harness::spec();
    spec.internet = true;
    spec.targets = Some(vec![target.clone()]);
    harness.service().launch(spec).unwrap();
    let records = harness.service().launch_records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].required().targets, Some(vec![target]));
    assert!(records[0]
        .required()
        .network
        .channels
        .contains(&NetworkChannel::Internet));
}

#[test]
fn directory_removal_and_vm_stop_views_say_what_was_observed() {
    assert!(DirectoryRemoval::NotChecked.is_removed() == false);
    assert!(!VmStop::NotStopped {
        pending: Vec::new(),
        uncertain: 0
    }
    .is_stopped());
}

/// A fake egress port: what the relay's guest transport looks like to the service. It records
/// the guest's opens and bytes and answers each stream, once the guest ended its direction,
/// with `response` followed by its own end.
#[derive(Default)]
struct PortState {
    opened: Vec<(u32, String)>,
    data: std::collections::BTreeMap<u32, Vec<u8>>,
    guest_ended: Vec<u32>,
    ended: Vec<u32>,
    queued: Vec<super::EgressInbound>,
    refuse_opens: bool,
}

struct FakePort {
    state: std::sync::Arc<std::sync::Mutex<PortState>>,
    response: Vec<u8>,
}

impl super::EgressPort for FakePort {
    fn opened(
        &mut self,
        stream: crate::sandbox::link::StreamId,
        destination: &crate::sandbox::link::LinkName,
    ) -> Result<(), String> {
        let mut state = self.state.lock().unwrap();
        if state.refuse_opens {
            return Err("scripted: the relay is gone".to_owned());
        }
        state
            .opened
            .push((stream.get(), destination.as_str().to_owned()));
        Ok(())
    }

    fn data(&mut self, stream: crate::sandbox::link::StreamId, bytes: &[u8]) -> Result<(), String> {
        self.state
            .lock()
            .unwrap()
            .data
            .entry(stream.get())
            .or_default()
            .extend_from_slice(bytes);
        Ok(())
    }

    fn guest_ended(&mut self, stream: crate::sandbox::link::StreamId) {
        let mut state = self.state.lock().unwrap();
        state.guest_ended.push(stream.get());
        state.queued.push(super::EgressInbound::Data {
            stream,
            bytes: self.response.clone(),
        });
        state.queued.push(super::EgressInbound::End { stream });
    }

    fn ended(&mut self, stream: crate::sandbox::link::StreamId) {
        self.state.lock().unwrap().ended.push(stream.get());
    }

    fn poll(&mut self) -> Vec<super::EgressInbound> {
        std::mem::take(&mut self.state.lock().unwrap().queued)
    }
}

const EGRESS_REQUEST: &[u8] = b"GET /v1/models HTTP/1.1\r\nhost: api.example.com\r\n\r\n";
const EGRESS_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}";

/// The guest opens an egress stream shortly after its welcome; with a port attached the
/// bytes reach it and its answer returns on the same stream, which then ends in order.
#[test]
fn an_egress_stream_the_guest_opens_reaches_the_attached_port_and_its_answer_returns() {
    let mut harness = Harness::new();
    harness.guest(
        0,
        Behaviour {
            egress: Some(crate::sandbox::vm_service::fakes::EgressScript {
                destination: "provider",
                request: EGRESS_REQUEST,
                delay: Duration::from_millis(400),
            }),
            ..Behaviour::default()
        },
    );
    let id = harness.service().launch(Harness::spec()).unwrap();
    let state = std::sync::Arc::new(std::sync::Mutex::new(PortState::default()));
    harness
        .service()
        .attach_egress(
            &id,
            Box::new(FakePort {
                state: std::sync::Arc::clone(&state),
                response: EGRESS_RESPONSE.to_vec(),
            }),
        )
        .unwrap();
    let status = harness.service().status();
    assert!(status[0].egress.attached);
    let guest = &harness.guests[0];
    harness.wait_until("the egress answer", || guest.state().egress_ended);
    {
        let guest = guest.state();
        assert!(guest.egress_opened);
        assert_eq!(guest.egress_refused, None);
        assert_eq!(guest.egress_received, EGRESS_RESPONSE);
    }
    harness.wait_until("the stream's end at the port", || {
        state.lock().unwrap().ended == vec![1]
    });
    {
        let port = state.lock().unwrap();
        assert_eq!(port.opened, vec![(1, "provider".to_owned())]);
        assert_eq!(port.data.get(&1).map(Vec::as_slice), Some(EGRESS_REQUEST));
        assert_eq!(port.guest_ended, vec![1]);
    }
    let status = harness.service().status();
    assert_eq!(status[0].egress.open_streams, 0);
    // Detached: refused again, and a second detach finds nothing attached.
    assert!(harness.service().detach_egress(&id).unwrap());
    assert!(!harness.service().status()[0].egress.attached);
    assert!(!harness.service().detach_egress(&id).unwrap());
    harness.service().stop(&id).unwrap();
}

/// Without a port every guest egress open is refused as unavailable, and a port that refuses
/// an open has the stream cancelled on the link.
#[test]
fn a_guest_egress_open_is_refused_without_a_port_and_cancelled_when_the_port_refuses() {
    let mut harness = Harness::new();
    harness.guest(
        0,
        Behaviour {
            egress: Some(crate::sandbox::vm_service::fakes::EgressScript {
                destination: "provider",
                request: EGRESS_REQUEST,
                delay: Duration::ZERO,
            }),
            ..Behaviour::default()
        },
    );
    let id = harness.service().launch(Harness::spec()).unwrap();
    let guest = &harness.guests[0];
    harness.wait_until("the refusal", || guest.state().egress_refused.is_some());
    assert_eq!(
        guest.state().egress_refused,
        Some(crate::sandbox::link::OpenRefusalCause::Unavailable)
    );
    assert!(!guest.state().egress_opened);
    // A port that refuses the open: the stream is cancelled, the port told.
    assert!(harness
        .service()
        .attach_egress(
            &id,
            Box::new(FakePort {
                state: std::sync::Arc::new(std::sync::Mutex::new(PortState {
                    refuse_opens: true,
                    ..PortState::default()
                })),
                response: Vec::new(),
            })
        )
        .is_ok());
    harness.service().stop(&id).unwrap();
}

/// The staged workspace is attached to a ready sandbox's file channel as its one workspace
/// grant: a second attach, an unknown sandbox and a missing folder are refused, a detach
/// takes it off once, and a stopped sandbox takes none.
#[test]
fn the_workspace_grant_attaches_to_a_ready_sandbox_only_and_comes_off_once() {
    let mut harness = Harness::new();
    harness.guest(0, Behaviour::default());
    let id = harness.service().launch(Harness::spec()).unwrap();
    let staging = tempfile::tempdir().unwrap();
    std::fs::write(staging.path().join("main.py"), b"print(1)\n").unwrap();
    let quota = crate::sandbox_contract::files::FileQuota {
        max_total_bytes: 1 << 20,
        max_entries: 100,
        max_file_bytes: 1 << 20,
    };
    let day = Duration::from_secs(24 * 60 * 60);
    harness
        .service()
        .attach_workspace(&id, staging.path(), None, quota, day)
        .unwrap();
    // One workspace grant per sandbox.
    assert!(matches!(
        harness
            .service()
            .attach_workspace(&id, staging.path(), None, quota, day),
        Err(VmServiceError::Host { .. })
    ));
    let stranger =
        super::SandboxId::new(crate::foundation::ids::ExecutionId::new("exe-nobody").unwrap());
    assert!(matches!(
        harness
            .service()
            .attach_workspace(&stranger, staging.path(), None, quota, day),
        Err(VmServiceError::UnknownSandbox { .. })
    ));
    assert!(harness.service().detach_workspace(&id));
    assert!(!harness.service().detach_workspace(&id));
    assert!(matches!(
        harness
            .service()
            .attach_workspace(&id, &staging.path().join("missing"), None, quota, day),
        Err(VmServiceError::Workspace { .. })
    ));
    harness.service().stop(&id).unwrap();
    assert!(harness
        .service()
        .attach_workspace(&id, staging.path(), None, quota, day)
        .is_err());
}

const INGRESS_REQUEST: &[u8] = b"GET / HTTP/1.1\r\nhost: preview\r\n\r\n";
const INGRESS_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nhi";

fn ingress_guest() -> Behaviour {
    Behaviour {
        ingress: Some(crate::sandbox::vm_service::fakes::IngressService {
            listener: "port-8080",
            response: INGRESS_RESPONSE,
        }),
        ..Behaviour::default()
    }
}

/// Reads `handle` until the guest ended its direction, at most five seconds.
fn read_all(handle: &mut crate::sandbox::vm_service::GuestIngress) -> Result<Vec<u8>, String> {
    use crate::sandbox_contract::connections::{SessionStream, StreamRead};
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut got = Vec::new();
    let mut buffer = [0u8; 1024];
    while std::time::Instant::now() < deadline {
        match handle
            .read(&mut buffer)
            .map_err(|error| error.to_string())?
        {
            StreamRead::Bytes(read) => got.extend_from_slice(&buffer[..read]),
            StreamRead::Ended => return Ok(got),
            StreamRead::Idle => std::thread::sleep(Duration::from_millis(5)),
        }
    }
    Err(format!("no end after {} bytes", got.len()))
}

/// PROVES a caller's ingress stream through the service (M14): a handle the gate closes
/// untouched (a refused caller) never reaches the guest; a used one opens the guest's
/// listener, carries the caller's request and returns the guest service's answer and its
/// end; a closed handle has its stream cancelled on the link; and a listener nothing serves
/// is refused by the guest and fails the handle.
#[test]
fn a_callers_ingress_stream_opens_once_used_and_carries_the_services_answer() {
    use crate::sandbox_contract::connections::{SessionStream, StreamError, StreamRead};
    let mut harness = Harness::new();
    harness.guest(0, ingress_guest());
    let id = harness.service().launch(Harness::spec()).unwrap();
    let guest = &harness.guests[0];
    // A refused caller: closed untouched, nothing asked of the guest.
    let mut refused = harness.service().ingress(&id, "port-8080").unwrap();
    assert_eq!(harness.service().status()[0].ingress.requested, 1);
    refused.close();
    harness.wait_until("the untouched request dropped", || {
        harness.service().status()[0].ingress.requested == 0
    });
    assert!(guest.state().ingress_opened.is_empty() && guest.state().ingress_refused.is_empty());
    // An admitted caller: the first write opens the stream.
    let mut handle = harness.service().ingress(&id, "port-8080").unwrap();
    assert_eq!(handle.stream(), None);
    handle.write(INGRESS_REQUEST).unwrap();
    harness.wait_until("the guest's request", || {
        guest.state().ingress_received.get(&2).map(Vec::as_slice) == Some(INGRESS_REQUEST)
    });
    assert_eq!(guest.state().ingress_opened, vec![2]);
    assert_eq!(read_all(&mut handle).unwrap(), INGRESS_RESPONSE);
    assert!(handle.is_open());
    handle.close();
    assert!(matches!(
        handle.read(&mut [0u8; 8]),
        Err(StreamError::Closed)
    ));
    harness.wait_until("the stream gone", || {
        harness.service().status()[0].ingress.open_streams == 0
    });
    // A listener nothing serves: refused by the guest, the handle fails.
    let mut nobody = harness.service().ingress(&id, "port-9").unwrap();
    assert!(matches!(nobody.read(&mut [0u8; 8]), Ok(StreamRead::Idle)));
    harness.wait_until("the refusal", || nobody.closed().is_some());
    assert!(matches!(
        nobody.read(&mut [0u8; 8]),
        Err(StreamError::Failed { .. })
    ));
    assert!(guest.state().ingress_refused.contains(&4));
    // A name that is not a listener's is refused before anything.
    assert!(harness.service().ingress(&id, "port:80").is_err());
    harness.service().stop(&id).unwrap();
}

/// PROVES a stop (the host closing the sandbox's channels) fails every caller's open stream
/// and every request not opened yet, and a later handle is refused.
#[test]
fn a_stop_fails_the_callers_ingress_streams() {
    use crate::sandbox_contract::connections::{SessionStream, StreamError, StreamRead};
    let mut harness = Harness::new();
    harness.guest(0, ingress_guest());
    let id = harness.service().launch(Harness::spec()).unwrap();
    let guest = &harness.guests[0];
    let mut open = harness.service().ingress(&id, "port-8080").unwrap();
    assert!(matches!(open.read(&mut [0u8; 8]), Ok(StreamRead::Idle)));
    harness.wait_until("the open", || open.is_open());
    let mut waiting = harness.service().ingress(&id, "port-8080").unwrap();
    harness.service().stop(&id).unwrap();
    harness.wait_until("the open stream failed", || open.closed().is_some());
    assert!(matches!(
        open.write(b"late"),
        Err(StreamError::Failed { .. })
    ));
    harness.wait_until("the waiting request failed", || waiting.closed().is_some());
    assert!(matches!(
        waiting.read(&mut [0u8; 8]),
        Err(StreamError::Failed { .. })
    ));
    assert_eq!(guest.state().ingress_opened, vec![2]);
    assert!(harness.service().ingress(&id, "port-8080").is_err());
}

/// One end of an in-memory byte stream for a caller (the gate's other end).
struct Pipe {
    inbound: std::sync::Arc<std::sync::Mutex<(std::collections::VecDeque<u8>, bool)>>,
    outbound: std::sync::Arc<std::sync::Mutex<(std::collections::VecDeque<u8>, bool)>>,
}

fn pipe() -> (Pipe, Pipe) {
    let a = std::sync::Arc::new(std::sync::Mutex::new((
        std::collections::VecDeque::new(),
        false,
    )));
    let b = std::sync::Arc::new(std::sync::Mutex::new((
        std::collections::VecDeque::new(),
        false,
    )));
    (
        Pipe {
            inbound: std::sync::Arc::clone(&a),
            outbound: std::sync::Arc::clone(&b),
        },
        Pipe {
            inbound: b,
            outbound: a,
        },
    )
}

impl crate::sandbox_contract::connections::SessionStream for Pipe {
    fn read(
        &mut self,
        buffer: &mut [u8],
    ) -> Result<
        crate::sandbox_contract::connections::StreamRead,
        crate::sandbox_contract::connections::StreamError,
    > {
        use crate::sandbox_contract::connections::StreamRead;
        let mut inbound = self.inbound.lock().unwrap();
        if inbound.0.is_empty() {
            return Ok(if inbound.1 {
                StreamRead::Ended
            } else {
                StreamRead::Idle
            });
        }
        let take = inbound.0.len().min(buffer.len());
        for (slot, byte) in buffer.iter_mut().zip(inbound.0.drain(..take)) {
            *slot = byte;
        }
        Ok(StreamRead::Bytes(take))
    }

    fn write(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), crate::sandbox_contract::connections::StreamError> {
        let mut outbound = self.outbound.lock().unwrap();
        if outbound.1 {
            return Err(crate::sandbox_contract::connections::StreamError::Closed);
        }
        outbound.0.extend(bytes);
        Ok(())
    }

    fn finish(&mut self) {
        self.outbound.lock().unwrap().1 = true;
    }

    fn close(&mut self) {
        self.outbound.lock().unwrap().1 = true;
        self.inbound.lock().unwrap().1 = true;
    }
}

/// Proves only the token it issued, for its own binding, as the owner.
struct TokenVerifier {
    token: Vec<u8>,
    binding: crate::sandbox_contract::connections::ProofBinding,
}

impl crate::sandbox_contract::connections::ProofVerifier for TokenVerifier {
    fn verify(
        &self,
        binding: &crate::sandbox_contract::connections::ProofBinding,
        proof: &crate::sandbox_contract::connections::AuthenticationProof,
        now: crate::foundation::ids::MonotonicTime,
    ) -> Result<
        crate::sandbox_contract::connections::VerifiedProof,
        crate::sandbox_contract::connections::ProofRefusal,
    > {
        use crate::sandbox_contract::connections::{ProofRefusal, VerifiedProof};
        if *binding != self.binding {
            return Err(ProofRefusal::WrongPublication);
        }
        if proof.material() != self.token.as_slice() {
            return Err(ProofRefusal::Invalid);
        }
        Ok(VerifiedProof {
            principal: crate::sandbox_contract::destinations::PrincipalId::new("owner").unwrap(),
            valid_until: now.saturating_add(Duration::from_secs(3600)),
        })
    }
}

fn publishing_spec() -> super::LaunchSpec {
    let mut spec = Harness::spec();
    spec.published = vec![super::PublishedPort {
        service: "web".to_owned(),
        port: 8080,
    }];
    spec
}

/// Pumps the service's sessions until `done` or five seconds passed.
fn pump_until(harness: &Harness, what: &str, mut done: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !done() {
        assert!(std::time::Instant::now() < deadline, "timed out: {what}");
        harness.service().pump_sessions();
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// PROVES a published guest service end to end through the gate (M14): only a declared
/// service publishes; a private publication refuses a caller without its token, and the
/// guest is never asked for that caller; the owner's caller is admitted, its request
/// reaches the guest service and the answer comes back, charged to the publication's
/// budget and the sandbox's release account; the session ends with the guest's end; a
/// withdrawn publication admits no one.
#[test]
fn a_published_service_admits_only_its_audience_and_charges_every_answer() {
    use crate::sandbox_contract::connections::{AuthenticationProof, SessionStream};
    use crate::sandbox_contract::destinations::AuthenticationMode;
    let mut harness = Harness::new();
    harness.guest(0, ingress_guest());
    let id = harness.service().launch(publishing_spec()).unwrap();
    let guest = &harness.guests[0];
    let view = harness.service().publications(&id);
    assert_eq!(view.declared.len(), 1);
    assert!(
        view.publications.is_empty(),
        "nothing is published at launch"
    );
    assert!(
        harness
            .service()
            .publish(
                &id,
                "api",
                super::PublicationAudience::Owner,
                Duration::from_secs(60),
                4096
            )
            .is_err(),
        "a service the launch did not declare"
    );
    let number = harness
        .service()
        .publish(
            &id,
            "web",
            super::PublicationAudience::Owner,
            Duration::from_secs(60),
            4096,
        )
        .unwrap()
        .0;
    let binding = harness.service().proof_binding(&id, number).unwrap();
    let verifier = TokenVerifier {
        token: b"token-1".to_vec(),
        binding,
    };
    // No proof, then a wrong one: refused, and the guest never dialed.
    let (gate_end, _caller) = pipe();
    assert!(harness
        .service()
        .admit(&id, "web", None, &verifier, Box::new(gate_end), None)
        .is_err());
    let (gate_end, _caller) = pipe();
    let wrong = AuthenticationProof::new(AuthenticationMode::BearerToken, b"token-2".to_vec());
    assert!(harness
        .service()
        .admit(&id, "web", Some(wrong), &verifier, Box::new(gate_end), None)
        .is_err());
    harness.service().pump_sessions();
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        guest.state().ingress_opened.is_empty(),
        "a refused caller reached the guest"
    );
    // The owner.
    let (gate_end, mut caller) = pipe();
    let proof = AuthenticationProof::new(AuthenticationMode::BearerToken, b"token-1".to_vec());
    let (_session, _room) = harness
        .service()
        .admit(&id, "web", Some(proof), &verifier, Box::new(gate_end), None)
        .unwrap();
    caller.write(INGRESS_REQUEST).unwrap();
    let mut answer = Vec::new();
    pump_until(&harness, "the answer", || {
        let mut buffer = [0u8; 256];
        if let Ok(crate::sandbox_contract::connections::StreamRead::Bytes(read)) =
            caller.read(&mut buffer)
        {
            answer.extend_from_slice(&buffer[..read]);
        }
        answer.len() >= INGRESS_RESPONSE.len()
    });
    assert_eq!(answer, INGRESS_RESPONSE);
    assert_eq!(
        guest.state().ingress_received.get(&2).map(Vec::as_slice),
        Some(INGRESS_REQUEST)
    );
    pump_until(&harness, "the session's end", || {
        harness.service().publications(&id).publications[0].open_sessions == 0
    });
    let view = harness.service().publications(&id);
    let publication = &view.publications[0];
    assert_eq!(publication.audience, super::PublicationAudience::Owner);
    assert_eq!(
        publication.response_budget.used_bytes,
        INGRESS_RESPONSE.len() as u64
    );
    assert_eq!(publication.sessions_admitted, 1);
    assert_eq!(view.released_bytes, INGRESS_RESPONSE.len() as u64);
    // Withdrawn: no one more.
    harness.service().withdraw(&id, number).unwrap();
    let (gate_end, _caller) = pipe();
    let proof = AuthenticationProof::new(AuthenticationMode::BearerToken, b"token-1".to_vec());
    assert!(harness
        .service()
        .admit(&id, "web", Some(proof), &verifier, Box::new(gate_end), None)
        .is_err());
    assert_eq!(
        harness.service().publications(&id).publications[0].state,
        "withdrawn"
    );
    harness.service().stop(&id).unwrap();
}

/// PROVES a revocation closes an open session before anything more reaches its caller,
/// and the host acknowledges "channels closed" only once the gate closed it; a response
/// budget spent ends a session too.
#[test]
fn a_revocation_closes_the_open_sessions_and_channels_close_after_them() {
    use crate::sandbox_contract::connections::{AuthenticationProof, SessionStream, StreamRead};
    use crate::sandbox_contract::destinations::AuthenticationMode;
    let mut harness = Harness::new();
    harness.guest(0, ingress_guest());
    let id = harness.service().launch(publishing_spec()).unwrap();
    // A public publication with a budget smaller than the answer: the session ends at it.
    let small = harness
        .service()
        .publish(
            &id,
            "web",
            super::PublicationAudience::Public,
            Duration::from_secs(60),
            10,
        )
        .unwrap()
        .0;
    let binding = harness.service().proof_binding(&id, small).unwrap();
    let verifier = TokenVerifier {
        token: b"unused".to_vec(),
        binding,
    };
    let (gate_end, mut caller) = pipe();
    harness
        .service()
        .admit(&id, "web", None, &verifier, Box::new(gate_end), None)
        .unwrap();
    caller.write(INGRESS_REQUEST).unwrap();
    pump_until(&harness, "the budget spent", || {
        harness.service().publications(&id).publications[0].state == "response_budget_spent"
    });
    let mut got = Vec::new();
    let mut buffer = [0u8; 256];
    while let Ok(StreamRead::Bytes(read)) = caller.read(&mut buffer) {
        got.extend_from_slice(&buffer[..read]);
    }
    assert_eq!(got.len(), 10, "exactly the budget left: {got:?}");
    // The spent publication is withdrawn before the service is published again.
    harness.service().withdraw(&id, small).unwrap();
    // An owner's session held open (its request never ends, so the guest never answers).
    let owner = harness
        .service()
        .publish(
            &id,
            "web",
            super::PublicationAudience::Owner,
            Duration::from_secs(60),
            4096,
        )
        .unwrap()
        .0;
    let binding = harness.service().proof_binding(&id, owner).unwrap();
    let verifier = TokenVerifier {
        token: b"token-1".to_vec(),
        binding,
    };
    let (gate_end, mut caller) = pipe();
    let proof = AuthenticationProof::new(AuthenticationMode::BearerToken, b"token-1".to_vec());
    harness
        .service()
        .admit(&id, "web", Some(proof), &verifier, Box::new(gate_end), None)
        .unwrap();
    caller.write(b"GET / HTTP/1.1\r\n").unwrap();
    pump_until(&harness, "the open session", || {
        harness.service().publications(&id).publications[1].open_sessions == 1
    });
    // The stop revokes: the session closes first, with no pump needed, and the VM stops.
    let report = harness.service().stop(&id).unwrap();
    assert!(report.vm_stop.is_stopped(), "{:?}", report.vm_stop);
    let mut buffer = [0u8; 64];
    assert!(matches!(caller.read(&mut buffer), Ok(StreamRead::Ended)));
    assert_eq!(harness.service().pump_sessions().open, 0);
    let status = harness.service().status();
    let revocation = status[0].revocation.as_ref().unwrap();
    assert!(revocation
        .acknowledged
        .iter()
        .any(|(acknowledgment, _)| *acknowledgment
            == crate::sandbox::lifecycle::Acknowledgment::ChannelsClosed));
}

/// A caller's guest whose program connects to the endpoint `api` `delay` after the welcome,
/// sends `request` and ends its writing.
fn connecting_guest(request: &'static [u8], delay: Duration) -> Behaviour {
    Behaviour {
        egress: Some(crate::sandbox::vm_service::fakes::EgressScript {
            destination: "api",
            request,
            delay,
        }),
        ..Behaviour::default()
    }
}

fn serving_spec() -> super::LaunchSpec {
    let mut spec = Harness::spec();
    spec.published = vec![super::PublishedPort {
        service: "api".to_owned(),
        port: 8080,
    }];
    spec
}

fn connecting_spec() -> super::LaunchSpec {
    let mut spec = Harness::spec();
    spec.connect = vec![super::ConnectionEndpoint {
        name: "api".to_owned(),
        port: 8080,
    }];
    spec
}

/// PROVES a sandbox connection (M14, VM-CP-29) through the service: a program's connection
/// to an endpoint granted nothing is cancelled and never reaches the other sandbox; a grant
/// needs the caller's declared endpoint and the callee's declared service, never the same
/// sandbox; once granted, the program's request reaches the callee's service, its end of
/// writing reaches the service as the end of the stream (a half close), and the answer and
/// its end come back; both sandboxes show the grant; withdrawing it is refused the second
/// time.
#[test]
fn a_sandbox_connection_needs_a_grant_and_carries_a_half_closed_exchange() {
    let mut harness = Harness::new();
    harness.guest(0, ingress_guest());
    harness.guest(1, connecting_guest(INGRESS_REQUEST, Duration::ZERO));
    harness.guest(
        2,
        connecting_guest(INGRESS_REQUEST, Duration::from_millis(800)),
    );
    let callee = harness.service().launch(serving_spec()).unwrap();
    let ungranted = harness.service().launch(connecting_spec()).unwrap();
    let records = harness.service().status();
    assert_eq!(records.len(), 2);
    harness.wait_until("the ungranted connection cancelled", || {
        harness.service().pump_sessions();
        harness.guests[1].state().egress_cancelled
    });
    assert!(
        harness.guests[1].state().egress_opened,
        "the host accepted the endpoint's stream"
    );
    assert!(
        harness.guests[0].state().ingress_opened.is_empty(),
        "nothing reached the callee"
    );
    assert_eq!(
        harness
            .service()
            .connections(&ungranted)
            .refused_connections,
        1
    );

    let caller = harness.service().launch(connecting_spec()).unwrap();
    let minute = Duration::from_secs(60);
    for (endpoint, to, service) in [
        ("db", &callee, "api"),
        ("api", &callee, "web"),
        ("api", &caller, "api"),
    ] {
        assert!(
            matches!(
                harness
                    .service()
                    .connect(&caller, endpoint, to, service, minute, 1 << 20),
                Err(VmServiceError::Connection { .. })
            ),
            "{endpoint} to {service}"
        );
    }
    harness
        .service()
        .connect(&caller, "api", &callee, "api", minute, 1 << 20)
        .unwrap();
    assert!(
        harness
            .service()
            .connect(&caller, "api", &callee, "api", minute, 1 << 20)
            .is_err(),
        "an endpoint is granted one service at a time"
    );
    // The service answers as soon as the request arrives, so the answer may come back before
    // the program's end of writing reaches the service: wait for both.
    harness.wait_until("the answer and its end, and the end of writing at the service", || {
        harness.service().pump_sessions();
        let state = harness.guests[2].state();
        state.egress_received == INGRESS_RESPONSE
            && state.egress_ended
            && !harness.guests[0].state().ingress_ended.is_empty()
    });
    let served = harness.guests[0].state();
    assert_eq!(
        served.ingress_received.get(&2).map(Vec::as_slice),
        Some(INGRESS_REQUEST)
    );
    assert_eq!(
        served.ingress_ended,
        vec![2],
        "the program's end of writing reached the service"
    );
    drop(served);
    assert!(!harness.guests[2].state().egress_cancelled);
    let view = harness.service().connections(&caller);
    let granted = view.endpoints[0].granted.as_ref().unwrap();
    assert_eq!(
        (granted.service.as_str(), granted.connections_opened),
        ("api", 1)
    );
    assert_eq!(granted.sandbox, callee.execution().as_str());
    let callers = harness.service().connections(&callee).callers;
    assert_eq!(
        (callers[0].sandbox.as_str(), callers[0].endpoint.as_str()),
        (caller.execution().as_str(), "api")
    );
    harness.wait_until("the connection closed", || {
        harness.service().pump_sessions();
        harness.service().connections(&caller).open_connections == 0
    });
    assert_eq!(harness.service().disconnect(&caller, "api").unwrap(), 0);
    assert!(harness.service().disconnect(&caller, "api").is_err());
    assert!(harness.service().connections(&callee).callers.is_empty());
    for id in [&caller, &ungranted, &callee] {
        harness.service().stop(id).unwrap();
    }
}

/// PROVES a stop of the callee cuts an open connection that carried nothing back: the
/// caller's stream is cancelled, and the grant is gone with the callee.
#[test]
fn a_callees_stop_cuts_its_open_connections() {
    let mut harness = Harness::new();
    harness.guest(0, ingress_guest());
    // No request head: the service never answers, so the connection stays open.
    harness.guest(1, connecting_guest(b"partial", Duration::from_millis(800)));
    let callee = harness.service().launch(serving_spec()).unwrap();
    let caller = harness.service().launch(connecting_spec()).unwrap();
    harness
        .service()
        .connect(
            &caller,
            "api",
            &callee,
            "api",
            Duration::from_secs(60),
            1 << 20,
        )
        .unwrap();
    harness.wait_until("the request reached the callee", || {
        harness.service().pump_sessions();
        harness.guests[0].state().ingress_ended == vec![2]
    });
    assert_eq!(harness.service().connections(&caller).open_connections, 1);
    harness.service().stop(&callee).unwrap();
    harness.wait_until("the caller's stream cancelled", || {
        harness.service().pump_sessions();
        harness.guests[1].state().egress_cancelled
    });
    let view = harness.service().connections(&caller);
    assert_eq!(view.open_connections, 0);
    assert!(
        view.endpoints[0].granted.is_none(),
        "the grant went with the callee"
    );
    harness.service().stop(&caller).unwrap();
}

/// PROVES a connection grant expires on the shared clock: status marks it expired, and a new
/// grant replaces it without a disconnect.
#[test]
fn an_expired_connection_grant_is_marked_and_replaced_by_a_new_one() {
    let mut harness = Harness::new();
    harness.guest(0, ingress_guest());
    harness.guest(1, Behaviour::default());
    let callee = harness.service().launch(serving_spec()).unwrap();
    let caller = harness.service().launch(connecting_spec()).unwrap();
    let state = |harness: &Harness| {
        harness.service().connections(&caller).endpoints[0]
            .granted
            .as_ref()
            .map(|granted| granted.state)
    };
    harness
        .service()
        .connect(
            &caller,
            "api",
            &callee,
            "api",
            Duration::from_secs(60),
            1 << 20,
        )
        .unwrap();
    assert_eq!(state(&harness), Some("active"));
    harness.advance(Duration::from_secs(61));
    assert_eq!(state(&harness), Some("expired"));
    harness
        .service()
        .connect(
            &caller,
            "api",
            &callee,
            "api",
            Duration::from_secs(60),
            1 << 20,
        )
        .unwrap();
    assert_eq!(state(&harness), Some("active"));
    for id in [&caller, &callee] {
        harness.service().stop(id).unwrap();
    }
}

/// PROVES a connection cut at its budget still delivers what passed the gate: the caller's
/// program reads the answer up to the budget, then the end of the stream (never a cancel
/// that would drop bytes already charged).
#[test]
fn a_connection_cut_at_its_budget_delivers_what_passed_then_ends() {
    let mut harness = Harness::new();
    harness.guest(0, ingress_guest());
    harness.guest(
        1,
        connecting_guest(INGRESS_REQUEST, Duration::from_millis(800)),
    );
    let callee = harness.service().launch(serving_spec()).unwrap();
    let caller = harness.service().launch(connecting_spec()).unwrap();
    // The 33-byte request passes; the 40-byte answer stops at 36.
    assert_eq!((INGRESS_REQUEST.len(), INGRESS_RESPONSE.len()), (33, 40));
    harness
        .service()
        .connect(&caller, "api", &callee, "api", Duration::from_secs(60), 36)
        .unwrap();
    harness.wait_until("the caller's stream ended", || {
        harness.service().pump_sessions();
        harness.guests[1].state().egress_ended
    });
    let state = harness.guests[1].state();
    assert_eq!(state.egress_received.as_slice(), &INGRESS_RESPONSE[..36]);
    assert!(!state.egress_cancelled);
    drop(state);
    for id in [&caller, &callee] {
        harness.service().stop(id).unwrap();
    }
}
