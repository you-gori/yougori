//! These tests use the real coordinator, child leases and service drivers with the
//! existing scripted host ports. Actual SSH/KVM validation is a separate gate.
use std::time::Duration;

use super::fakes::{Behaviour, Harness};
use super::{BootPhase, ExecRequest, SandboxId, VmServiceError};
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{Clock, LeaseId};
use crate::sandbox_contract::remote::fakes::{control_key, identity, session_id, session_key};
use crate::sandbox_contract::remote::{ControlBody, ControlSession, GrantRef, LeaseGrant};

const SECOND: Duration = Duration::from_secs(1);

#[test]
fn a_persisted_remote_identity_launches_once_and_read_only_probe_grants_no_work() {
    let mut h = Harness::new();
    h.guest(0, Behaviour::default());
    let execution = crate::foundation::ids::ExecutionId::generate();
    let id = h
        .service()
        .launch_remote_identified(Harness::spec(), execution.clone())
        .unwrap();
    let before = h.service().remote_view(&id).unwrap();
    assert!(before.lease.is_none());
    let observed = h.service().observe_vm(&id).unwrap();
    assert!(observed.remote_control.unwrap().lease.is_none());
    assert!(h.service().exec(&id, command()).is_err());
    assert!(h
        .service()
        .launch_remote_identified(Harness::spec(), execution.clone())
        .is_err());
    assert_eq!(h.world().launches.len(), 1);
    let mut session = host(&h);
    connect(&h, &id, &mut session);
    grant(&h, &id, &mut session, ClockSession::generate(), 20);
    assert!(
        h.service().exec(&id, command()).is_ok(),
        "duplicate launch did not disturb the original"
    );
    h.service().stop(&id).unwrap();
    assert!(h.service().observe_vm(&id).is_err());
    assert!(
        h.service()
            .launch_remote_identified(Harness::spec(), execution)
            .is_err(),
        "an ended execution cannot be revived"
    );
    assert_eq!(h.world().launches.len(), 1);
}

fn host(h: &Harness) -> ControlSession {
    ControlSession::open(
        identity(1),
        session_id(1),
        session_key(1),
        control_key(1),
        h.clock.now(),
    )
}

fn connect(h: &Harness, id: &SandboxId, host: &mut ControlSession) {
    let hello = host.seal_outbound(ControlBody::Heartbeat).unwrap();
    let reply = h.service().remote_open(id, control_key(1), &hello).unwrap();
    assert_eq!(
        host.accept(&reply, h.clock.now()).unwrap(),
        ControlBody::Heartbeat
    );
}

fn grant(h: &Harness, id: &SandboxId, host: &mut ControlSession, clock: ClockSession, ttl: u64) {
    let frame = host
        .seal_outbound(ControlBody::Grant {
            grant: LeaseGrant {
                authority: GrantRef::Lease {
                    lease: LeaseId::new(301),
                },
                clock,
                ttl_nanos: ttl * 1_000_000_000,
            },
        })
        .unwrap();
    let prepared = h.service().remote_frame(id, &frame).unwrap().unwrap();
    // The scripted host has no native process. Explicitly model its deadline
    // acknowledgment; production obtains that acknowledgment over the real pipe.
    h.service().commit_remote_grant(id, prepared).unwrap();
}

#[test]
fn a_prepared_grant_cannot_enable_work_or_survive_a_late_enforcement_ack() {
    let mut h = Harness::new();
    h.guest(0, Behaviour::default());
    let id = h.service().launch_remote(Harness::spec()).unwrap();
    let mut host = host(&h);
    connect(&h, &id, &mut host);
    let frame = host
        .seal_outbound(ControlBody::Grant {
            grant: LeaseGrant {
                authority: GrantRef::Lease {
                    lease: LeaseId::new(301),
                },
                clock: ClockSession::generate(),
                ttl_nanos: 10_000_000_000,
            },
        })
        .unwrap();
    let pending = h.service().remote_frame(&id, &frame).unwrap().unwrap();
    assert!(h.service().remote_view(&id).unwrap().lease.is_none());
    assert!(h.service().exec(&id, command()).is_err());
    assert_eq!(h.service().lease_terms()[0].renewal_left, Some(10 * SECOND));
    h.advance(11 * SECOND);
    assert!(h.service().commit_remote_grant(&id, pending).is_err());
    assert!(h.service().remote_view(&id).unwrap().lease.is_none());
    assert!(h.service().exec(&id, command()).is_err());
}

fn command() -> ExecRequest {
    ExecRequest::new(b"echo remote".to_vec(), 4096, 5 * SECOND)
}

#[test]
fn remote_work_waits_for_a_real_child_lease_and_renewals_consume_all_transit_time() {
    let mut h = Harness::new();
    h.guest(0, Behaviour::default());
    let id = h.service().launch_remote(Harness::spec()).unwrap();
    assert!(matches!(
        h.service().exec(&id, command()),
        Err(VmServiceError::RemoteControl { .. })
    ));
    assert!(h.service().remote_view(&id).unwrap().lease.is_none());
    let staging = tempfile::tempdir().unwrap();
    assert!(matches!(
        h.service().attach_workspace(
            &id,
            staging.path(),
            None,
            crate::sandbox_contract::files::FileQuota {
                max_total_bytes: 1024,
                max_file_bytes: 1024,
                max_entries: 8,
            },
            5 * SECOND,
        ),
        Err(VmServiceError::RemoteControl { .. })
    ));
    assert!(matches!(
        h.service().ingress(&id, "service"),
        Err(VmServiceError::RemoteControl { .. })
    ));
    let mut host = host(&h);
    connect(&h, &id, &mut host);
    h.advance(5 * SECOND);
    let home_clock = ClockSession::generate();
    grant(&h, &id, &mut host, home_clock, 20);
    let first = h.service().remote_view(&id).unwrap();
    assert!(first.lease.is_some());
    assert_eq!(first.remaining_ms, 15_000);
    assert_eq!(h.service().lease_terms()[0].renewal_left, Some(15 * SECOND));
    assert_eq!(h.service().exec(&id, command()).unwrap().exit_code, Some(0));
    h.advance(8 * SECOND);
    let request = h.service().remote_poll(&id).unwrap();
    assert!(matches!(
        host.accept(&request, h.clock.now()).unwrap(),
        ControlBody::RenewalRequest { .. }
    ));
    h.advance(2 * SECOND);
    grant(&h, &id, &mut host, home_clock, 20);
    let next = h.service().remote_view(&id).unwrap();
    assert_ne!(first.lease, next.lease);
    assert_eq!(next.remaining_ms, 18_000);
    assert_eq!(h.service().lease_terms()[0].renewal_left, Some(18 * SECOND));
    h.service().remote_close(&id);
    h.wait_until("remote stop", || {
        h.service().status()[0].phase == Some(BootPhase::Ended)
    });
    assert!(h.service().remote_view(&id).unwrap().lease.is_none());
    assert_eq!(h.world().terminated.len(), 1);
    assert!(h.world().directories.is_empty());
}

#[test]
fn a_delayed_grant_or_a_missing_agent_cannot_outlive_the_supervised_window() {
    let mut h = Harness::new();
    h.guest(0, Behaviour::default());
    let id = h.service().launch_remote(Harness::spec()).unwrap();
    h.advance(31 * SECOND);
    h.wait_until("bootstrap expiration without a bridge", || {
        h.service().status()[0].phase == Some(BootPhase::Ended)
    });
    assert_eq!(h.world().terminated.len(), 1);
    assert!(h.service().exec(&id, command()).is_err());

    let mut h = Harness::new();
    h.guest(0, Behaviour::default());
    let id = h.service().launch_remote(Harness::spec()).unwrap();
    let mut host = host(&h);
    connect(&h, &id, &mut host);
    let clock = ClockSession::generate();
    grant(&h, &id, &mut host, clock, 20);
    h.advance(12 * SECOND);
    h.service().remote_poll(&id).unwrap();
    let delayed = host
        .seal_outbound(ControlBody::Grant {
            grant: LeaseGrant {
                authority: GrantRef::Lease {
                    lease: LeaseId::new(301),
                },
                clock,
                ttl_nanos: 60_000_000_000,
            },
        })
        .unwrap();
    h.advance(9 * SECOND);
    assert!(h.service().remote_frame(&id, &delayed).is_err());
    assert!(h.service().exec(&id, command()).is_err());
    h.wait_until("expired grant", || {
        h.service().status()[0].phase == Some(BootPhase::Ended)
    });
}

#[test]
fn a_tampered_channel_ends_only_its_remote_vm_and_an_ordinary_vm_is_not_a_control_target() {
    let mut h = Harness::new();
    h.guest(0, Behaviour::default());
    h.guest(1, Behaviour::default());
    let remote = h.service().launch_remote(Harness::spec()).unwrap();
    let ordinary = h.service().launch(Harness::spec()).unwrap();
    let mut host = host(&h);
    connect(&h, &remote, &mut host);
    let mut forged = host.seal_outbound(ControlBody::Heartbeat).unwrap();
    forged.frame.body = ControlBody::Stop;
    assert!(h.service().remote_frame(&ordinary, &forged).is_err());
    assert_eq!(
        h.service().exec(&ordinary, command()).unwrap().exit_code,
        Some(0)
    );
    assert!(h.service().remote_frame(&remote, &forged).is_err());
    h.wait_until("tampered session closed", || {
        h.service().remote_view(&remote).unwrap().closed
    });
    assert!(h.service().exec(&remote, command()).is_err());
    assert_eq!(
        h.service().exec(&ordinary, command()).unwrap().exit_code,
        Some(0)
    );
    assert!(h.service().stop(&ordinary).unwrap().vm_stop.is_stopped());
}

#[test]
fn a_restart_never_restores_a_remote_session_or_its_child_authority() {
    let mut h = Harness::new();
    h.guest(0, Behaviour::default());
    let id = h.service().launch_remote(Harness::spec()).unwrap();
    let mut host = host(&h);
    connect(&h, &id, &mut host);
    grant(&h, &id, &mut host, ClockSession::generate(), 20);
    let persisted = h.service().persist().unwrap();
    h.restart(persisted).unwrap();
    assert!(h.service().remote_view(&id).is_none());
    let frame = host.seal_outbound(ControlBody::Heartbeat).unwrap();
    assert!(h
        .service()
        .remote_open(&id, control_key(1), &frame)
        .is_err());
    assert!(h.service().exec(&id, command()).is_err());
}
