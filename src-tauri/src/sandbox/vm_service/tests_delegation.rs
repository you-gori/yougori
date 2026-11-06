//! The host adapter uses this service's real coordinator; only the existing
//! hypervisor/guest ports are scripted here. Cross-host acceptance is separate.
use std::time::Duration;

use super::fakes::{Behaviour, Harness};
use crate::foundation::coordination::{LeaseKind, LeaseTerms};
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::OperationId;
use crate::sandbox_contract::remote::HostAuthority;

fn terms() -> LeaseTerms {
    LeaseTerms {
        term: Duration::from_secs(20),
        max_lifetime: Duration::from_secs(60),
        cancel_within: Duration::from_secs(5),
    }
}

fn operation(name: &str) -> OperationId {
    OperationId::new(name).unwrap()
}

#[test]
fn cleanup_keeps_the_real_clock_without_granting_work_even_to_a_live_parent() {
    let mut h = Harness::new();
    h.guest(0, Behaviour::default());
    let parent = h.service().launch(Harness::spec()).unwrap();
    let boot = h.service().observe_vm(&parent).unwrap().boot.unwrap();
    let mut live = h.service().delegation(&parent).unwrap();
    let lease = live
        .issue(parent.execution(), operation("live"), terms())
        .unwrap();
    let mut cleanup = h.service().cleanup_delegation(&parent, boot).unwrap();
    assert_eq!(cleanup.session(), live.session());
    assert_eq!(cleanup.now(), live.now());
    assert!(cleanup
        .issue(
            parent.execution(),
            operation("cleanup-must-not-grant"),
            terms()
        )
        .is_err());
    assert!(cleanup.check(lease.id()).is_err());
    assert!(cleanup.renew(lease.id(), live.session()).is_err());
    assert!(cleanup.release(lease.id()).is_err());
    assert!(live.check(lease.id()).is_ok());
    h.service().stop(&parent).unwrap();
    let mut recovered = h.service().cleanup_delegation(&parent, boot).unwrap();
    assert!(recovered
        .issue(parent.execution(), operation("ended-parent"), terms())
        .is_err());
    let missing =
        super::SandboxId::new(crate::foundation::ids::ExecutionId::new("removed-parent").unwrap());
    let mut recovered = h.service().cleanup_delegation(&missing, boot).unwrap();
    assert!(recovered
        .issue(missing.execution(), operation("missing-parent"), terms())
        .is_err());
}

#[test]
fn delegation_uses_the_existing_parent_and_leases_and_drop_releases_only_its_children() {
    let mut h = Harness::new();
    h.guest(0, Behaviour::default());
    h.guest(1, Behaviour::default());
    let parent = h.service().launch(Harness::spec()).unwrap();
    let other = h.service().launch(Harness::spec()).unwrap();
    let mut first = h.service().delegation(&parent).unwrap();
    let mut second = h.service().delegation(&parent).unwrap();
    assert!(first
        .issue(other.execution(), operation("foreign"), terms())
        .is_err());
    let a = first
        .issue(parent.execution(), operation("remote-a"), terms())
        .unwrap();
    let b = second
        .issue(parent.execution(), operation("remote-b"), terms())
        .unwrap();
    assert_eq!(a.parent(), parent.execution());
    assert_eq!(a.kind(), LeaseKind::Service);
    assert_eq!(first.session(), h.session);
    assert!(first.check(b.id()).is_err());
    assert!(first.renew(b.id(), h.session).is_err());
    assert!(first.release(b.id()).is_err());
    h.advance(Duration::from_secs(6));
    let renewed = first.renew(a.id(), h.session).unwrap();
    assert!(renewed.expires_at() > a.expires_at());
    drop(first);
    let core = h.service().shared.lock();
    let coordinator = core.host.as_ref().unwrap().supervisor().coordinator();
    assert!(coordinator.check_lease(a.id()).is_err());
    assert!(coordinator.check_lease(b.id()).is_ok());
    drop(core);
    assert!(second.check(b.id()).is_ok());
}

#[test]
fn a_wrong_session_refusal_is_final_for_that_delegation_lease() {
    let mut h = Harness::new();
    h.guest(0, Behaviour::default());
    let parent = h.service().launch(Harness::spec()).unwrap();
    let mut authority = h.service().delegation(&parent).unwrap();
    let lease = authority
        .issue(parent.execution(), operation("remote"), terms())
        .unwrap();
    assert!(authority
        .renew(lease.id(), ClockSession::generate())
        .is_err());
    assert!(authority.check(lease.id()).is_err());
    assert!(authority.renew(lease.id(), h.session).is_err());
}

#[test]
fn a_stopped_or_restarted_parent_cannot_delegate_or_revive_its_old_child() {
    let mut h = Harness::new();
    h.guest(0, Behaviour::default());
    let parent = h.service().launch(Harness::spec()).unwrap();
    let mut authority = h.service().delegation(&parent).unwrap();
    let lease = authority
        .issue(parent.execution(), operation("remote"), terms())
        .unwrap();
    let persisted = h.service().persist().unwrap();
    h.restart(persisted).unwrap();
    assert!(authority.check(lease.id()).is_err());
    assert!(authority.renew(lease.id(), h.session).is_err());
    assert!(authority
        .issue(parent.execution(), operation("revive"), terms())
        .is_err());
    assert!(h.service().delegation(&parent).is_err());
}

#[test]
fn bootstrap_cannot_delegate_and_unavailable_cancellation_guarantees_are_refused() {
    let mut h = Harness::new();
    h.guest(0, Behaviour::default());
    h.guest(1, Behaviour::default());
    let remote = h.service().launch_remote(Harness::spec()).unwrap();
    let parent = h.service().launch(Harness::spec()).unwrap();
    let mut bootstrap = h.service().delegation(&remote).unwrap();
    assert!(bootstrap
        .issue(remote.execution(), operation("nested"), terms())
        .is_err());
    let mut authority = h.service().delegation(&parent).unwrap();
    assert!(authority
        .issue(
            parent.execution(),
            operation("too-fast"),
            LeaseTerms {
                cancel_within: Duration::from_millis(1),
                ..terms()
            }
        )
        .is_err());
    let child = authority
        .issue(parent.execution(), operation("valid"), terms())
        .unwrap();
    h.advance(Duration::from_secs(21));
    assert!(authority.check(child.id()).is_err());
    assert!(authority.renew(child.id(), h.session).is_err());
}
