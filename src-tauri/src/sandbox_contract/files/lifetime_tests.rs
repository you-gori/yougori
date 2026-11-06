//! Lifetimes on the coordination leases (VM part §6.2; VM-D12; VM-P18, VM-P40) and the
//! per-class responses of VM-D7 and VM-D10, run through a real coordinator on fakes.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use super::fakes::{at, execution, session, RewindableClock, World, HOUR, SECOND};
use super::*;
use crate::foundation::coordination::{LeaseKind, LeaseRefusal, LeaseTerms, RevocationStatus};
use crate::foundation::ids::{
    digest, ExecutionId, LeaseId, ManualClock, MonotonicTime, OperationId, SandboxBootGeneration,
};

const DAY: Duration = Duration::from_secs(24 * 3_600);

fn operation(name: &str) -> OperationId {
    OperationId::new(name).unwrap()
}

fn task_policy() -> LifetimePolicy {
    LifetimePolicy::task(600, 4 * 3_600, 5).unwrap()
}

fn manual_world() -> World<Arc<ManualClock>> {
    World::new(Arc::new(ManualClock::new(at(100))), session(1))
}

#[test]
fn vm_d12_starting_values() {
    assert_eq!(DEFAULT_IDLE_SECONDS, 43_200);
    assert_eq!(DEFAULT_TASK_ABSOLUTE_SECONDS, 86_400);
    assert_eq!(DEFAULT_SERVICE_RENEWAL_SECONDS, 604_800);
    let task = task_policy();
    assert_eq!(task.class(), SandboxClass::Task);
    assert_eq!(task.idle_seconds(), Some(12 * 3_600));
    assert_eq!(task.absolute_seconds(), Some(24 * 3_600));
    assert_eq!(task.service_renewal_seconds(), None);
    assert_eq!(task.authority_seconds(), 86_400);
    let service = LifetimePolicy::service(600, 5).unwrap();
    assert_eq!(service.class(), SandboxClass::Service);
    assert_eq!(service.service_renewal_seconds(), Some(7 * 24 * 3_600));
    assert_eq!(service.idle_seconds(), None);
    assert_eq!(service.authority_seconds(), 604_800);
}

#[test]
fn limits_nest_and_are_never_zero() {
    assert_eq!(
        LifetimePolicy::task(0, 3_600, 5),
        Err(LifetimeProblem::Zero {
            limit: LifetimeLimit::PerCall
        })
    );
    assert_eq!(
        LifetimePolicy::task(60, 3_600, 0),
        Err(LifetimeProblem::Zero {
            limit: LifetimeLimit::CancelWithin
        })
    );
    assert_eq!(
        LifetimePolicy::task(3_601, 3_600, 5),
        Err(LifetimeProblem::Exceeds {
            limit: LifetimeLimit::PerCall,
            bound: LifetimeLimit::Task
        })
    );
    assert_eq!(
        LifetimePolicy::task(60, 86_401, 5),
        Err(LifetimeProblem::Exceeds {
            limit: LifetimeLimit::Task,
            bound: LifetimeLimit::Absolute
        })
    );
    assert_eq!(
        task_policy().with_idle_seconds(86_401),
        Err(LifetimeProblem::Exceeds {
            limit: LifetimeLimit::Idle,
            bound: LifetimeLimit::Absolute
        })
    );
    assert_eq!(
        task_policy().with_absolute_seconds(3 * 3_600),
        Err(LifetimeProblem::Exceeds {
            limit: LifetimeLimit::Task,
            bound: LifetimeLimit::Absolute
        })
    );
    assert_eq!(
        task_policy().with_service_renewal_seconds(DAY.as_secs()),
        Err(LifetimeProblem::NotForClass {
            limit: LifetimeLimit::ServiceRenewal,
            class: SandboxClass::Task
        })
    );
    let service = LifetimePolicy::service(600, 5).unwrap();
    assert_eq!(
        service.with_absolute_seconds(DAY.as_secs()),
        Err(LifetimeProblem::NotForClass {
            limit: LifetimeLimit::Absolute,
            class: SandboxClass::Service
        })
    );
    assert_eq!(
        LifetimePolicy::service(604_801, 5),
        Err(LifetimeProblem::Exceeds {
            limit: LifetimeLimit::PerCall,
            bound: LifetimeLimit::ServiceRenewal
        })
    );
    // Adjusted from measurement within the nesting.
    let adjusted = task_policy().with_idle_seconds(1_800).unwrap();
    assert_eq!(adjusted.idle_seconds(), Some(1_800));
}

#[test]
fn a_policy_reads_back_only_when_valid() {
    let policy = task_policy();
    let text = serde_json::to_string(&policy).unwrap();
    assert_eq!(
        serde_json::from_str::<LifetimePolicy>(&text).unwrap(),
        policy
    );
    let widened = text.replace("\"idle_seconds\":43200", "\"idle_seconds\":172800");
    assert_ne!(widened, text);
    assert!(serde_json::from_str::<LifetimePolicy>(&widened).is_err());
    let extra = text.replacen('{', "{\"keep_alive_on_traffic\":true,", 1);
    assert!(serde_json::from_str::<LifetimePolicy>(&extra).is_err());
}

#[test]
fn limits_become_coordination_lease_terms_and_authority() {
    let policy = task_policy();
    let terms = |term: u64, max_lifetime: u64| LeaseTerms {
        term: Duration::from_secs(term),
        max_lifetime: Duration::from_secs(max_lifetime),
        cancel_within: Duration::from_secs(5),
    };
    assert_eq!(policy.call_terms(), terms(600, 600));
    assert_eq!(policy.task_terms(), Some(terms(14_400, 14_400)));
    assert_eq!(policy.idle_terms(), Some(terms(43_200, 86_400)));
    for terms in [
        policy.call_terms(),
        policy.task_terms().unwrap(),
        policy.idle_terms().unwrap(),
    ] {
        assert_eq!(terms.check(), Ok(()));
    }
    let service = LifetimePolicy::service(600, 5).unwrap();
    assert_eq!(service.idle_terms(), None);
    assert_eq!(service.task_terms(), None);
    let mut world = manual_world();
    let mut plan = world.plan(&execution("exe-task"), DAY);
    assert_eq!(policy.check_launch(&plan), Ok(()));
    plan.authority_lifetime = DAY + SECOND;
    assert_eq!(
        policy.check_launch(&plan),
        Err(LifetimeProblem::AuthorityTooLong {
            plan_seconds: 86_401,
            policy_seconds: 86_400
        })
    );
    plan.authority_lifetime = Duration::ZERO;
    assert_eq!(
        policy.check_launch(&plan),
        Err(LifetimeProblem::Zero {
            limit: LifetimeLimit::Absolute
        })
    );
    plan.authority_lifetime = 7 * DAY + Duration::from_millis(1);
    assert_eq!(
        service.check_launch(&plan),
        Err(LifetimeProblem::AuthorityTooLong {
            plan_seconds: 604_801,
            policy_seconds: 604_800
        })
    );
}

#[test]
fn network_traffic_streams_and_heartbeats_never_keep_an_idle_vm_alive() {
    let policy = task_policy();
    let mut world = manual_world();
    let sandbox = execution("exe-task");
    let plan = world.plan(&sandbox, DAY);
    world.launch(plan);
    let idle = IdleKeepAlive::start(
        &mut world.coordinator,
        &sandbox,
        operation("op-idle"),
        &policy,
    )
    .unwrap();
    let issued = world.coordinator.check_lease(idle.lease()).unwrap();
    assert_eq!(issued.kind(), LeaseKind::Service);
    assert_eq!(issued.expires_at(), at(100 + 43_200));
    for hour in 1..12 {
        world.clock.advance_to(at(100 + hour * 3_600));
        for (activity, reason) in [
            (
                Activity::InboundNetwork { bytes: 1 << 20 },
                IgnoredActivity::NetworkTraffic,
            ),
            (
                Activity::OutboundNetwork { bytes: 1 << 20 },
                IgnoredActivity::NetworkTraffic,
            ),
            (
                Activity::OutputStream { bytes: 4_096 },
                IgnoredActivity::OutputStream,
            ),
            (Activity::GuestHeartbeat, IgnoredActivity::GuestReport),
        ] {
            assert_eq!(
                idle.observe(&mut world.coordinator, activity),
                Ok(KeepAliveDecision::Ignored { reason })
            );
        }
    }
    world.clock.advance_to(at(100 + 43_199));
    assert!(world.coordinator.check_lease(idle.lease()).is_ok());
    world.clock.advance_to(at(100 + 43_200));
    assert_eq!(
        world.coordinator.check_lease(idle.lease()),
        Err(LeaseRefusal::Expired {
            expired_at: at(100 + 43_200)
        })
    );
    // An interaction after expiry does not revive it.
    assert!(matches!(
        idle.observe(&mut world.coordinator, Activity::UserInteraction),
        Err(LifetimeRefusal::Lease {
            refusal: LeaseRefusal::Expired { .. }
        })
    ));
}

#[test]
fn host_activity_renews_the_idle_lease_but_never_past_the_absolute_limit() {
    let policy = task_policy();
    let mut world = manual_world();
    let sandbox = execution("exe-task");
    let plan = world.plan(&sandbox, DAY);
    world.launch(plan);
    let idle = IdleKeepAlive::start(
        &mut world.coordinator,
        &sandbox,
        operation("op-idle"),
        &policy,
    )
    .unwrap();
    world.clock.advance_to(at(100 + 6 * 3_600));
    assert_eq!(
        idle.observe(&mut world.coordinator, Activity::UserInteraction),
        Ok(KeepAliveDecision::Renewed {
            expires_at: at(100 + 18 * 3_600)
        })
    );
    world.clock.advance_to(at(100 + 17 * 3_600));
    let call = world
        .coordinator
        .start_child_work(
            &sandbox,
            operation("op-call"),
            LeaseKind::ChildWork,
            policy.call_terms(),
        )
        .unwrap();
    assert_eq!(
        idle.observe(
            &mut world.coordinator,
            Activity::HostCall { lease: call.id() }
        ),
        Ok(KeepAliveDecision::Renewed {
            expires_at: at(100 + 24 * 3_600)
        })
    );
    // At 23 h a renewal cannot reach past 24 h after issue, the absolute limit.
    world.clock.advance_to(at(100 + 23 * 3_600));
    match idle.observe(&mut world.coordinator, Activity::UserInteraction) {
        Ok(KeepAliveDecision::Renewed { expires_at }) => {
            assert!(expires_at <= at(100 + 24 * 3_600))
        }
        Err(LifetimeRefusal::Lease {
            refusal: LeaseRefusal::RenewalLimitReached { expires_at, .. },
        }) => assert_eq!(expires_at, at(100 + 24 * 3_600)),
        other => panic!("{other:?}"),
    }
    world.clock.advance_to(at(100 + 24 * 3_600));
    assert!(world.coordinator.check_lease(idle.lease()).is_err());
    assert!(idle
        .observe(&mut world.coordinator, Activity::UserInteraction)
        .is_err());
}

#[test]
fn only_a_call_of_the_same_sandbox_renews_the_idle_lease() {
    let policy = task_policy();
    let mut world = manual_world();
    let mine = execution("exe-task");
    let other = execution("exe-other");
    let plan = world.plan(&mine, DAY);
    world.launch(plan);
    let plan = world.plan(&other, DAY);
    world.launch(plan);
    let idle =
        IdleKeepAlive::start(&mut world.coordinator, &mine, operation("op-idle"), &policy).unwrap();
    let foreign = world
        .coordinator
        .start_child_work(
            &other,
            operation("op-call"),
            LeaseKind::ChildWork,
            policy.call_terms(),
        )
        .unwrap();
    assert_eq!(
        idle.observe(
            &mut world.coordinator,
            Activity::HostCall {
                lease: foreign.id()
            }
        ),
        Err(LifetimeRefusal::ForeignCall {
            lease: foreign.id()
        })
    );
    assert_eq!(
        idle.observe(
            &mut world.coordinator,
            Activity::HostCall {
                lease: idle.lease()
            }
        ),
        Err(LifetimeRefusal::ForeignCall {
            lease: idle.lease()
        })
    );
    let transfer = world
        .coordinator
        .start_child_work(
            &mine,
            operation("op-download"),
            LeaseKind::Transfer,
            policy.call_terms(),
        )
        .unwrap();
    assert_eq!(
        idle.observe(
            &mut world.coordinator,
            Activity::HostCall {
                lease: transfer.id()
            }
        ),
        Err(LifetimeRefusal::ForeignCall {
            lease: transfer.id()
        })
    );
}

#[test]
fn a_service_sandbox_ends_at_its_renewal_limit_whatever_its_traffic() {
    let policy = LifetimePolicy::service(600, 5).unwrap();
    let mut world = manual_world();
    let service = execution("exe-service");
    let plan = world.plan(&service, Duration::from_secs(policy.authority_seconds()));
    assert_eq!(policy.check_launch(&plan), Ok(()));
    world.launch(plan);
    assert_eq!(
        IdleKeepAlive::start(
            &mut world.coordinator,
            &service,
            operation("op-idle"),
            &policy
        ),
        Err(LifetimeRefusal::NoIdleLimit)
    );
    world.clock.advance_to(at(100 + 604_799));
    assert!(world
        .coordinator
        .start_child_work(
            &service,
            operation("op-late"),
            LeaseKind::ChildWork,
            policy.call_terms()
        )
        .is_ok());
    world.clock.advance_to(at(100 + 604_800));
    assert!(matches!(
        world.coordinator.start_child_work(
            &service,
            operation("op-after"),
            LeaseKind::Service,
            policy.call_terms()
        ),
        Err(LeaseRefusal::AuthorityExpired { .. })
    ));
}

fn call_lease(
    world: &mut World<Arc<RewindableClock>>,
    sandbox: &ExecutionId,
    name: &str,
) -> LeaseId {
    world
        .coordinator
        .start_child_work(
            sandbox,
            operation(name),
            LeaseKind::ChildWork,
            task_policy().call_terms(),
        )
        .unwrap()
        .id()
}

#[test]
fn a_clock_that_goes_back_cannot_revive_a_lease() {
    let clock = Arc::new(RewindableClock::new(at(100)));
    let mut world = World::new(Arc::clone(&clock), session(1));
    let sandbox = execution("exe-task");
    let plan = world.plan(&sandbox, DAY);
    world.launch(plan);
    // Call leases last 600 s: `lease` until 700, `later` until 1000.
    let lease = call_lease(&mut world, &sandbox, "op-call");
    let mut guard = ExpiryGuard::new(session(1));
    assert!(guard.check(&world.coordinator, lease).is_ok());
    clock.set(at(400));
    let later = call_lease(&mut world, &sandbox, "op-later");
    assert!(guard.check(&world.coordinator, later).is_ok());
    clock.set(at(100 + 600));
    assert_eq!(
        guard.check(&world.coordinator, lease),
        Err(LifetimeRefusal::Lease {
            refusal: LeaseRefusal::Expired {
                expired_at: at(700)
            }
        })
    );
    assert_eq!(world.coordinator.clock_high_water(), at(700));
    // The time source jumps back: the coordinator's own high-water mark refuses, and the
    // refusal ends the lease in the guard.
    clock.set(at(400));
    assert_eq!(
        guard.check(&world.coordinator, later),
        Err(LifetimeRefusal::Lease {
            refusal: LeaseRefusal::ClockWentBack {
                now: at(400),
                high_water: at(700)
            }
        })
    );
    assert_eq!(
        guard.check(&world.coordinator, lease),
        Err(LifetimeRefusal::Ended { lease })
    );
    // Forward again, past the mark: the coordinator alone honours `later` until 1000, but
    // the guard never does, and `lease` stays ended too.
    clock.set(at(800));
    assert!(world.coordinator.check_lease(later).is_ok());
    assert_eq!(
        guard.check(&world.coordinator, later),
        Err(LifetimeRefusal::Ended { lease: later })
    );
    assert_eq!(
        guard.check(&world.coordinator, lease),
        Err(LifetimeRefusal::Ended { lease })
    );
    // An ended lease is not checked again, but its check still reads the clock into the
    // coordinator's high-water mark.
    clock.set(at(900));
    assert_eq!(
        guard.check(&world.coordinator, lease),
        Err(LifetimeRefusal::Ended { lease })
    );
    assert_eq!(world.coordinator.clock_high_water(), at(900));
    clock.set(at(850));
    assert_eq!(
        world.coordinator.check_lease(later),
        Err(LeaseRefusal::ClockWentBack {
            now: at(850),
            high_water: at(900)
        })
    );
    assert_eq!(guard.state().session, session(1));
    assert_eq!(guard.state().ended, BTreeSet::from([lease, later]));
}

#[test]
fn a_lease_from_another_clock_session_is_refused_and_ends_in_that_guard() {
    let clock = Arc::new(RewindableClock::new(at(100)));
    let mut world = World::new(Arc::clone(&clock), session(1));
    let sandbox = execution("exe-task");
    let plan = world.plan(&sandbox, DAY);
    world.launch(plan);
    let lease = call_lease(&mut world, &sandbox, "op-call");
    // A guard presenting another session: the coordinator's session check refuses.
    let mut foreign = ExpiryGuard::new(session(9));
    assert_eq!(
        foreign.check(&world.coordinator, lease),
        Err(LifetimeRefusal::Lease {
            refusal: LeaseRefusal::OtherClock
        })
    );
    assert_eq!(
        foreign.check(&world.coordinator, lease),
        Err(LifetimeRefusal::Ended { lease })
    );
    assert_eq!(foreign.state().ended, BTreeSet::from([lease]));
    // The guard of the issuing session still honours it.
    let mut guard = ExpiryGuard::new(session(1));
    assert_eq!(
        guard
            .check(&world.coordinator, lease)
            .map(|lease| lease.clock()),
        Ok(session(1))
    );
    // An unknown lease is refused and ends as well.
    let unknown = LeaseId::new(9_999);
    assert_eq!(
        guard.check(&world.coordinator, unknown),
        Err(LifetimeRefusal::Lease {
            refusal: LeaseRefusal::UnknownLease { lease: unknown }
        })
    );
    assert!(guard.state().ended.contains(&unknown));
}

#[test]
fn a_restored_guard_keeps_ended_leases_ended_on_any_clock_session() {
    let clock = Arc::new(RewindableClock::new(at(100)));
    let mut world = World::new(Arc::clone(&clock), session(1));
    let sandbox = execution("exe-task");
    let plan = world.plan(&sandbox, DAY);
    world.launch(plan);
    let lease = call_lease(&mut world, &sandbox, "op-call");
    let live = call_lease(&mut world, &sandbox, "op-live");
    let mut guard = ExpiryGuard::new(session(1));
    clock.set(at(300));
    assert!(guard.check(&world.coordinator, lease).is_ok());
    clock.set(at(200));
    assert!(matches!(
        guard.check(&world.coordinator, lease),
        Err(LifetimeRefusal::Lease {
            refusal: LeaseRefusal::ClockWentBack { .. }
        })
    ));
    clock.set(at(400));
    // The guard persists and keeps the lease ended after a restart on the same session.
    let persisted = serde_json::to_string(guard.state()).unwrap();
    let state: GuardState = serde_json::from_str(&persisted).unwrap();
    assert_eq!(&state, guard.state());
    let mut same = ExpiryGuard::restore(state.clone(), session(1));
    assert_eq!(
        same.check(&world.coordinator, lease),
        Err(LifetimeRefusal::Ended { lease })
    );
    assert!(same.check(&world.coordinator, live).is_ok());
    // On a new clock session the ended leases stay ended, and a lease issued on the old
    // session is refused by the coordinator's session check.
    let mut restarted = ExpiryGuard::restore(state, session(2));
    assert_eq!(restarted.state().session, session(2));
    assert_eq!(restarted.state().ended, BTreeSet::from([lease]));
    assert_eq!(
        restarted.check(&world.coordinator, lease),
        Err(LifetimeRefusal::Ended { lease })
    );
    assert_eq!(
        restarted.check(&world.coordinator, live),
        Err(LifetimeRefusal::Lease {
            refusal: LeaseRefusal::OtherClock
        })
    );
    // The new session's coordinator never sees an ended lease either.
    let fresh = World::new(Arc::clone(&clock), session(2));
    assert_eq!(
        restarted.check(&fresh.coordinator, lease),
        Err(LifetimeRefusal::Ended { lease })
    );
    assert_eq!(
        restarted.check(&fresh.coordinator, live),
        Err(LifetimeRefusal::Ended { lease: live })
    );
}

#[test]
fn a_guard_state_reads_back_strictly() {
    let mut state = GuardState {
        session: session(1),
        ended: BTreeSet::from([LeaseId::new(3), LeaseId::new(7)]),
    };
    let persisted = serde_json::to_string(&state).unwrap();
    assert_eq!(
        serde_json::from_str::<GuardState>(&persisted).unwrap(),
        state
    );
    let fields: Vec<String> = match serde_json::from_str::<serde_json::Value>(&persisted).unwrap() {
        serde_json::Value::Object(map) => map.keys().cloned().collect(),
        other => panic!("{other:?}"),
    };
    assert_eq!(fields, ["ended", "session"]);
    assert!(serde_json::from_str::<GuardState>(&persisted.replacen('{', "{\"x\":1,", 1)).is_err());
    // A state written while the guard kept its own high-water mark is refused.
    let old = persisted.replacen(
        '{',
        &format!(
            "{{\"high_water\":{},",
            serde_json::to_string(&at(700)).unwrap()
        ),
        1,
    );
    assert!(serde_json::from_str::<GuardState>(&old).is_err());
    state.ended.clear();
    let empty = serde_json::to_string(&state).unwrap();
    assert!(serde_json::from_str::<GuardState>(&empty.replace(",\"ended\":[]", "")).is_err());
}

fn skew() -> ClockSkewPolicy {
    ClockSkewPolicy {
        max_skew_seconds: 5,
        max_remote_lifetime_seconds: 3_600,
    }
}

fn right() -> RemoteExpiry {
    RemoteExpiry {
        right: digest("yougori/test/right/v1", &[b"provider-lease"]),
        issued_unix_seconds: 1_000,
        expires_unix_seconds: 1_100,
        remote_now_unix_seconds: 1_000,
    }
}

fn observation(local_unix_seconds: i64) -> RemoteObservation {
    RemoteObservation {
        sent_at: at(100),
        received_at: MonotonicTime::from_nanos(100_500_000_000),
        local_unix_seconds,
    }
}

#[test]
fn a_remote_expiry_becomes_a_conservative_local_deadline() {
    let mut guard = WallClockGuard::default();
    let local = skew()
        .localize(
            &right(),
            &observation(1_002),
            session(1),
            SandboxBootGeneration::FIRST,
            &mut guard,
        )
        .unwrap();
    // 100 s remain on the remote clock, less the 5 s allowance, counted from sending.
    assert_eq!(local.deadline, at(100 + 95));
    let boot = SandboxBootGeneration::FIRST;
    assert_eq!(local.check(at(194), session(1), boot, &mut guard), Ok(()));
    assert_eq!(
        local.check(at(195), session(1), boot, &mut guard),
        Err(SkewRefusal::Expired {
            right: right().right
        })
    );
    // Once seen expired it never revives, even at an earlier reading.
    assert_eq!(
        local.check(at(150), session(1), boot, &mut guard),
        Err(SkewRefusal::Ended {
            right: right().right
        })
    );
    assert_eq!(
        skew().localize(&right(), &observation(1_003), session(1), boot, &mut guard),
        Err(SkewRefusal::Ended {
            right: right().right
        })
    );
}

#[test]
fn excessive_skew_long_lifetimes_and_inconsistent_times_are_refused() {
    let boot = SandboxBootGeneration::FIRST;
    let localize = |remote: &RemoteExpiry, observed: &RemoteObservation| {
        skew().localize(
            remote,
            observed,
            session(1),
            boot,
            &mut WallClockGuard::default(),
        )
    };
    // A 0.5 s round trip rounds up to 1 s: 5 + 1 = 6 s allowed.
    assert!(localize(&right(), &observation(1_006)).is_ok());
    assert_eq!(
        localize(&right(), &observation(1_007)),
        Err(SkewRefusal::SkewExceeded {
            observed_seconds: 7,
            allowed_seconds: 6
        })
    );
    assert_eq!(
        localize(&right(), &observation(993)),
        Err(SkewRefusal::SkewExceeded {
            observed_seconds: 7,
            allowed_seconds: 6
        })
    );
    let immortal = RemoteExpiry {
        expires_unix_seconds: 1_000 + 3_601,
        ..right()
    };
    assert_eq!(
        localize(&immortal, &observation(1_000)),
        Err(SkewRefusal::LifetimeExceedsPolicy {
            lifetime_seconds: 3_601,
            max_seconds: 3_600
        })
    );
    let future_issue = RemoteExpiry {
        issued_unix_seconds: 1_001,
        ..right()
    };
    assert_eq!(
        localize(&future_issue, &observation(1_000)),
        Err(SkewRefusal::InconsistentRemote)
    );
    let backwards = RemoteExpiry {
        expires_unix_seconds: 1_000,
        ..right()
    };
    assert_eq!(
        localize(&backwards, &observation(1_000)),
        Err(SkewRefusal::InconsistentRemote)
    );
    let reversed = RemoteObservation {
        sent_at: at(101),
        ..observation(1_000)
    };
    assert_eq!(
        localize(&right(), &reversed),
        Err(SkewRefusal::InvalidObservation)
    );
    // 5 s left is within the allowance: already expired, and remembered.
    let nearly = RemoteExpiry {
        remote_now_unix_seconds: 1_095,
        ..right()
    };
    let mut guard = WallClockGuard::default();
    assert_eq!(
        skew().localize(&nearly, &observation(1_095), session(1), boot, &mut guard),
        Err(SkewRefusal::Expired {
            right: right().right
        })
    );
    assert!(guard.ended.contains(&right().right));
}

#[test]
fn wall_clock_rollback_restart_and_snapshot_restore_never_revive_a_right() {
    let boot = SandboxBootGeneration::FIRST;
    let mut guard = WallClockGuard::default();
    let local = skew()
        .localize(&right(), &observation(1_002), session(1), boot, &mut guard)
        .unwrap();
    assert_eq!(guard.high_water_unix_seconds, 1_002);
    // The local wall clock is set back: refused.
    let other = RemoteExpiry {
        right: digest("yougori/test/right/v1", &[b"another"]),
        ..right()
    };
    assert_eq!(
        skew().localize(&other, &observation(990), session(1), boot, &mut guard),
        Err(SkewRefusal::LocalClockRollback {
            local_unix_seconds: 990,
            high_water_unix_seconds: 1_002
        })
    );
    // A snapshot restore boots again; the deadline is bound to the old boot.
    let restored = boot.next().unwrap();
    assert_eq!(
        local.check(at(120), session(1), restored, &mut guard),
        Err(SkewRefusal::RestoredBoot {
            bound: boot,
            current: restored
        })
    );
    // A restart starts a new clock session; the old deadline cannot be compared.
    assert_eq!(
        local.check(at(120), session(2), boot, &mut guard),
        Err(SkewRefusal::OtherSession)
    );
    // The right expires, and the persisted guard keeps it ended across a restart even when
    // the remote replays its old answer.
    assert!(local.check(at(195), session(1), boot, &mut guard).is_err());
    let persisted = serde_json::to_string(&guard).unwrap();
    let mut reloaded: WallClockGuard = serde_json::from_str(&persisted).unwrap();
    assert_eq!(
        skew().localize(
            &right(),
            &observation(1_002),
            session(2),
            boot,
            &mut reloaded
        ),
        Err(SkewRefusal::Ended {
            right: right().right
        })
    );
}

#[test]
fn vm_d7_engine_death_and_gui_closure_per_class() {
    let task = engine_death_response(SandboxClass::Task);
    assert_eq!(task.action, EngineDeathAction::EndWithEngine);
    assert_eq!(task.existing_operations, ExistingOperations::EndWithSandbox);
    let service = engine_death_response(SandboxClass::Service);
    assert_eq!(
        service.action,
        EngineDeathAction::ContinueUnderSupervisorLeases
    );
    assert_eq!(
        service.existing_operations,
        ExistingOperations::FollowBoundedLeases
    );
    for response in [task, service] {
        assert_eq!(
            response.new_privileged_authorizations,
            NewAuthorizations::DeniedUntilReconciliation
        );
        assert!(!response.treated_as_violation);
    }
    for class in [SandboxClass::Task, SandboxClass::Service] {
        assert!(gui_closed_response(class).sandbox_continues);
    }
}

#[test]
fn vm_d10_a_task_sandbox_stops_on_a_clear_violation() {
    let mut world = manual_world();
    let sandbox = execution("exe-task");
    let plan = world.plan(&sandbox, DAY);
    world.launch(plan);
    let outcome = respond_to_violation(
        &mut world.coordinator,
        &sandbox,
        SandboxClass::Task,
        &mut world.port,
    )
    .unwrap();
    match outcome {
        ViolationOutcome::Stopping { notice, status } => {
            assert_eq!(notice.execution, sandbox);
            assert!(
                matches!(status, RevocationStatus::Completed { .. }),
                "{status:?}"
            );
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(world.port.terminated.len(), 1);
    assert!(world.port.running.is_empty());
    assert!(world
        .coordinator
        .start_child_work(
            &sandbox,
            operation("op-after"),
            LeaseKind::ChildWork,
            task_policy().call_terms()
        )
        .is_err());
}

#[test]
fn vm_d10_a_service_sandbox_locks_down_with_a_one_click_stop() {
    let mut world = manual_world();
    let service = execution("exe-service");
    let plan = world.plan(&service, HOUR);
    world.launch(plan);
    let outcome = respond_to_violation(
        &mut world.coordinator,
        &service,
        SandboxClass::Service,
        &mut world.port,
    )
    .unwrap();
    let stop = match outcome {
        ViolationOutcome::LockedDown { notice, stop } => {
            assert!(notice.current > notice.revoked);
            stop
        }
        other => panic!("{other:?}"),
    };
    // Locked down: the VM is kept, but it holds no authority.
    assert_eq!(world.port.running.len(), 1);
    assert!(world.port.terminated.is_empty());
    assert!(world
        .coordinator
        .start_child_work(
            &service,
            operation("op-after"),
            LeaseKind::ChildWork,
            task_policy().call_terms()
        )
        .is_err());
    assert_eq!(stop.execution(), &service);
    let status = stop.stop(&mut world.coordinator, &mut world.port).unwrap();
    assert!(
        matches!(status, RevocationStatus::Completed { .. }),
        "{status:?}"
    );
    assert_eq!(world.port.terminated.len(), 1);
    assert_eq!(
        ViolationAction::for_class(SandboxClass::Task),
        ViolationAction::Stop
    );
    assert_eq!(
        ViolationAction::for_class(SandboxClass::Service),
        ViolationAction::LockDown
    );
    // Recorded decisions read back exactly; an unknown action is refused.
    for action in [ViolationAction::Stop, ViolationAction::LockDown] {
        let json = serde_json::to_string(&action).unwrap();
        assert_eq!(
            serde_json::from_str::<ViolationAction>(&json).unwrap(),
            action
        );
    }
    assert_eq!(
        serde_json::to_string(&ViolationAction::LockDown).unwrap(),
        "\"lock_down\""
    );
    assert!(serde_json::from_str::<ViolationAction>("\"pause\"").is_err());
}
