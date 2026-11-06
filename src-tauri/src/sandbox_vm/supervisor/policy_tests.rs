//! The lifetime supervisor's rules over fake VMs (module notes in `policy.rs`).

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use super::*;

#[derive(Default)]
struct FakeState {
    ended: Option<LifetimeEnded>,
    kills: u32,
    /// A kill that is not observed (the end cannot be proven).
    unkillable: bool,
}

#[derive(Clone)]
struct Fake {
    pid: u32,
    state: Rc<RefCell<FakeState>>,
}

impl Fake {
    fn new(pid: u32) -> Self {
        Self {
            pid,
            state: Rc::default(),
        }
    }

    fn end_itself(&self) {
        self.state.borrow_mut().ended = Some(LifetimeEnded {
            exit_code: Some(0),
            job_processes: 1,
            kill_rounds: 0,
            elapsed: Duration::ZERO,
        });
    }

    fn kills(&self) -> u32 {
        self.state.borrow().kills
    }
}

impl Lifetime for Fake {
    fn identity(&self) -> ProcessIdentity {
        ProcessIdentity {
            pid: self.pid,
            start_time_ticks: u64::from(self.pid) * 10,
        }
    }

    fn ended(&self) -> Option<LifetimeEnded> {
        self.state.borrow().ended
    }

    fn terminate(&self, _kill_wait: Duration) -> Result<LifetimeEnded, String> {
        let mut state = self.state.borrow_mut();
        state.kills += 1;
        if state.unkillable {
            return Err("the job still holds a process".to_owned());
        }
        let ended = LifetimeEnded {
            exit_code: Some(1),
            job_processes: 1,
            kill_rounds: 1,
            elapsed: Duration::from_millis(3),
        };
        state.ended = Some(ended);
        Ok(ended)
    }
}

const SETTINGS: SupervisorSettings = SupervisorSettings {
    silence_ms: 60_000,
    grace_ms: 30_000,
    kill_wait_ms: 1_000,
};

fn sandbox(name: &str) -> ExecutionId {
    ExecutionId::new(name).unwrap()
}

fn terms(idle_s: u64, absolute_s: Option<u64>, renewal_s: Option<u64>) -> Terms {
    Terms {
        idle_left_ms: idle_s * 1000,
        absolute_left_ms: absolute_s.map(|s| s * 1000),
        renewal_left_ms: renewal_s.map(|s| s * 1000),
        delegation_deadline_host_ns: None,
    }
}

fn s(seconds: u64) -> Duration {
    Duration::from_secs(seconds)
}

fn delegated(deadline_seconds: u64) -> Terms {
    Terms {
        delegation_deadline_host_ns: Some(deadline_seconds * 1_000_000_000),
        ..terms(3600, None, None)
    }
}

/// Arrival after seven seconds leaves three seconds, not a fresh TTL or the
/// ordinary thirty-second cleanup grace. Arrival after expiry ends immediately.
#[test]
fn delegation_subtracts_transit_and_never_gets_cleanup_grace() {
    for arrival in [107, 111] {
        let start = MonotonicTime::from_nanos(1);
        let mut supervision = Supervision::new(SETTINGS, start);
        let vm = Fake::new(1);
        supervision
            .hold_at(
                sandbox("exe-remote"),
                SandboxClass::Service,
                vm.clone(),
                delegated(110),
                start,
                arrival * 1_000_000_000,
            )
            .unwrap();
        let left = 110_u64.saturating_sub(arrival);
        if left > 0 {
            assert!(supervision
                .tick(start.saturating_add(s(left - 1)), true)
                .1
                .is_empty());
        }
        let ends = supervision.tick(start.saturating_add(s(left)), true).1;
        assert_eq!(ends.len(), 1);
        assert_eq!(ends[0].cause, EndCause::RenewalLimit);
        assert_eq!(vm.kills(), 1);
    }
}

/// Missing terms cannot remove the installed limit. A late queued renewal cannot
/// replace it, even when the supervisor paused after reading its process clock.
#[test]
fn delegation_survives_omission_and_rejects_late_queued_renewal() {
    for (replacement, local_seconds, host_seconds) in [
        (terms(3600, None, None), 5, 105),
        (delegated(160), 10, 110),
        (delegated(160), 5, 111),
    ] {
        let start = MonotonicTime::from_nanos(1);
        let mut supervision = Supervision::new(SETTINGS, start);
        supervision
            .hold_at(
                sandbox("exe-remote"),
                SandboxClass::Service,
                Fake::new(1),
                delegated(110),
                start,
                100_000_000_000,
            )
            .unwrap();
        supervision.leases_at(
            &[SandboxTerms {
                sandbox: sandbox("exe-remote"),
                terms: replacement,
            }],
            start.saturating_add(s(local_seconds)),
            host_seconds * 1_000_000_000,
        );
        let ends = supervision.tick(start.saturating_add(s(11)), true).1;
        assert_eq!(ends.len(), 1);
        assert_eq!(ends[0].cause, EndCause::RenewalLimit);
    }
}

/// A timely grant really extends service; its own remaining time is still
/// bounded at the host deadline, independently of ordinary lease renewal.
#[test]
fn live_delegation_can_renew_only_to_the_new_host_deadline() {
    let start = MonotonicTime::from_nanos(1);
    let mut supervision = Supervision::new(SETTINGS, start);
    supervision
        .hold_at(
            sandbox("exe-remote"),
            SandboxClass::Service,
            Fake::new(1),
            delegated(110),
            start,
            100_000_000_000,
        )
        .unwrap();
    supervision.leases_at(
        &[SandboxTerms {
            sandbox: sandbox("exe-remote"),
            terms: delegated(120),
        }],
        start.saturating_add(s(5)),
        105_000_000_000,
    );
    assert!(supervision
        .tick(start.saturating_add(s(19)), true)
        .1
        .is_empty());
    let ends = supervision.tick(start.saturating_add(s(20)), true).1;
    assert_eq!(ends.len(), 1);
    assert_eq!(ends[0].cause, EndCause::RenewalLimit);
}

/// Ticks every second from `from` to `to` (exclusive of `from`), the engine speaking at
/// each when `speaking`; the ends observed.
fn run(
    supervision: &mut Supervision<Fake>,
    start: MonotonicTime,
    from: u64,
    to: u64,
    speaking: bool,
    alive: bool,
) -> Vec<HeldEnd> {
    let mut ends = Vec::new();
    for second in from + 1..=to {
        let now = start.saturating_add(s(second));
        if speaking {
            supervision.heard(now);
        }
        ends.extend(supervision.tick(now, alive).1);
    }
    ends
}

/// PROVES the engine's death ends every task sandbox's VM at the next tick and leaves a
/// service sandbox's VM to its own limit (VM-D7), after which it ends too and the
/// supervisor is finished.
#[test]
fn a_dead_engine_ends_task_vms_and_service_vms_run_to_their_limits() {
    let start = MonotonicTime::from_nanos(1);
    let mut supervision = Supervision::new(SETTINGS, start);
    let (task, service) = (Fake::new(1), Fake::new(2));
    supervision
        .hold(
            sandbox("exe-task"),
            SandboxClass::Task,
            task.clone(),
            terms(3600, Some(7200), None),
            start,
        )
        .unwrap();
    supervision
        .hold(
            sandbox("exe-service"),
            SandboxClass::Service,
            service.clone(),
            terms(600, None, Some(900)),
            start,
        )
        .unwrap();
    assert!(run(&mut supervision, start, 0, 5, true, true).is_empty());
    let (changes, ends) = supervision.tick(start.saturating_add(s(6)), false);
    assert_eq!(changes, vec![EngineChange::Died]);
    assert_eq!(ends.len(), 1);
    assert_eq!(ends[0].sandbox, sandbox("exe-task"));
    assert_eq!(ends[0].cause, EndCause::EngineDied);
    assert_eq!(ends[0].decided_after_ms, Some(0));
    assert_eq!((task.kills(), service.kills()), (1, 0));
    assert!(!supervision.finished(), "the service VM is still held");
    // The service VM's idle limit (600 s) and grace (30 s) pass with no engine to renew it.
    assert!(run(&mut supervision, start, 6, 629, false, false).is_empty());
    let ends = run(&mut supervision, start, 629, 631, false, false);
    assert_eq!(ends.len(), 1);
    assert_eq!(ends[0].cause, EndCause::IdleLimit);
    assert_eq!(ends[0].at_ms, 630_000);
    assert!(supervision.finished());
}

/// PROVES an engine silent for the silence bound counts as failed: its task VMs end, a
/// hold is refused meanwhile, and once it speaks again it is answered again (what ended
/// stays ended).
#[test]
fn a_silent_engine_ends_task_vms_and_is_answered_again_when_it_speaks() {
    let start = MonotonicTime::from_nanos(1);
    let mut supervision = Supervision::new(SETTINGS, start);
    let task = Fake::new(1);
    supervision
        .hold(
            sandbox("exe-task"),
            SandboxClass::Task,
            task.clone(),
            terms(3600, Some(7200), None),
            start,
        )
        .unwrap();
    assert!(run(&mut supervision, start, 0, 59, false, true).is_empty());
    let (changes, ends) = supervision.tick(start.saturating_add(s(60)), true);
    assert!(
        matches!(changes.as_slice(), [EngineChange::Silent { .. }]),
        "{changes:?}"
    );
    assert_eq!(ends.len(), 1);
    assert_eq!(ends[0].cause, EndCause::EngineSilent);
    assert_eq!(ends[0].decided_after_ms, Some(0));
    assert!(supervision
        .hold(
            sandbox("exe-other"),
            SandboxClass::Task,
            Fake::new(3),
            terms(60, None, None),
            start.saturating_add(s(61))
        )
        .is_err());
    assert_eq!(
        supervision.heard(start.saturating_add(s(62))),
        Some(EngineChange::AnsweringAgain)
    );
    assert_eq!(supervision.engine(), EngineState::Answering);
    assert_eq!(
        supervision.take_ends().len(),
        1,
        "kept for the engine's next reply"
    );
    supervision
        .hold(
            sandbox("exe-other"),
            SandboxClass::Task,
            Fake::new(3),
            terms(60, None, None),
            start.saturating_add(s(62)),
        )
        .unwrap();
    assert!(!supervision.finished());
}

/// PROVES the lease backstop: a VM whose idle, absolute or renewal limit passed by the
/// grace without the engine's revocation is ended for that limit; terms the engine sends
/// move the deadlines, and a VM within its terms is left alone.
#[test]
fn the_lease_backstop_ends_a_vm_past_its_limit_and_grace() {
    let start = MonotonicTime::from_nanos(1);
    let mut supervision = Supervision::new(SETTINGS, start);
    let (idle, absolute, renewal, fine) = (Fake::new(1), Fake::new(2), Fake::new(3), Fake::new(4));
    supervision
        .hold(
            sandbox("exe-idle"),
            SandboxClass::Task,
            idle.clone(),
            terms(10, Some(1000), None),
            start,
        )
        .unwrap();
    supervision
        .hold(
            sandbox("exe-absolute"),
            SandboxClass::Task,
            absolute.clone(),
            terms(1000, Some(20), None),
            start,
        )
        .unwrap();
    supervision
        .hold(
            sandbox("exe-renewal"),
            SandboxClass::Service,
            renewal.clone(),
            terms(1000, None, Some(30)),
            start,
        )
        .unwrap();
    supervision
        .hold(
            sandbox("exe-fine"),
            SandboxClass::Task,
            fine.clone(),
            terms(10, Some(1000), None),
            start,
        )
        .unwrap();
    let mut ends = Vec::new();
    for second in 1..=70 {
        let now = start.saturating_add(s(second));
        supervision.heard(now);
        // The engine keeps renewing exe-fine's idle limit, as a busy sandbox's would be.
        supervision.leases(
            &[SandboxTerms {
                sandbox: sandbox("exe-fine"),
                terms: terms(10, Some(1000 - second), None),
            }],
            now,
        );
        ends.extend(supervision.tick(now, true).1);
    }
    let causes: Vec<(String, EndCause, Option<u64>)> = ends
        .iter()
        .map(|end| (end.sandbox.to_string(), end.cause, end.decided_after_ms))
        .collect();
    assert_eq!(
        causes,
        vec![
            ("exe-idle".to_owned(), EndCause::IdleLimit, Some(0)),
            ("exe-absolute".to_owned(), EndCause::AbsoluteLimit, Some(0)),
            ("exe-renewal".to_owned(), EndCause::RenewalLimit, Some(0)),
        ]
    );
    assert_eq!(ends[0].at_ms, 40_000, "10 s idle and 30 s grace");
    assert_eq!(fine.kills(), 0);
    assert_eq!(supervision.holding(), 1);
}

/// A scheduling pause cannot manufacture an engine heartbeat or extend any lease.
#[test]
fn a_gap_enforces_engine_silence_and_all_expired_lease_classes() {
    let start = MonotonicTime::from_nanos(1);
    let mut supervision = Supervision::new(SETTINGS, start);
    let cases = [
        (
            "task",
            SandboxClass::Task,
            terms(1000, None, None),
            EndCause::EngineSilent,
        ),
        (
            "idle",
            SandboxClass::Service,
            terms(20, None, None),
            EndCause::IdleLimit,
        ),
        (
            "absolute",
            SandboxClass::Service,
            terms(1000, Some(40), None),
            EndCause::AbsoluteLimit,
        ),
        (
            "renewal",
            SandboxClass::Service,
            terms(1000, None, Some(50)),
            EndCause::RenewalLimit,
        ),
    ];
    for (index, (name, class, terms, _)) in cases.iter().enumerate() {
        supervision
            .hold(
                sandbox(name),
                *class,
                Fake::new(index as u32 + 1),
                *terms,
                start,
            )
            .unwrap();
    }
    let now = start.saturating_add(s(200));
    let (changes, ends) = supervision.tick(now, true);
    assert!(matches!(
        changes.as_slice(),
        [EngineChange::Gap { .. }, EngineChange::Silent { .. }]
    ));
    for (name, _, _, cause) in cases {
        assert_eq!(
            ends.iter()
                .find(|end| end.sandbox == sandbox(name))
                .unwrap()
                .cause,
            cause
        );
    }
    assert_eq!(supervision.holding(), 0);
    supervision.heard(now);
    supervision.leases(
        &[SandboxTerms {
            sandbox: sandbox("idle"),
            terms: terms(500, None, None),
        }],
        now,
    );
    assert_eq!(
        supervision.holding(),
        0,
        "a resumed engine cannot revive ended VMs"
    );
}

#[test]
fn a_gap_does_not_end_a_service_still_within_its_lease() {
    let start = MonotonicTime::from_nanos(1);
    let mut supervision = Supervision::new(SETTINGS, start);
    let service = Fake::new(1);
    supervision
        .hold(
            sandbox("service"),
            SandboxClass::Service,
            service.clone(),
            terms(600, None, Some(900)),
            start,
        )
        .unwrap();
    assert!(supervision
        .tick(start.saturating_add(s(200)), true)
        .1
        .is_empty());
    assert_eq!(service.kills(), 0);
    let ends = supervision.tick(start.saturating_add(s(630)), true).1;
    assert_eq!(ends.len(), 1);
    assert_eq!(ends[0].cause, EndCause::IdleLimit);
}

#[test]
fn a_late_renewal_cannot_reset_an_expired_backstop_before_tick() {
    for limits in [
        terms(1, None, None),
        terms(1000, Some(1), None),
        terms(1000, None, Some(1)),
    ] {
        let start = MonotonicTime::from_nanos(1);
        let mut supervision = Supervision::new(SETTINGS, start);
        supervision
            .hold(
                sandbox("service"),
                SandboxClass::Service,
                Fake::new(1),
                limits,
                start,
            )
            .unwrap();
        let now = start.saturating_add(s(31));
        supervision.leases(
            &[SandboxTerms {
                sandbox: sandbox("service"),
                terms: terms(500, Some(900), Some(800)),
            }],
            now,
        );
        assert_eq!(supervision.tick(now, true).1.len(), 1);
    }
}

#[test]
fn absolute_limit_cannot_be_extended_or_removed_by_new_terms() {
    for absolute in [None, Some(500)] {
        let start = MonotonicTime::from_nanos(1);
        let mut supervision = Supervision::new(SETTINGS, start);
        supervision
            .hold(
                sandbox("service"),
                SandboxClass::Service,
                Fake::new(1),
                terms(1000, Some(10), None),
                start,
            )
            .unwrap();
        supervision.leases(
            &[SandboxTerms {
                sandbox: sandbox("service"),
                terms: terms(1000, absolute, None),
            }],
            start.saturating_add(s(5)),
        );
        let ends = supervision.tick(start.saturating_add(s(40)), true).1;
        assert_eq!(ends.len(), 1);
        assert_eq!(ends[0].cause, EndCause::AbsoluteLimit);
    }
}

/// PROVES an end that cannot be observed is not reported: the VM is listed unended and
/// killed again at each tick until its end is observed.
#[test]
fn an_end_not_observed_is_tried_again_and_listed_unended() {
    let start = MonotonicTime::from_nanos(1);
    let mut supervision = Supervision::new(SETTINGS, start);
    let task = Fake::new(1);
    task.state.borrow_mut().unkillable = true;
    supervision
        .hold(
            sandbox("exe-task"),
            SandboxClass::Task,
            task.clone(),
            terms(3600, None, None),
            start,
        )
        .unwrap();
    assert!(supervision
        .tick(start.saturating_add(s(1)), false)
        .1
        .is_empty());
    assert!(supervision
        .tick(start.saturating_add(s(2)), false)
        .1
        .is_empty());
    assert_eq!(task.kills(), 2);
    assert_eq!(supervision.unended(), vec![sandbox("exe-task")]);
    assert!(!supervision.finished());
    task.state.borrow_mut().unkillable = false;
    let ends = supervision.tick(start.saturating_add(s(3)), false).1;
    assert_eq!(ends.len(), 1);
    assert_eq!(ends[0].cause, EndCause::EngineDied);
    assert_eq!(
        ends[0].decided_after_ms,
        Some(2000),
        "decided when the engine died"
    );
    assert!(supervision.unended().is_empty());
    assert!(supervision.finished());
}

/// PROVES a VM that ends without the supervisor is reported as such, a released one is
/// forgotten (its end returned when it had ended), holds are bounded and a sandbox is held
/// once, and an orderly shutdown lets every VM go without killing any.
#[test]
fn ends_without_the_supervisor_releases_and_bounds() {
    let start = MonotonicTime::from_nanos(1);
    let mut supervision = Supervision::new(SETTINGS, start);
    let (a, b, c) = (Fake::new(1), Fake::new(2), Fake::new(3));
    supervision
        .hold(
            sandbox("exe-a"),
            SandboxClass::Task,
            a.clone(),
            terms(3600, None, None),
            start,
        )
        .unwrap();
    supervision
        .hold(
            sandbox("exe-b"),
            SandboxClass::Task,
            b.clone(),
            terms(3600, None, None),
            start,
        )
        .unwrap();
    assert!(supervision
        .hold(
            sandbox("exe-a"),
            SandboxClass::Task,
            Fake::new(9),
            terms(1, None, None),
            start
        )
        .is_err());
    a.end_itself();
    let ends = supervision.tick(start.saturating_add(s(1)), true).1;
    assert_eq!(ends.len(), 1);
    assert_eq!(ends[0].cause, EndCause::EndedWithoutSupervisor);
    assert_eq!(ends[0].decided_after_ms, None);
    assert_eq!(a.kills(), 0);
    b.end_itself();
    let released = supervision
        .release(&sandbox("exe-b"), start.saturating_add(s(2)))
        .unwrap();
    assert_eq!(released.cause, EndCause::EndedWithoutSupervisor);
    assert!(supervision
        .release(&sandbox("exe-b"), start.saturating_add(s(2)))
        .is_none());
    supervision
        .hold(
            sandbox("exe-c"),
            SandboxClass::Task,
            c.clone(),
            terms(3600, None, None),
            start,
        )
        .unwrap();
    for index in 0..MAX_HELD - 1 {
        supervision
            .hold(
                sandbox(&format!("exe-n{index}")),
                SandboxClass::Task,
                Fake::new(100),
                terms(3600, None, None),
                start,
            )
            .unwrap();
    }
    assert!(supervision
        .hold(
            sandbox("exe-over"),
            SandboxClass::Task,
            Fake::new(200),
            terms(3600, None, None),
            start
        )
        .is_err());
    assert_eq!(supervision.release_all(), MAX_HELD);
    assert_eq!(c.kills(), 0);
    assert_eq!(supervision.holding(), 0);
}
