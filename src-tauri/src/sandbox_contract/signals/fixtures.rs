//! Test fixtures (tests only): the host clock and session, sandboxes and grants, V14's
//! default policies, and a responder that assesses and answers signals the way the runtime
//! would. Nothing here touches the host.

use std::collections::BTreeSet;
use std::time::Duration;

use super::observed::Observed;
use crate::foundation::events::EmissionLimit;
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{
    digest, ExecutionCategory, ExecutionId, GrantId, ManualClock, MonotonicTime, TrustScope,
};
use crate::sandbox_contract::files::SandboxClass;
use crate::sandbox_contract::response::{
    assess_violation, Assessment, MonitoringSignal, NotifyPolicy, Responder, ResponseAction,
    ResponseBounds, ResponseOutcome, ResponsePolicies, ResponseRecord, SignalAssessment,
    SignalDraft, UncertainPolicy,
};

pub const SECOND: Duration = Duration::from_secs(1);
pub const MINUTE: Duration = Duration::from_secs(60);

/// Where every test clock starts: 1,000 s after its origin.
pub const START_SECONDS: u64 = 1_000;

pub fn at(seconds: u64) -> MonotonicTime {
    MonotonicTime::from_nanos(seconds * 1_000_000_000)
}

pub fn session(number: u128) -> ClockSession {
    ClockSession::from_uuid(uuid::Uuid::from_u128(number))
}

/// The shared host clock's session in these tests.
pub fn host_session() -> ClockSession {
    session(1)
}

pub fn clock() -> ManualClock {
    ManualClock::new(at(START_SECONDS))
}

pub fn execution(name: &str) -> ExecutionId {
    ExecutionId::new(name).unwrap()
}

pub fn grant(name: &str) -> GrantId {
    GrantId::from_digest(digest("yougori/test/grant/v1", &[name.as_bytes()]))
}

/// The trust scope the host assigned `sandbox`.
pub fn scope_of(sandbox: &str) -> TrustScope {
    TrustScope::named(ExecutionCategory::VmSandbox, sandbox)
}

/// An observation about `sandbox` stamped now on the host clock.
pub fn observed(sandbox: &str, now: &ManualClock) -> Observed {
    Observed::read(execution(sandbox), now, host_session())
}

/// Observations older than 30 s are stale.
pub fn uncertain() -> UncertainPolicy {
    UncertainPolicy::new(30 * SECOND).unwrap()
}

/// V14's default triggers; three notifications per sandbox and minute.
pub fn policies() -> ResponsePolicies {
    ResponsePolicies::with_default_triggers(
        NotifyPolicy::new(EmissionLimit::new(3, MINUTE).unwrap()),
        uncertain(),
    )
}

/// Two repeats per sandbox and minute; 64 incidents; 16 sandboxes.
pub fn bounds() -> ResponseBounds {
    ResponseBounds::new(EmissionLimit::new(2, MINUTE).unwrap(), 64, 16).unwrap()
}

/// The V14 signal of a draft; the test fails if V14 refuses it.
pub fn signal(draft: SignalDraft) -> MonitoringSignal {
    MonitoringSignal::new(draft).unwrap()
}

/// V14's assessment of one incident's signals at the clock's time.
pub fn assess(signals: &[MonitoringSignal], now: &ManualClock) -> SignalAssessment {
    match assess_violation(signals, &uncertain(), now, host_session()).unwrap() {
        Assessment::Signal(assessment) => assessment,
        other => panic!("expected a signal, got {other:?}"),
    }
}

/// A V14 responder on `now` with default policies and `sandboxes` registered, each with
/// its class and grants.
pub fn responder_with<'a>(
    now: &'a ManualClock,
    sandboxes: &[(&str, SandboxClass, &[GrantId])],
) -> Responder<&'a ManualClock> {
    let mut responder = Responder::new(now, policies(), bounds());
    for (name, class, grants) in sandboxes {
        responder
            .register_sandbox(
                execution(name),
                *class,
                grants.iter().copied().collect::<BTreeSet<_>>(),
            )
            .unwrap();
    }
    responder
}

/// The responder's outcome as a record.
pub fn responded(outcome: ResponseOutcome) -> ResponseRecord {
    match outcome {
        ResponseOutcome::Responded(record) => record,
        other => panic!("expected a response, got {other:?}"),
    }
}

/// One draft through V14 end to end: checked, assessed alone at the clock's time and
/// answered by a responder that knows only the draft's sandbox as a task sandbox.
pub fn respond_alone(draft: SignalDraft, now: &ManualClock) -> ResponseRecord {
    let sandbox = draft.sandbox.clone();
    let assessment = assess(&[signal(draft)], now);
    let mut responder = responder_with(now, &[(sandbox.as_str(), SandboxClass::Task, &[])]);
    responded(responder.respond_to(&assessment).unwrap())
}

/// The actions of a fresh host-observed known violation under the default policies.
pub fn violation_actions(stops: bool) -> BTreeSet<ResponseAction> {
    let mut actions = BTreeSet::from([
        ResponseAction::NotifyUser,
        ResponseAction::DenyNewHighImpact,
        ResponseAction::Isolate,
        ResponseAction::Revoke,
    ]);
    if stops {
        actions.insert(ResponseAction::Stop);
    }
    actions
}

/// The actions of an uncertain result: notify and deny new high-impact operations.
pub fn uncertain_actions() -> BTreeSet<ResponseAction> {
    UncertainPolicy::ACTIONS.into_iter().collect()
}
