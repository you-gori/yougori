//! The engine's response path for what the sandbox executor observes (V14 into V05; module
//! docs in `mod.rs`). Every refused exchange of a running relay reaches the engine already
//! classified by the executor (`signals::broker::classify_broker_refusal`):
//!
//! - a violation becomes a host-observed monitoring signal about its sandbox and route,
//!   stamped with the engine's clock when the report arrives (the executor's clock is another
//!   process's, so its readings are never compared with the engine's), collected per sandbox,
//!   assessed and given to the responder, whose decision the engine audits and then enforces
//!   (`engine.rs`);
//! - a relay protocol fault (the confined relay forwarded what the broker's own rebuild or
//!   book contradicts) is told to the user and audited; it revokes nothing, because it speaks
//!   of the relay, not of the guest;
//! - an ordinary refusal (an undeclared operation, a limit, an upstream failure, a response
//!   the echo scan refused) is counted per reason, the last few kept with the broker's
//!   statement.
//!
//! Every sandbox with a relay is registered as a task sandbox (VM-D10: a violation stops it)
//! holding no shared grant (the broker's signals name none). A sandbox the path cannot
//! register gets no relay. What the status shows is bounded: per sandbox the counts, the last
//! refusals and decisions with their audit receipts and enforcement, the restrictions in
//! force; overall the notices for the user and the totals.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::Duration;

use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::foundation::events::{EmissionLimit, Field};
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{Clock, Digest, DigestBuilder, ExecutionId};
use crate::sandbox_contract::destinations::RouteId;
use crate::sandbox_contract::files::SandboxClass;
use crate::sandbox_contract::response::{
    assess_violation, MonitoringSignal, NotifyPolicy, Responder, ResponderRefusal,
    ResponseAction, ResponseBounds, ResponseOutcome, ResponsePolicies, ResponseRecord,
    UncertainPolicy,
};
use crate::sandbox_contract::signals::{
    route_subject, CollectorBounds, Observed, SignalCollector, ROUTE_SUBJECT_DOMAIN,
};

use super::executor::protocol::{RefusalClass, RefusedExchange};

/// Observations one sandbox's batch holds before a decision. Every one here is the host's;
/// no share is kept for guest reports, which this path never receives.
const PER_SANDBOX: usize = 16;
const GUEST_REPORTS: usize = 0;
/// Sandboxes the collector and the responder track at once.
pub const MAX_SANDBOXES: usize = 64;
/// Incidents the responder keeps before it folds new ones into one per sandbox and class.
const MAX_INCIDENTS: usize = 256;
/// A decision that adds nothing repeats at most this often per sandbox, and the user is
/// told at most this often per sandbox, within [`WINDOW`].
const REPEATS: u32 = 8;
const NOTIFICATIONS: u32 = 4;
const WINDOW: Duration = Duration::from_secs(60);
/// A host observation older than this is uncertain. The engine stamps each when it arrives
/// and assesses at once, so none here is.
const MAX_OBSERVATION_AGE: Duration = Duration::from_secs(60);
/// What the view keeps.
const RECENT_REFUSALS: usize = 8;
const RECENT_DECISIONS: usize = 16;
const RECENT_FAULTS: usize = 8;
const MAX_NOTICES: usize = 32;
const MAX_VIEWS: usize = 128;

/// One refused exchange as the view keeps it.
#[derive(Clone, Debug, Serialize)]
struct Refusal {
    route: String,
    exchange: u64,
    class: RefusalClass,
    detail: String,
    at_ns: u64,
}

/// One decision with what the engine audited and enforced for it.
#[derive(Clone, Debug, Serialize)]
struct DecisionView {
    record: ResponseRecord,
    audit: Vec<Value>,
    enforced: Vec<Value>,
}

/// One sandbox's part of the view.
#[derive(Clone, Debug, Default, Serialize)]
struct SandboxView {
    /// Whether decisions are taken for it: its relay started and it has not ended.
    registered: bool,
    /// Ordinary refusals by reason.
    ordinary: BTreeMap<String, u64>,
    relay_protocol: u64,
    violations: u64,
    deduplicated: u64,
    rate_bounded: u64,
    recent: VecDeque<Refusal>,
    decisions: VecDeque<DecisionView>,
    /// The audit receipts of its relay protocol faults.
    faults: VecDeque<Value>,
    /// The restrictions decisions put in force while it runs.
    restrictions: BTreeSet<ResponseAction>,
}

/// A note for the user (the `NotifyUser` action, a relay protocol fault). It names the
/// sandbox, the route and what was done; never a guest byte.
#[derive(Clone, Debug, Serialize)]
pub struct Notice {
    pub sandbox: ExecutionId,
    pub text: String,
    pub at_ns: u64,
}

/// A decision for the engine to audit and enforce: the signals it was assessed from and
/// the responder's record.
#[derive(Debug)]
pub struct Decided {
    pub signals: Vec<MonitoringSignal>,
    pub record: ResponseRecord,
}

/// A relay protocol fault for the engine to audit.
#[derive(Debug)]
pub struct RelayFault {
    pub sandbox: ExecutionId,
    pub fields: Vec<Field>,
}

/// Counts over every sandbox.
#[derive(Clone, Copy, Debug, Default, Serialize)]
struct Totals {
    /// Refusals the executor's bounded queue could not keep.
    executor_dropped: u64,
    /// Refusals of a sandbox no decision is taken for (not registered, or ended).
    unattributed: u64,
    /// Violation reports the collector, the assessment or the responder refused.
    refused: u64,
    /// Decisions made.
    decisions: u64,
}

/// The engine's response path (module docs).
pub struct ViolationResponses<C: Clock + Clone> {
    clock: C,
    session: ClockSession,
    collector: SignalCollector,
    responder: Responder<C>,
    views: BTreeMap<ExecutionId, SandboxView>,
    /// The order the views were made, so the oldest view of an ended sandbox goes first.
    order: VecDeque<ExecutionId>,
    notices: VecDeque<Notice>,
    /// Notices not yet shown on the desktop.
    unshown: Vec<Notice>,
    totals: Totals,
}

impl<C: Clock + Clone> ViolationResponses<C> {
    /// The path with the default policies (`ResponsePolicies::with_default_triggers`) and the
    /// bounds above; `session` stamps every observation it makes.
    pub fn new(clock: C, session: ClockSession) -> Result<Self, String> {
        let limit = |events| {
            EmissionLimit::new(events, WINDOW)
                .map_err(|error| format!("the response path's limit: {error:?}"))
        };
        let uncertain = UncertainPolicy::new(MAX_OBSERVATION_AGE)
            .map_err(|error| format!("the response path's uncertainty: {error:?}"))?;
        let policies =
            ResponsePolicies::with_default_triggers(NotifyPolicy::new(limit(NOTIFICATIONS)?), uncertain);
        let bounds = ResponseBounds::new(limit(REPEATS)?, MAX_INCIDENTS, MAX_SANDBOXES)
            .map_err(|error| format!("the response path's bounds: {error}"))?;
        let collector = SignalCollector::new(
            CollectorBounds::new(PER_SANDBOX, GUEST_REPORTS, MAX_SANDBOXES)
                .map_err(|error| format!("the response path's collector: {error:?}"))?,
        );
        Ok(Self {
            responder: Responder::new(clock.clone(), policies, bounds),
            clock,
            session,
            collector,
            views: BTreeMap::new(),
            order: VecDeque::new(),
            notices: VecDeque::new(),
            unshown: Vec::new(),
            totals: Totals::default(),
        })
    }

    /// `sandbox`'s relay is about to start: refusals and decisions are taken for it from now
    /// on. Refused when the path tracks as many sandboxes as it may; the relay then does not
    /// start, so no sandbox has a network nothing answers for.
    pub fn register(&mut self, sandbox: &ExecutionId) -> Result<(), String> {
        match self
            .responder
            .register_sandbox(sandbox.clone(), SandboxClass::Task, BTreeSet::new())
        {
            Ok(()) | Err(ResponderRefusal::AlreadyRegistered { .. }) => {}
            Err(refusal) => {
                return Err(format!(
                    "The violation response path cannot take sandbox {sandbox}: {refusal}."
                ))
            }
        }
        let view = self.view_mut(sandbox);
        view.registered = true;
        view.restrictions.clear();
        Ok(())
    }

    /// `sandbox` ended (stopped or revoked) or its relay never started: nothing more is
    /// decided for it, and its restrictions lapse with it. Its view stays for the status
    /// until newer views displace it.
    pub fn forget(&mut self, sandbox: &ExecutionId) {
        self.responder.forget_sandbox(sandbox);
        let _ = self.collector.take(sandbox);
        if let Some(view) = self.views.get_mut(sandbox) {
            view.registered = false;
            view.restrictions.clear();
        }
    }

    /// Takes the refusals the executor reported since the last look (`dropped`: those its
    /// bounded queue could not keep); the relay protocol faults to audit.
    pub fn ingest(&mut self, refusals: Vec<RefusedExchange>, dropped: u64) -> Vec<RelayFault> {
        self.totals.executor_dropped = self.totals.executor_dropped.saturating_add(dropped);
        let now = self.clock.now();
        let mut faults = Vec::new();
        for refused in refusals {
            if !self
                .views
                .get(&refused.sandbox)
                .is_some_and(|view| view.registered)
            {
                self.totals.unattributed = self.totals.unattributed.saturating_add(1);
                continue;
            }
            let subject = route_subject_of(&refused.route);
            match &refused.class {
                RefusalClass::Violation { kind, observer } => {
                    let draft = Observed {
                        sandbox: refused.sandbox.clone(),
                        at: now,
                        session: self.session,
                    }
                    .violation(*kind, *observer, subject, None);
                    if self.collector.collect(draft).is_err() {
                        self.totals.refused = self.totals.refused.saturating_add(1);
                    }
                    let view = self.view_mut(&refused.sandbox);
                    view.violations = view.violations.saturating_add(1);
                }
                RefusalClass::RelayProtocol => {
                    let view = self.view_mut(&refused.sandbox);
                    view.relay_protocol = view.relay_protocol.saturating_add(1);
                    self.notice(
                        &refused.sandbox,
                        format!(
                            "The relay of sandbox {} forwarded a request on route {} that its broker's own rebuild contradicts; the broker refused it. This concerns the relay, not the guest: nothing was revoked.",
                            refused.sandbox, refused.route
                        ),
                    );
                    faults.push(RelayFault {
                        sandbox: refused.sandbox.clone(),
                        fields: vec![
                            Field::metadata("event", "relay_protocol_fault"),
                            Field::metadata("sandbox", refused.sandbox.as_str()),
                            Field::metadata("subject", subject),
                            Field::metadata("exchange", refused.exchange),
                            Field::metadata("observer", "broker"),
                        ],
                    });
                }
                RefusalClass::Ordinary { reason } => {
                    let view = self.view_mut(&refused.sandbox);
                    let count = view.ordinary.entry(reason.clone()).or_default();
                    *count = count.saturating_add(1);
                }
            }
            let view = self.view_mut(&refused.sandbox);
            if view.recent.len() >= RECENT_REFUSALS {
                view.recent.pop_front();
            }
            view.recent.push_back(Refusal {
                route: refused.route,
                exchange: refused.exchange,
                class: refused.class,
                detail: refused.detail,
                at_ns: now.as_nanos(),
            });
        }
        faults
    }

    /// Assesses every batch collected and gives each incident to the responder; the
    /// decisions to audit and enforce, in order.
    pub fn decide(&mut self) -> Vec<Decided> {
        let mut decided = Vec::new();
        for batch in self.collector.take_all() {
            for (_, signals) in batch.incidents() {
                let assessment = match assess_violation(
                    &signals,
                    self.responder.policies().uncertain(),
                    &self.clock,
                    self.session,
                ) {
                    Ok(assessment) => assessment,
                    Err(_) => {
                        self.totals.refused = self.totals.refused.saturating_add(1);
                        continue;
                    }
                };
                match self.responder.respond(&assessment) {
                    Ok(ResponseOutcome::Responded(record)) => {
                        self.totals.decisions = self.totals.decisions.saturating_add(1);
                        decided.push(Decided { signals, record });
                    }
                    Ok(ResponseOutcome::Deduplicated { .. }) => {
                        let view = self.view_mut(batch.sandbox());
                        view.deduplicated = view.deduplicated.saturating_add(1);
                    }
                    Ok(ResponseOutcome::RateBounded { .. }) => {
                        let view = self.view_mut(batch.sandbox());
                        view.rate_bounded = view.rate_bounded.saturating_add(1);
                    }
                    Ok(ResponseOutcome::NoViolationObserved) => {}
                    Err(_) => {
                        self.totals.refused = self.totals.refused.saturating_add(1);
                    }
                }
            }
        }
        decided
    }

    /// Keeps a decision with what the engine audited and enforced for it.
    pub fn settle(&mut self, record: ResponseRecord, audit: Vec<Value>, enforced: Vec<Value>) {
        let view = self.view_mut(&record.key.sandbox.clone());
        if view.decisions.len() >= RECENT_DECISIONS {
            view.decisions.pop_front();
        }
        view.decisions.push_back(DecisionView {
            record,
            audit,
            enforced,
        });
    }

    /// Keeps the audit receipt (or refusal) of a relay protocol fault of `sandbox`.
    pub fn fault_audited(&mut self, sandbox: &ExecutionId, audit: Value) {
        let view = self.view_mut(sandbox);
        if view.faults.len() >= RECENT_FAULTS {
            view.faults.pop_front();
        }
        view.faults.push_back(audit);
    }

    /// Puts `action` in force on `sandbox` while it runs (a decision's `DenyNewHighImpact`
    /// or `Isolate`); a sandbox that ended keeps none.
    pub fn restrict(&mut self, sandbox: &ExecutionId, action: ResponseAction) {
        if let Some(view) = self.views.get_mut(sandbox) {
            if view.registered {
                view.restrictions.insert(action);
            }
        }
    }

    /// Whether a new command may run on `sandbox`: not while a decision isolates it or
    /// denies it new high-impact operations (the engine's reading: a command on the guest's
    /// shell is the one new operation the engine starts in a running sandbox).
    pub fn admits_exec(&self, sandbox: &ExecutionId) -> Result<(), String> {
        let Some(view) = self.views.get(sandbox) else {
            return Ok(());
        };
        if view.restrictions.contains(&ResponseAction::Isolate) {
            return Err(format!(
                "Sandbox {sandbox} is isolated by a violation response; stop or revoke it."
            ));
        }
        if view
            .restrictions
            .contains(&ResponseAction::DenyNewHighImpact)
        {
            return Err(format!(
                "A violation response denies new commands on sandbox {sandbox}; stop or revoke it."
            ));
        }
        Ok(())
    }

    /// A note for the user about `sandbox`, kept for the status and shown on the desktop
    /// once.
    pub fn notice(&mut self, sandbox: &ExecutionId, text: String) {
        let notice = Notice {
            sandbox: sandbox.clone(),
            text,
            at_ns: self.clock.now().as_nanos(),
        };
        if self.notices.len() >= MAX_NOTICES {
            self.notices.pop_front();
        }
        self.notices.push_back(notice.clone());
        if self.unshown.len() < MAX_NOTICES {
            self.unshown.push(notice);
        }
    }

    /// The notices not shown on the desktop yet.
    pub fn take_unshown(&mut self) -> Vec<Notice> {
        std::mem::take(&mut self.unshown)
    }

    /// What the status shows (module docs).
    pub fn view(&self) -> Value {
        let sandboxes: Map<String, Value> = self
            .views
            .iter()
            .map(|(sandbox, view)| {
                (
                    sandbox.to_string(),
                    serde_json::to_value(view).unwrap_or(Value::Null),
                )
            })
            .collect();
        json!({
            "sandboxes": sandboxes,
            "notices": self.notices,
            "totals": self.totals,
            "responder": self.responder.totals(),
        })
    }

    fn view_mut(&mut self, sandbox: &ExecutionId) -> &mut SandboxView {
        if !self.views.contains_key(sandbox) {
            if self.views.len() >= MAX_VIEWS {
                // The oldest view of an ended sandbox goes; a registered one never does
                // (there are at most MAX_SANDBOXES of them, fewer than MAX_VIEWS).
                let views = &self.views;
                if let Some(position) = self
                    .order
                    .iter()
                    .position(|old| views.get(old).is_some_and(|view| !view.registered))
                {
                    if let Some(old) = self.order.remove(position) {
                        self.views.remove(&old);
                    }
                }
            }
            self.order.push_back(sandbox.clone());
        }
        self.views.entry(sandbox.clone()).or_default()
    }
}

/// The digest the broker's signals name a route by (`signals::route_subject`); a name that
/// is not a route identifier (the executor reports only identifiers) is digested alike.
fn route_subject_of(route: &str) -> Digest {
    match RouteId::new(route) {
        Ok(route) => route_subject(&route),
        Err(_) => DigestBuilder::new(ROUTE_SUBJECT_DOMAIN).str(route).finish(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::foundation::ids::{ManualClock, MonotonicTime};
    use crate::sandbox_contract::response::{HostObserver, ViolationKind};

    const START: MonotonicTime = MonotonicTime::from_nanos(5_000_000_000_000);

    fn path() -> (Arc<ManualClock>, ViolationResponses<Arc<ManualClock>>) {
        let clock = Arc::new(ManualClock::new(START));
        let path = ViolationResponses::new(Arc::clone(&clock), ClockSession::generate()).unwrap();
        (clock, path)
    }

    fn sandbox(name: &str) -> ExecutionId {
        ExecutionId::new(name).unwrap()
    }

    fn refused(sandbox: &ExecutionId, route: &str, exchange: u64, class: RefusalClass) -> RefusedExchange {
        RefusedExchange {
            sandbox: sandbox.clone(),
            route: route.to_owned(),
            exchange,
            class,
            detail: format!("refusal {exchange}"),
        }
    }

    fn perimeter() -> RefusalClass {
        RefusalClass::Violation {
            kind: ViolationKind::PerimeterRule,
            observer: HostObserver::Perimeter,
        }
    }

    fn ordinary(reason: &str) -> RefusalClass {
        RefusalClass::Ordinary {
            reason: reason.to_owned(),
        }
    }

    /// PROVES a violation the executor reports about a registered sandbox becomes one fresh
    /// host-observed signal and one decision that stops and revokes the task sandbox, tells
    /// the user and isolates it, with the signal's audit fields at hand for the engine.
    #[test]
    fn a_reported_violation_becomes_a_decision_that_stops_and_revokes() {
        let (_, mut path) = path();
        let one = sandbox("exe-one");
        path.register(&one).unwrap();
        let faults = path.ingest(vec![refused(&one, "secure", 3, perimeter())], 0);
        assert!(faults.is_empty());
        let decided = path.decide();
        assert_eq!(decided.len(), 1);
        let Decided { signals, record } = &decided[0];
        assert_eq!(signals.len(), 1);
        assert!(!signals[0].audit_fields().is_empty());
        assert_eq!(record.key.sandbox, one);
        let target = record.observed().unwrap();
        for action in [
            ResponseAction::NotifyUser,
            ResponseAction::DenyNewHighImpact,
            ResponseAction::Isolate,
            ResponseAction::Revoke,
            ResponseAction::Stop,
        ] {
            assert!(target.new_actions.contains(&action), "{action:?}");
        }
        assert!(!record.audit_fields().is_empty());
        // The decision is kept with what the engine did about it.
        path.settle(record.clone(), vec![json!({"sequence": 1})], vec![json!({"action": "revoke"})]);
        let view = path.view();
        assert_eq!(view["sandboxes"]["exe-one"]["violations"], json!(1));
        assert_eq!(view["sandboxes"]["exe-one"]["decisions"].as_array().unwrap().len(), 1);
        assert_eq!(view["totals"]["decisions"], json!(1));
    }

    /// PROVES the same violation again (same sandbox, route and observer) adds nothing the
    /// first decision did not apply, so it is deduplicated instead of decided twice.
    #[test]
    fn the_same_violation_again_is_deduplicated() {
        let (clock, mut path) = path();
        let one = sandbox("exe-one");
        path.register(&one).unwrap();
        path.ingest(vec![refused(&one, "secure", 1, perimeter())], 0);
        assert_eq!(path.decide().len(), 1);
        clock.advance(Duration::from_secs(1));
        path.ingest(vec![refused(&one, "secure", 2, perimeter())], 0);
        assert!(path.decide().is_empty());
        assert_eq!(path.view()["sandboxes"]["exe-one"]["deduplicated"], json!(1));
    }

    /// PROVES ordinary refusals are counted per reason, keep only the last few with their
    /// statements, and decide nothing.
    #[test]
    fn ordinary_refusals_are_counted_and_decide_nothing() {
        let (_, mut path) = path();
        let one = sandbox("exe-one");
        path.register(&one).unwrap();
        let reports = (0..10)
            .map(|exchange| refused(&one, "secure", exchange, ordinary("not_permitted")))
            .collect();
        path.ingest(reports, 2);
        assert!(path.decide().is_empty());
        let view = path.view();
        assert_eq!(view["sandboxes"]["exe-one"]["ordinary"]["not_permitted"], json!(10));
        assert_eq!(
            view["sandboxes"]["exe-one"]["recent"].as_array().unwrap().len(),
            RECENT_REFUSALS
        );
        assert_eq!(view["totals"]["executor_dropped"], json!(2));
    }

    /// PROVES a relay protocol fault is told to the user and handed to the audit, and
    /// decides nothing: it concerns the relay, not the guest.
    #[test]
    fn a_relay_protocol_fault_is_told_and_audited_never_decided() {
        let (_, mut path) = path();
        let one = sandbox("exe-one");
        path.register(&one).unwrap();
        let faults = path.ingest(vec![refused(&one, "secure", 4, RefusalClass::RelayProtocol)], 0);
        assert_eq!(faults.len(), 1);
        assert_eq!(faults[0].sandbox, one);
        assert!(path.decide().is_empty());
        let unshown = path.take_unshown();
        assert_eq!(unshown.len(), 1);
        assert!(unshown[0].text.contains("not the guest"));
        assert!(path.take_unshown().is_empty());
        assert_eq!(path.view()["notices"].as_array().unwrap().len(), 1);
    }

    /// PROVES refusals about a sandbox the path does not answer for (never registered, or
    /// forgotten when it ended) are counted as unattributed and decide nothing.
    #[test]
    fn refusals_of_unregistered_sandboxes_are_unattributed() {
        let (_, mut path) = path();
        let one = sandbox("exe-one");
        path.ingest(vec![refused(&one, "secure", 1, perimeter())], 0);
        assert!(path.decide().is_empty());
        path.register(&one).unwrap();
        path.forget(&one);
        path.ingest(vec![refused(&one, "secure", 2, perimeter())], 0);
        assert!(path.decide().is_empty());
        assert_eq!(path.view()["totals"]["unattributed"], json!(2));
    }

    /// PROVES a decision's restrictions refuse new commands while the sandbox runs and lapse
    /// when it ends.
    #[test]
    fn restrictions_refuse_commands_until_the_sandbox_ends() {
        let (_, mut path) = path();
        let one = sandbox("exe-one");
        assert!(path.admits_exec(&one).is_ok());
        path.register(&one).unwrap();
        path.restrict(&one, ResponseAction::DenyNewHighImpact);
        assert!(path.admits_exec(&one).unwrap_err().contains("denies new commands"));
        path.restrict(&one, ResponseAction::Isolate);
        assert!(path.admits_exec(&one).unwrap_err().contains("isolated"));
        path.forget(&one);
        assert!(path.admits_exec(&one).is_ok());
        // A restriction on a sandbox that ended is not kept.
        path.restrict(&one, ResponseAction::Isolate);
        assert!(path.admits_exec(&one).is_ok());
    }

    /// PROVES the path registers at most MAX_SANDBOXES sandboxes at once, so a relay whose
    /// sandbox it cannot answer for is refused before it starts.
    #[test]
    fn the_path_refuses_a_sandbox_past_its_bound() {
        let (_, mut path) = path();
        for index in 0..MAX_SANDBOXES {
            path.register(&sandbox(&format!("exe-{index}"))).unwrap();
        }
        let refused = path.register(&sandbox("exe-over")).unwrap_err();
        assert!(refused.contains("cannot take sandbox exe-over"), "{refused}");
        path.forget(&sandbox("exe-0"));
        path.register(&sandbox("exe-over")).unwrap();
    }
}
