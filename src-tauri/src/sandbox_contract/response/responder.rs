//! Bounded responses (VM-W43 line 2491: "Known violations trigger bounded responses").
//!
//! - One response per incident: a signal about an incident that already had a response is
//!   deduplicated unless its decision adds an action, which climbs the explicit escalation
//!   ladder. An incident therefore has at most one response per rung.
//! - A per-sandbox rate bound on repeats: a response that adds no restrictive action to
//!   what its sandbox already has is admitted at most `repeats` times per window; the rest
//!   are counted and folded into the next notification, never dropped silently. A response
//!   that adds a restrictive action is never held back, and there are at most as many of
//!   those per sandbox as there are rungs.
//! - Reach: a response targets the sandbox the signal is about. It reaches another sandbox
//!   only when it revokes and that sandbox holds the violated grant, and then it only
//!   revokes that one grant there, by a CORE-04 tombstone, and notifies: the bystander
//!   keeps its authorization epoch and every other grant, because the grant is what is
//!   suspect, not the bystander (VM-W43: bounded responses that do not erase unrelated
//!   work). The violator still gets its whole policy-defined response.
//! - No action widens authority, and only the user takes isolation back down
//!   ([`Responder::release_isolation`]); nothing takes back a revocation or a stop.
//! - Notifications go to the user only, bounded by the [`NotifyPolicy`](super::NotifyPolicy).
//!
//! The responder decides and records; the runtime applies (see [`execute_target`](super::execute_target)).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::assess::{Assessment, IncidentKey, SignalAssessment};
use super::emission::EmissionGate;
use super::policy::{
    decide, preserved_under, rung_of, Decision, DecisionInput, EscalationRung, NotifyPolicy,
    NotifyRecipient, Preserved, ResponseAction, ResponsePolicies,
};
use super::signal::GrantRef;
use crate::foundation::events::{AuditDraft, EmissionLimit, Field, HostFact};
use crate::foundation::ids::{digest, Clock, Digest, DigestBuilder, ExecutionId, MonotonicTime};
use crate::sandbox_contract::files::{SandboxClass, ViolationAction};

const INCIDENT_DOMAIN: &str = "yougori/sandbox/response/incident/v1";
const DECISION_DOMAIN: &str = "yougori/sandbox/response/decision/v1";
const OVERFLOW_DOMAIN: &str = "yougori/sandbox/response/incident-overflow/v1";

/// The identity of one incident: a digest of its key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IncidentId(Digest);

impl IncidentId {
    /// The identity of the incident `key` names.
    pub fn of(key: &IncidentKey) -> Self {
        Self(
            DigestBuilder::new(INCIDENT_DOMAIN)
                .str(key.sandbox.as_str())
                .str(key.class.label())
                .digest(&key.subject)
                .finish(),
        )
    }

    /// The digest behind the identity.
    pub const fn digest(&self) -> &Digest {
        &self.0
    }
}

/// The identity of one decision: its incident and the responder's sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DecisionId(Digest);

impl DecisionId {
    fn new(incident: IncidentId, sequence: u64) -> Self {
        Self(
            DigestBuilder::new(DECISION_DOMAIN)
                .digest(incident.digest())
                .u64(sequence)
                .finish(),
        )
    }

    /// The digest behind the identity.
    pub const fn digest(&self) -> &Digest {
        &self.0
    }
}

/// The responder's bounds (VM-W43 "bounded responses").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResponseBounds {
    repeats: EmissionLimit,
    max_incidents: usize,
    max_sandboxes: usize,
}

impl ResponseBounds {
    /// `repeats` bounds the responses per sandbox that add no restrictive action;
    /// `max_incidents` the incidents tracked one by one (more share one overflow incident
    /// per sandbox and class); `max_sandboxes` the sandboxes registered at once.
    pub fn new(
        repeats: EmissionLimit,
        max_incidents: usize,
        max_sandboxes: usize,
    ) -> Result<Self, BoundsProblem> {
        if max_incidents == 0 {
            return Err(BoundsProblem::ZeroIncidents);
        }
        if max_sandboxes == 0 {
            return Err(BoundsProblem::ZeroSandboxes);
        }
        Ok(Self {
            repeats,
            max_incidents,
            max_sandboxes,
        })
    }

    /// The per-sandbox bound on responses that add no restrictive action.
    pub const fn repeats(&self) -> EmissionLimit {
        self.repeats
    }

    /// The incidents tracked one by one.
    pub const fn max_incidents(&self) -> usize {
        self.max_incidents
    }

    /// The sandboxes registered at once.
    pub const fn max_sandboxes(&self) -> usize {
        self.max_sandboxes
    }
}

/// Why bounds were refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundsProblem {
    ZeroIncidents,
    ZeroSandboxes,
}

impl fmt::Display for BoundsProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ZeroIncidents => "the incident bound is zero",
            Self::ZeroSandboxes => "the sandbox bound is zero",
        })
    }
}

impl std::error::Error for BoundsProblem {}

/// Why a target is part of a response.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "role", rename_all = "snake_case")]
pub enum TargetRole {
    /// The sandbox the signal is about.
    Observed,
    /// Another sandbox that holds the violated grant; it loses that grant
    /// ([`ResponseAction::RevokeGrant`]) and nothing else.
    SharesViolatedGrant { grant: GrantRef },
}

/// What happened to one notification (VM-W43: the user only, rate-bounded).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "notification", rename_all = "snake_case")]
pub enum NotificationOutcome {
    /// Sent to the user; it summarizes `folded_held_back` earlier notifications and
    /// responses that the bounds held back.
    Sent {
        recipient: NotifyRecipient,
        folded_held_back: u64,
    },
    /// Held back by the notify bound; counted, and summarized in the next one sent.
    HeldBack {
        retry_after: Duration,
        held_back: u64,
    },
}

/// One sandbox's part of a response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TargetResponse {
    pub sandbox: ExecutionId,
    pub sandbox_class: SandboxClass,
    pub role: TargetRole,
    pub actions: BTreeSet<ResponseAction>,
    /// The actions this response added to what the sandbox already had.
    pub new_actions: BTreeSet<ResponseAction>,
    /// V05's VM-D10 response, when the target stops.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class_response: Option<ViolationAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification: Option<NotificationOutcome>,
    pub preserves: Vec<Preserved>,
}

/// One response: the durable decision record of VM-P14 (line 2614).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ResponseRecord {
    pub id: DecisionId,
    pub incident: IncidentId,
    pub key: IncidentKey,
    pub sequence: u64,
    pub decided_at: MonotonicTime,
    pub decision: Decision,
    /// The incident's rung before this response, when it escalates an earlier one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub escalated_from: Option<EscalationRung>,
    /// The observed sandbox first, then sandboxes sharing the violated grant.
    pub targets: Vec<TargetResponse>,
}

impl ResponseRecord {
    /// The target the signal is about.
    pub fn observed(&self) -> Option<&TargetResponse> {
        self.targets
            .iter()
            .find(|target| target.role == TargetRole::Observed)
    }

    /// The record as CORE-06 metadata fields.
    pub fn audit_fields(&self) -> Vec<Field> {
        let input = &self.decision.input;
        let mut fields = vec![
            Field::metadata("event", "response_decision"),
            Field::metadata("decision", *self.id.digest()),
            Field::metadata("incident", *self.incident.digest()),
            Field::metadata("sequence", self.sequence),
            Field::metadata("sandbox", self.key.sandbox.as_str()),
            Field::metadata("sandbox_class", class_label(input.sandbox_class)),
            Field::metadata("class", input.class.label()),
            Field::metadata("subject", self.key.subject),
            Field::metadata("source", input.source.label()),
            Field::metadata("freshness", input.freshness.label()),
            Field::metadata("reason", self.decision.reason.label()),
            Field::metadata("rung", self.decision.rung.label()),
            Field::metadata("decided_at_ns", self.decided_at.as_nanos()),
            Field::metadata(
                "targets",
                u64::try_from(self.targets.len()).unwrap_or(u64::MAX),
            ),
        ];
        if let Some(observer) = input.source.observer() {
            fields.push(Field::metadata("observer", observer.label()));
        }
        for action in ResponseAction::ALL {
            fields.push(Field::metadata(
                action_field(action),
                self.decision.actions.contains(&action),
            ));
        }
        if let Some(response) = self.decision.class_response {
            fields.push(Field::metadata(
                "class_response",
                match response {
                    ViolationAction::Stop => "stop",
                    ViolationAction::LockDown => "lock_down",
                },
            ));
        }
        if let Some(rung) = self.escalated_from {
            fields.push(Field::metadata("escalated_from", rung.label()));
        }
        fields.push(Field::metadata(
            "preserves_vm_state",
            self.decision.preserves.contains(&Preserved::VmState),
        ));
        fields
    }

    /// The CORE-06 draft: a host fact of kind authorization decision.
    pub fn audit_draft(&self) -> AuditDraft {
        AuditDraft::HostFact {
            fact: HostFact::AuthorizationDecision,
            fields: self.audit_fields(),
        }
    }
}

const fn class_label(class: SandboxClass) -> &'static str {
    match class {
        SandboxClass::Task => "task",
        SandboxClass::Service => "service",
    }
}

const fn action_field(action: ResponseAction) -> &'static str {
    match action {
        ResponseAction::NotifyUser => "action_notify_user",
        ResponseAction::RequestHostCorroboration => "action_request_host_corroboration",
        ResponseAction::DenyNewHighImpact => "action_deny_new_high_impact",
        ResponseAction::Isolate => "action_isolate",
        ResponseAction::RevokeGrant => "action_revoke_grant",
        ResponseAction::Revoke => "action_revoke",
        ResponseAction::Stop => "action_stop",
    }
}

/// What the responder did with one assessment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResponseOutcome {
    NoViolationObserved,
    Responded(ResponseRecord),
    /// The incident already had a response with every action this decision takes.
    Deduplicated {
        incident: IncidentId,
        last_decision: DecisionId,
    },
    /// The response would add no restrictive action, and the sandbox's repeat bound is
    /// used up. Counted, and folded into the next notification.
    RateBounded {
        incident: IncidentId,
        retry_after: Duration,
        held_back: u64,
    },
}

/// The user released a sandbox's isolation: channels and network may be restored. Any
/// revocation or stop stays, and no authority is restored (VM-P24 "do not revive
/// authority").
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IsolationRelease {
    pub sandbox: ExecutionId,
    pub released_at: MonotonicTime,
    /// What the sandbox still has; a revocation or a stop is never released.
    pub still_applied: BTreeSet<ResponseAction>,
}

/// Why the responder refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResponderRefusal {
    UnknownSandbox { sandbox: ExecutionId },
    AlreadyRegistered { sandbox: ExecutionId },
    TooManySandboxes { max_sandboxes: usize },
    NotIsolated { sandbox: ExecutionId },
    SequenceExhausted,
}

impl fmt::Display for ResponderRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownSandbox { sandbox } => write!(f, "sandbox {sandbox} is not registered"),
            Self::AlreadyRegistered { sandbox } => {
                write!(f, "sandbox {sandbox} is already registered")
            }
            Self::TooManySandboxes { max_sandboxes } => {
                write!(f, "{max_sandboxes} sandboxes are already registered")
            }
            Self::NotIsolated { sandbox } => write!(f, "sandbox {sandbox} is not isolated"),
            Self::SequenceExhausted => f.write_str("the responder used its last sequence"),
        }
    }
}

impl std::error::Error for ResponderRefusal {}

/// Counts of what the responder did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ResponderTotals {
    pub responded: u64,
    /// Responses that climbed an incident's ladder.
    pub escalations: u64,
    pub deduplicated: u64,
    pub rate_bounded: u64,
    pub notifications_sent: u64,
    pub notifications_held_back: u64,
    /// Signals filed under an overflow incident because the incident bound was reached.
    pub overflowed: u64,
}

#[derive(Clone, Debug)]
struct SandboxEntry {
    class: SandboxClass,
    grants: BTreeSet<GrantRef>,
    applied: BTreeSet<ResponseAction>,
    /// The grants revoked here as a bystander, each once.
    revoked_grants: BTreeSet<GrantRef>,
    repeats: EmissionGate,
    notifications: EmissionGate,
}

#[derive(Clone, Debug)]
struct Incident {
    id: IncidentId,
    applied: BTreeSet<ResponseAction>,
    rung: EscalationRung,
    last_decision: DecisionId,
}

/// The VM-W43 responder: decisions under bounds, one record per response.
#[derive(Debug)]
pub struct Responder<C> {
    clock: C,
    policies: ResponsePolicies,
    bounds: ResponseBounds,
    sandboxes: BTreeMap<ExecutionId, SandboxEntry>,
    incidents: BTreeMap<IncidentKey, Incident>,
    sequence: u64,
    totals: ResponderTotals,
}

impl<C: Clock> Responder<C> {
    /// A responder on `clock` with checked policies and bounds and no sandbox yet.
    pub fn new(clock: C, policies: ResponsePolicies, bounds: ResponseBounds) -> Self {
        Self {
            clock,
            policies,
            bounds,
            sandboxes: BTreeMap::new(),
            incidents: BTreeMap::new(),
            sequence: 0,
            totals: ResponderTotals::default(),
        }
    }

    /// The five policy records.
    pub fn policies(&self) -> &ResponsePolicies {
        &self.policies
    }

    /// The response bounds.
    pub fn bounds(&self) -> &ResponseBounds {
        &self.bounds
    }

    /// Counts of what the responder did.
    pub fn totals(&self) -> ResponderTotals {
        self.totals
    }

    /// Incidents currently tracked, overflow incidents included.
    pub fn open_incidents(&self) -> usize {
        self.incidents.len()
    }

    /// Registers a sandbox with its class and the grants it holds.
    pub fn register_sandbox(
        &mut self,
        sandbox: ExecutionId,
        class: SandboxClass,
        grants: BTreeSet<GrantRef>,
    ) -> Result<(), ResponderRefusal> {
        if self.sandboxes.contains_key(&sandbox) {
            return Err(ResponderRefusal::AlreadyRegistered { sandbox });
        }
        if self.sandboxes.len() >= self.bounds.max_sandboxes {
            return Err(ResponderRefusal::TooManySandboxes {
                max_sandboxes: self.bounds.max_sandboxes,
            });
        }
        let notify = NotifyPolicy::limit(self.policies.notify());
        self.sandboxes.insert(
            sandbox,
            SandboxEntry {
                class,
                grants,
                applied: BTreeSet::new(),
                revoked_grants: BTreeSet::new(),
                repeats: EmissionGate::new(self.bounds.repeats),
                notifications: EmissionGate::new(notify),
            },
        );
        Ok(())
    }

    /// Forgets a sandbox that ended, with its incidents. Returns whether it was known.
    pub fn forget_sandbox(&mut self, sandbox: &ExecutionId) -> bool {
        self.incidents.retain(|key, _| &key.sandbox != sandbox);
        self.sandboxes.remove(sandbox).is_some()
    }

    /// The actions a sandbox currently has.
    pub fn applied(&self, sandbox: &ExecutionId) -> Option<&BTreeSet<ResponseAction>> {
        self.sandboxes.get(sandbox).map(|entry| &entry.applied)
    }

    /// The highest rung a sandbox has reached, if any.
    pub fn rung(&self, sandbox: &ExecutionId) -> Option<EscalationRung> {
        self.sandboxes
            .get(sandbox)
            .filter(|entry| !entry.applied.is_empty())
            .map(|entry| rung_of(&entry.applied))
    }

    /// Responds to an assessment.
    pub fn respond(
        &mut self,
        assessment: &Assessment,
    ) -> Result<ResponseOutcome, ResponderRefusal> {
        match assessment {
            Assessment::NoViolationObserved => Ok(ResponseOutcome::NoViolationObserved),
            Assessment::Signal(signal) => self.respond_to(signal),
        }
    }

    /// Responds to one signal assessment under the bounds.
    pub fn respond_to(
        &mut self,
        signal: &SignalAssessment,
    ) -> Result<ResponseOutcome, ResponderRefusal> {
        let now = self.clock.now();
        let origin = signal.sandbox().clone();
        let (class, sandbox_applied) = match self.sandboxes.get(&origin) {
            Some(entry) => (entry.class, entry.applied.clone()),
            None => return Err(ResponderRefusal::UnknownSandbox { sandbox: origin }),
        };
        let decision = decide(
            &self.policies,
            &DecisionInput {
                class: signal.class(),
                source: signal.source(),
                freshness: signal.freshness(),
                sandbox_class: class,
            },
        );
        let key = self.file_under(signal.key());
        let incident_id = IncidentId::of(&key);
        let previous = self.incidents.get(&key).cloned();
        if let Some(incident) = &previous {
            if decision.actions.is_subset(&incident.applied) {
                self.totals.deduplicated = self.totals.deduplicated.saturating_add(1);
                return Ok(ResponseOutcome::Deduplicated {
                    incident: incident.id,
                    last_decision: incident.last_decision,
                });
            }
        }
        let escalates = decision
            .actions
            .difference(&sandbox_applied)
            .any(|action| !action.is_informational());
        if !escalates {
            if let Some(entry) = self.sandboxes.get_mut(&origin) {
                if let Err(retry_after) = entry.repeats.admit(now) {
                    self.totals.rate_bounded = self.totals.rate_bounded.saturating_add(1);
                    return Ok(ResponseOutcome::RateBounded {
                        incident: incident_id,
                        retry_after,
                        held_back: entry.repeats.held_back(),
                    });
                }
            }
        }
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(ResponderRefusal::SequenceExhausted)?;
        self.sequence = sequence;
        let id = DecisionId::new(incident_id, sequence);

        let mut targets = vec![self.apply_target(
            &origin,
            TargetRole::Observed,
            decision.actions.clone(),
            decision.class_response,
            now,
        )];
        if decision.actions.contains(&ResponseAction::Revoke) {
            if let Some(grant) = signal.violated_grant() {
                let sharing: Vec<ExecutionId> = self
                    .sandboxes
                    .iter()
                    .filter(|(sandbox, entry)| {
                        **sandbox != origin
                            && entry.grants.contains(&grant)
                            && !entry.applied.contains(&ResponseAction::Revoke)
                            && !entry.revoked_grants.contains(&grant)
                    })
                    .map(|(sandbox, _)| sandbox.clone())
                    .collect();
                for sandbox in sharing {
                    let actions =
                        BTreeSet::from([ResponseAction::NotifyUser, ResponseAction::RevokeGrant]);
                    targets.push(self.apply_target(
                        &sandbox,
                        TargetRole::SharesViolatedGrant { grant },
                        actions,
                        None,
                        now,
                    ));
                }
            }
        }
        let targets = targets.into_iter().flatten().collect();

        let mut applied = previous
            .as_ref()
            .map(|incident| incident.applied.clone())
            .unwrap_or_default();
        applied.extend(decision.actions.iter().copied());
        self.incidents.insert(
            key.clone(),
            Incident {
                id: incident_id,
                rung: rung_of(&applied),
                applied,
                last_decision: id,
            },
        );
        self.totals.responded = self.totals.responded.saturating_add(1);
        if previous.is_some() {
            self.totals.escalations = self.totals.escalations.saturating_add(1);
        }
        Ok(ResponseOutcome::Responded(ResponseRecord {
            id,
            incident: incident_id,
            key,
            sequence,
            decided_at: now,
            escalated_from: previous.map(|incident| incident.rung),
            decision,
            targets,
        }))
    }

    /// Records `actions` against one sandbox and sends its notification through the
    /// bound. `None` when the sandbox is not registered.
    fn apply_target(
        &mut self,
        sandbox: &ExecutionId,
        role: TargetRole,
        actions: BTreeSet<ResponseAction>,
        class_response: Option<ViolationAction>,
        now: MonotonicTime,
    ) -> Option<TargetResponse> {
        let entry = self.sandboxes.get_mut(sandbox)?;
        let mut new_actions: BTreeSet<ResponseAction> =
            actions.difference(&entry.applied).copied().collect();
        // A grant revocation is new for each grant, even after another grant was revoked.
        if let TargetRole::SharesViolatedGrant { grant } = role {
            if actions.contains(&ResponseAction::RevokeGrant) && entry.revoked_grants.insert(grant)
            {
                new_actions.insert(ResponseAction::RevokeGrant);
            }
        }
        entry.applied.extend(actions.iter().copied());
        let notification = if actions.contains(&ResponseAction::NotifyUser) {
            Some(match entry.notifications.admit(now) {
                Ok(()) => {
                    self.totals.notifications_sent =
                        self.totals.notifications_sent.saturating_add(1);
                    NotificationOutcome::Sent {
                        recipient: NotifyPolicy::RECIPIENT,
                        folded_held_back: entry
                            .notifications
                            .take_held_back()
                            .saturating_add(entry.repeats.take_held_back()),
                    }
                }
                Err(retry_after) => {
                    self.totals.notifications_held_back =
                        self.totals.notifications_held_back.saturating_add(1);
                    NotificationOutcome::HeldBack {
                        retry_after,
                        held_back: entry.notifications.held_back(),
                    }
                }
            })
        } else {
            None
        };
        Some(TargetResponse {
            sandbox: sandbox.clone(),
            sandbox_class: entry.class,
            role,
            preserves: preserved_under(&actions, entry.class),
            actions,
            new_actions,
            class_response,
            notification,
        })
    }

    /// The key an incident is filed under: its own while the incident bound allows,
    /// otherwise the overflow incident of its sandbox and class.
    fn file_under(&mut self, key: &IncidentKey) -> IncidentKey {
        if self.incidents.contains_key(key) || self.incidents.len() < self.bounds.max_incidents {
            return key.clone();
        }
        self.totals.overflowed = self.totals.overflowed.saturating_add(1);
        IncidentKey {
            sandbox: key.sandbox.clone(),
            class: key.class,
            subject: digest(
                OVERFLOW_DOMAIN,
                &[
                    key.sandbox.as_str().as_bytes(),
                    key.class.label().as_bytes(),
                ],
            ),
        }
    }

    /// Closes an incident, such as a resource series that cleared. A later signal about it
    /// opens a new incident. What its responses applied to the sandbox stays.
    pub fn close_incident(&mut self, key: &IncidentKey) -> bool {
        self.incidents.remove(key).is_some()
    }

    /// The user releases a sandbox's isolation (VM-W43 "isolation is reversible"). A
    /// revocation or stop stays, and nothing restores authority.
    pub fn release_isolation(
        &mut self,
        sandbox: &ExecutionId,
    ) -> Result<IsolationRelease, ResponderRefusal> {
        let now = self.clock.now();
        let entry =
            self.sandboxes
                .get_mut(sandbox)
                .ok_or_else(|| ResponderRefusal::UnknownSandbox {
                    sandbox: sandbox.clone(),
                })?;
        if !entry.applied.remove(&ResponseAction::Isolate) {
            return Err(ResponderRefusal::NotIsolated {
                sandbox: sandbox.clone(),
            });
        }
        Ok(IsolationRelease {
            sandbox: sandbox.clone(),
            released_at: now,
            still_applied: entry.applied.clone(),
        })
    }
}
