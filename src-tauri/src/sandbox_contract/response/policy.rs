//! The five response policies and the one decision function (VM-W43 line 2491: "Define
//! isolate, revoke, stop, notify and uncertain-result policies separately"; §1.3 lines
//! 1718–1735: facets, never a score; VM-D10 line 3029).
//!
//! Each policy is its own record. [`decide`] maps (class, source, freshness, sandbox class)
//! to a bounded set of actions with a recorded reason, in this order:
//!
//! 1. A guest report alone can only notify the user or ask the host to corroborate it.
//! 2. A stale or conflicting host observation is an uncertain result: it notifies and
//!    denies new high-impact operations, never more, and is never silent.
//! 3. A fresh host observation of a known violation notifies, denies new high-impact
//!    operations, and isolates, revokes and stops as the three records say. A stop is
//!    V05's VM-D10 response for the class: a task sandbox stops, a service sandbox locks
//!    down with a one-click stop.
//! 4. A sustained resource signal notifies, denies new high-impact operations when the
//!    release budget is spent, and isolates when the isolate record says so. It never
//!    revokes or stops: the revoke and stop records take violations only.
//!
//! No action deletes anything. Every decision lists what it preserves.

use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::signal::{
    Freshness, HostObserver, MonitoredResource, SignalClass, SignalSource, ViolationKind,
};
use crate::foundation::events::{EmissionLimit, RevocationReason};
use crate::foundation::ids::Digest;
use crate::sandbox_contract::canaries::HitMeaning;
use crate::sandbox_contract::files::{
    CleanupPlan, CleanupRefusal, CleanupTarget, ManagedObjectKind, ManagedObjects,
    ObservedIdentities, SandboxClass, ViolationAction, VolumeClass,
};

/// One action a decision may take. Every action restricts; none grants, renews or
/// extends authority, and none deletes user data (VM-W43).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseAction {
    /// Tell the user, rate-bounded ([`NotifyPolicy`]); never a third party.
    NotifyUser,
    /// Ask a host observer to corroborate a guest report.
    RequestHostCorroboration,
    /// Deny new high-impact operations; existing authority is otherwise unchanged.
    DenyNewHighImpact,
    /// Cut the sandbox's channels and network and keep the VM and its state (reversible).
    Isolate,
    /// Revoke the one grant the target's role names, by a CORE-04 tombstone, leaving the
    /// sandbox's authorization epoch and its other grants in force (§6.3 step 1). Only a
    /// sandbox that holds a violated grant without being the violator gets it; no policy
    /// record decides it.
    RevokeGrant,
    /// Advance the sandbox's authorization epoch through the CORE-04 path (§6.3).
    Revoke,
    /// V05's VM-D10 response for the class: stop a task sandbox, lock a service sandbox
    /// down with a one-click stop.
    Stop,
}

impl ResponseAction {
    /// Every action, lowest rung first.
    pub const ALL: [Self; 7] = [
        Self::NotifyUser,
        Self::RequestHostCorroboration,
        Self::DenyNewHighImpact,
        Self::Isolate,
        Self::RevokeGrant,
        Self::Revoke,
        Self::Stop,
    ];

    /// The rung of the escalation ladder the action belongs to.
    pub const fn rung(self) -> EscalationRung {
        match self {
            Self::NotifyUser | Self::RequestHostCorroboration => EscalationRung::Notify,
            Self::DenyNewHighImpact => EscalationRung::DenyNewHighImpact,
            Self::Isolate => EscalationRung::Isolate,
            Self::RevokeGrant => EscalationRung::RevokeGrant,
            Self::Revoke => EscalationRung::Revoke,
            Self::Stop => EscalationRung::Stop,
        }
    }

    /// Whether the action only informs, without restricting the sandbox.
    pub const fn is_informational(self) -> bool {
        matches!(self, Self::NotifyUser | Self::RequestHostCorroboration)
    }

    /// The snake_case label used in audit fields.
    pub const fn label(self) -> &'static str {
        match self {
            Self::NotifyUser => "notify_user",
            Self::RequestHostCorroboration => "request_host_corroboration",
            Self::DenyNewHighImpact => "deny_new_high_impact",
            Self::Isolate => "isolate",
            Self::RevokeGrant => "revoke_grant",
            Self::Revoke => "revoke",
            Self::Stop => "stop",
        }
    }
}

/// One rung of the explicit escalation ladder (VM-W43 "bounded responses"). A sandbox's
/// responses only climb it; the user, not a signal, takes isolation back down, and nothing
/// takes a grant revocation, a revocation or a stop back.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationRung {
    Notify,
    DenyNewHighImpact,
    Isolate,
    /// One grant revoked: irreversible like a revocation, narrower than one.
    RevokeGrant,
    Revoke,
    Stop,
}

impl EscalationRung {
    /// The snake_case label used in audit fields.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Notify => "notify",
            Self::DenyNewHighImpact => "deny_new_high_impact",
            Self::Isolate => "isolate",
            Self::RevokeGrant => "revoke_grant",
            Self::Revoke => "revoke",
            Self::Stop => "stop",
        }
    }
}

/// The escalation ladder, lowest rung first.
pub const ESCALATION_LADDER: [EscalationRung; 6] = [
    EscalationRung::Notify,
    EscalationRung::DenyNewHighImpact,
    EscalationRung::Isolate,
    EscalationRung::RevokeGrant,
    EscalationRung::Revoke,
    EscalationRung::Stop,
];

/// What isolation cuts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationCut {
    /// Every host–guest channel: provider operations, file transfers, terminals, previews
    /// and published services.
    GuestChannels,
    /// Every network route of the sandbox.
    Network,
}

/// The isolate policy: cut channels and network, keep the VM and its state (VM-W43).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IsolatePolicy {
    triggers: BTreeSet<SignalClass>,
}

impl IsolatePolicy {
    /// Isolation always cuts both.
    pub const CUTS: [IsolationCut; 2] = [IsolationCut::GuestChannels, IsolationCut::Network];
    /// Isolation keeps the VM, its memory and its disks.
    pub const KEEPS_VM_STATE: bool = true;
    /// The user can release isolation; releasing it restores no revoked authority.
    pub const REVERSIBLE: bool = true;

    /// An isolate policy over `triggers`; [`ResponsePolicies::new`] checks it.
    pub fn new(triggers: BTreeSet<SignalClass>) -> Self {
        Self { triggers }
    }

    /// Every known violation, and sustained packet and connection rates.
    pub fn default_triggers() -> BTreeSet<SignalClass> {
        ViolationKind::ALL
            .iter()
            .map(|&kind| SignalClass::Violation { kind })
            .chain([
                SignalClass::Resource {
                    resource: MonitoredResource::PacketsPerSecond,
                },
                SignalClass::Resource {
                    resource: MonitoredResource::ConnectionsPerSecond,
                },
            ])
            .collect()
    }

    /// The classes whose fresh host observation isolates.
    pub fn triggers(&self) -> &BTreeSet<SignalClass> {
        &self.triggers
    }
}

/// The revoke policy: advance authority through the CORE-04 path (§6.3; VM-W43). It takes
/// violations only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevokePolicy {
    triggers: BTreeSet<ViolationKind>,
}

impl RevokePolicy {
    /// The CORE-06 reason a response's revocation is published with.
    pub const REASON: RevocationReason = RevocationReason::SecurityEvent;

    /// A policy over `triggers`; [`ResponsePolicies::new`] checks it.
    pub fn new(triggers: BTreeSet<ViolationKind>) -> Self {
        Self { triggers }
    }

    /// Every known violation.
    pub fn default_triggers() -> BTreeSet<ViolationKind> {
        ViolationKind::ALL.into_iter().collect()
    }

    /// The violations whose fresh host observation takes this action.
    pub fn triggers(&self) -> &BTreeSet<ViolationKind> {
        &self.triggers
    }
}

/// The stop policy: V05's VM-D10 response for the class (line 3029: ephemeral sandboxes
/// stop, service sandboxes lock down with a one-click stop). It takes violations only and
/// never a canary hit alone, which is a signal, not proof (§8.2 line 2274).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StopPolicy {
    triggers: BTreeSet<ViolationKind>,
}

impl StopPolicy {
    /// A policy over `triggers`; [`ResponsePolicies::new`] checks it.
    pub fn new(triggers: BTreeSet<ViolationKind>) -> Self {
        Self { triggers }
    }

    /// Every known violation except canary use.
    pub fn default_triggers() -> BTreeSet<ViolationKind> {
        ViolationKind::ALL
            .into_iter()
            .filter(|&kind| kind != ViolationKind::CanaryUse)
            .collect()
    }

    /// The violations whose fresh host observation takes this action.
    pub fn triggers(&self) -> &BTreeSet<ViolationKind> {
        &self.triggers
    }

    /// The class response, from V05's one table (VM-D10).
    pub const fn class_response(class: SandboxClass) -> ViolationAction {
        ViolationAction::for_class(class)
    }
}

/// Who a notification goes to: the user, and nobody else (VM-W43; §8.2 line 2274
/// "without third-party notifications").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotifyRecipient {
    User,
}

/// The notify policy: the user only, at most `limit` notifications per sandbox and window
/// (§8.2 "bound ... emission rate"). Notifications the bound holds back are counted and
/// summarized in the next one sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotifyPolicy {
    limit: EmissionLimit,
}

impl NotifyPolicy {
    /// The one recipient.
    pub const RECIPIENT: NotifyRecipient = NotifyRecipient::User;

    /// A notify policy bounded by `limit` per sandbox.
    pub fn new(limit: EmissionLimit) -> Self {
        Self { limit }
    }

    /// The per-sandbox notification bound.
    pub const fn limit(&self) -> EmissionLimit {
        self.limit
    }
}

/// The uncertain-result policy: a stale or conflicting host observation notifies the user
/// and denies new high-impact operations, never more and never nothing (VM-W43).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UncertainPolicy {
    max_observation_age: Duration,
}

impl UncertainPolicy {
    /// The whole uncertain response: never destructive, never silent.
    pub const ACTIONS: [ResponseAction; 2] = [
        ResponseAction::NotifyUser,
        ResponseAction::DenyNewHighImpact,
    ];

    /// An observation older than `max_observation_age` is stale.
    pub fn new(max_observation_age: Duration) -> Result<Self, PolicyProblem> {
        if max_observation_age.is_zero() {
            return Err(PolicyProblem::ZeroObservationAge);
        }
        Ok(Self {
            max_observation_age,
        })
    }

    /// The age beyond which an observation is stale.
    pub const fn max_observation_age(&self) -> Duration {
        self.max_observation_age
    }
}

/// Why a set of policies was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyProblem {
    /// Every known violation must at least isolate (VM-W43 "known violations trigger
    /// bounded responses").
    ViolationWithoutIsolation {
        kind: ViolationKind,
    },
    /// A stop revokes first (VM-D10: authority is revoked at once for every class).
    StopWithoutRevoke {
        kind: ViolationKind,
    },
    /// A canary hit is a signal, not proof (§8.2 line 2274), so it alone never stops.
    CanaryStops,
    ZeroObservationAge,
}

impl fmt::Display for PolicyProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ViolationWithoutIsolation { kind } => {
                write!(f, "{} must at least isolate", kind.label())
            }
            Self::StopWithoutRevoke { kind } => {
                write!(f, "{} stops without revoking first", kind.label())
            }
            Self::CanaryStops => {
                f.write_str("a canary hit is a signal, not proof, and alone never stops")
            }
            Self::ZeroObservationAge => f.write_str("the maximum observation age is zero"),
        }
    }
}

impl std::error::Error for PolicyProblem {}

/// The five policy records, checked together.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponsePolicies {
    isolate: IsolatePolicy,
    revoke: RevokePolicy,
    stop: StopPolicy,
    notify: NotifyPolicy,
    uncertain: UncertainPolicy,
}

impl ResponsePolicies {
    /// Checks the five records together: every known violation isolates, every stop revokes first, and a canary hit alone never stops.
    pub fn new(
        isolate: IsolatePolicy,
        revoke: RevokePolicy,
        stop: StopPolicy,
        notify: NotifyPolicy,
        uncertain: UncertainPolicy,
    ) -> Result<Self, PolicyProblem> {
        for kind in ViolationKind::ALL {
            if !isolate.triggers.contains(&SignalClass::Violation { kind }) {
                return Err(PolicyProblem::ViolationWithoutIsolation { kind });
            }
        }
        if stop.triggers.contains(&ViolationKind::CanaryUse) {
            return Err(PolicyProblem::CanaryStops);
        }
        if let Some(&kind) = stop.triggers.difference(&revoke.triggers).next() {
            return Err(PolicyProblem::StopWithoutRevoke { kind });
        }
        Ok(Self {
            isolate,
            revoke,
            stop,
            notify,
            uncertain,
        })
    }

    /// The default trigger sets with the given notification bound and observation age.
    pub fn with_default_triggers(notify: NotifyPolicy, uncertain: UncertainPolicy) -> Self {
        Self {
            isolate: IsolatePolicy::new(IsolatePolicy::default_triggers()),
            revoke: RevokePolicy::new(RevokePolicy::default_triggers()),
            stop: StopPolicy::new(StopPolicy::default_triggers()),
            notify,
            uncertain,
        }
    }

    /// The isolate record.
    pub fn isolate(&self) -> &IsolatePolicy {
        &self.isolate
    }

    /// The revoke record.
    pub fn revoke(&self) -> &RevokePolicy {
        &self.revoke
    }

    /// The stop record.
    pub fn stop(&self) -> &StopPolicy {
        &self.stop
    }

    /// The notify record.
    pub fn notify(&self) -> &NotifyPolicy {
        &self.notify
    }

    /// The uncertain-result record.
    pub fn uncertain(&self) -> &UncertainPolicy {
        &self.uncertain
    }
}

/// What a decision is made from (VM-W43): the signal's class, source and freshness, and
/// the sandbox's class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct DecisionInput {
    pub class: SignalClass,
    pub source: SignalSource,
    pub freshness: Freshness,
    pub sandbox_class: SandboxClass,
}

/// Why a decision took its actions. It records observations and rules, never a verdict on
/// intent and never a score (§1.3; §8.2 line 2274).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum DecisionReason {
    /// A guest report alone: untrusted (§8.2 line 2268).
    GuestReportNeedsCorroboration { class: SignalClass },
    /// A stale or conflicting host observation: uncertain, never a pass.
    Uncertain {
        class: SignalClass,
        observer: HostObserver,
        freshness: Freshness,
    },
    /// A fresh host observation of a known violation. A canary hit carries its V09
    /// meaning, a signal and not proof.
    KnownViolation {
        kind: ViolationKind,
        observer: HostObserver,
        #[serde(skip_serializing_if = "Option::is_none")]
        meaning: Option<HitMeaning>,
    },
    /// A resource limit exceeded for a sustained window.
    SustainedResource {
        resource: MonitoredResource,
        observer: HostObserver,
    },
}

impl DecisionReason {
    /// The snake_case label used in audit fields.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::GuestReportNeedsCorroboration { .. } => "guest_report_needs_corroboration",
            Self::Uncertain { .. } => "uncertain",
            Self::KnownViolation { .. } => "known_violation",
            Self::SustainedResource { .. } => "sustained_resource",
        }
    }
}

/// User data and state a decision keeps (VM-W43 "false positives do not erase user work").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(tag = "preserved", rename_all = "snake_case")]
pub enum Preserved {
    /// Every volume of a V05 class (§5.5), kept for recovery whatever the sandbox class.
    Volume {
        class: VolumeClass,
    },
    /// Live workspace roots granted from the host (§5.1).
    HostWorkspaces,
    /// Promoted artifacts.
    Artifacts,
    Snapshots,
    /// The VM's root overlay and scratch directories: a response's cleanup leaves them for
    /// recovery ([`RESPONSE_CLEANUP_KINDS`]).
    RootOverlayAndScratch,
    /// The running VM and its memory: kept by isolation, by a lockdown and by every
    /// response that does not stop a task sandbox.
    VmState,
}

/// The managed objects a response-initiated cleanup may remove: the stopped VM's process,
/// its perimeter and its sockets. Overlays, scratch directories, snapshots and user source
/// data are never response cleanup targets (VM-W43; §6.4 line 2149).
pub const RESPONSE_CLEANUP_KINDS: [ManagedObjectKind; 3] = [
    ManagedObjectKind::VmProcess,
    ManagedObjectKind::Perimeter,
    ManagedObjectKind::Socket,
];

/// Whether a response-initiated cleanup may remove an object of `kind`.
pub fn response_cleanup_allows(kind: ManagedObjectKind) -> bool {
    RESPONSE_CLEANUP_KINDS.contains(&kind)
}

/// Why a response-initiated cleanup step was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum ResponseCleanupRefusal {
    /// V05's cleanup safety check refused it (§6.4; VM-P49).
    Unsafe { cleanup: CleanupRefusal },
    /// The object is kept for recovery: a response never deletes it (VM-W43).
    PreservedForRecovery {
        object: Digest,
        kind: ManagedObjectKind,
    },
}

impl fmt::Display for ResponseCleanupRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsafe { cleanup } => write!(f, "the cleanup is unsafe: {cleanup:?}"),
            Self::PreservedForRecovery { object, .. } => write!(
                f,
                "object {object} is kept for recovery; a response never deletes it"
            ),
        }
    }
}

impl std::error::Error for ResponseCleanupRefusal {}

/// Plans one cleanup step after a response: V05's safety check first, then the response
/// scope, so only the stopped VM's process, perimeter and sockets go
/// ([`RESPONSE_CLEANUP_KINDS`]).
pub fn plan_response_cleanup(
    objects: &ManagedObjects,
    target: &CleanupTarget,
    observed: &ObservedIdentities,
) -> Result<CleanupPlan, ResponseCleanupRefusal> {
    let plan = objects
        .validate_cleanup(target, observed)
        .map_err(|cleanup| ResponseCleanupRefusal::Unsafe { cleanup })?;
    match plan {
        CleanupPlan::Delete { object, kind, .. } if !response_cleanup_allows(kind) => {
            Err(ResponseCleanupRefusal::PreservedForRecovery { object, kind })
        }
        plan => Ok(plan),
    }
}

/// One decision (VM-W43): a bounded set of actions, the V05 class response when it stops,
/// the rung it reaches, the reason and what it preserves.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Decision {
    pub input: DecisionInput,
    /// At most the six actions a policy decides ([`ResponseAction::RevokeGrant`] is never
    /// one).
    pub actions: BTreeSet<ResponseAction>,
    /// V05's VM-D10 response, present exactly when the actions include a stop.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class_response: Option<ViolationAction>,
    pub rung: EscalationRung,
    pub reason: DecisionReason,
    pub preserves: Vec<Preserved>,
}

/// What a sandbox of `class` keeps under `actions`: everything, and the VM's state unless
/// the actions stop a task sandbox.
pub(super) fn preserved_under(
    actions: &BTreeSet<ResponseAction>,
    class: SandboxClass,
) -> Vec<Preserved> {
    let mut preserves: Vec<Preserved> = VolumeClass::ALL
        .iter()
        .map(|&class| Preserved::Volume { class })
        .collect();
    preserves.extend([
        Preserved::HostWorkspaces,
        Preserved::Artifacts,
        Preserved::Snapshots,
        Preserved::RootOverlayAndScratch,
    ]);
    let ends_vm = actions.contains(&ResponseAction::Stop)
        && StopPolicy::class_response(class) == ViolationAction::Stop;
    if !ends_vm {
        preserves.push(Preserved::VmState);
    }
    preserves
}

/// The rung a set of actions reaches.
pub(super) fn rung_of(actions: &BTreeSet<ResponseAction>) -> EscalationRung {
    actions
        .iter()
        .map(|action| action.rung())
        .max()
        .unwrap_or(EscalationRung::Notify)
}

/// The decision function of VM-W43: (class, source, freshness, sandbox class) to a bounded
/// set of actions with a recorded reason. See the module documentation for the rules.
pub fn decide(policies: &ResponsePolicies, input: &DecisionInput) -> Decision {
    let mut actions = BTreeSet::new();
    let reason = match input.source {
        SignalSource::GuestReported => {
            actions.insert(ResponseAction::NotifyUser);
            actions.insert(ResponseAction::RequestHostCorroboration);
            DecisionReason::GuestReportNeedsCorroboration { class: input.class }
        }
        SignalSource::HostObserved { observer } => match (input.freshness, input.class) {
            (Freshness::Stale { .. } | Freshness::Conflicting { .. }, class) => {
                actions.extend(UncertainPolicy::ACTIONS);
                DecisionReason::Uncertain {
                    class,
                    observer,
                    freshness: input.freshness,
                }
            }
            (Freshness::Fresh, SignalClass::Violation { kind }) => {
                actions.insert(ResponseAction::NotifyUser);
                actions.insert(ResponseAction::DenyNewHighImpact);
                if policies.isolate.triggers.contains(&input.class) {
                    actions.insert(ResponseAction::Isolate);
                }
                if policies.revoke.triggers.contains(&kind) {
                    actions.insert(ResponseAction::Revoke);
                }
                if policies.stop.triggers.contains(&kind) {
                    actions.insert(ResponseAction::Stop);
                }
                DecisionReason::KnownViolation {
                    kind,
                    observer,
                    meaning: (kind == ViolationKind::CanaryUse)
                        .then_some(HitMeaning::SignalNotProof),
                }
            }
            (Freshness::Fresh, SignalClass::Resource { resource }) => {
                actions.insert(ResponseAction::NotifyUser);
                if resource == MonitoredResource::ReleaseBudgetSpentBytes {
                    actions.insert(ResponseAction::DenyNewHighImpact);
                }
                if policies.isolate.triggers.contains(&input.class) {
                    actions.insert(ResponseAction::Isolate);
                }
                DecisionReason::SustainedResource { resource, observer }
            }
        },
    };
    let class_response = actions
        .contains(&ResponseAction::Stop)
        .then(|| StopPolicy::class_response(input.sandbox_class));
    Decision {
        input: *input,
        rung: rung_of(&actions),
        preserves: preserved_under(&actions, input.sandbox_class),
        actions,
        class_response,
        reason,
    }
}
