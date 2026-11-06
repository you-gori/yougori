//! The broker identity, the fail-closed install plan and the elevation grant (VM §4.4;
//! VM-W15: "Transactional platform perimeter with stable process identity"; VM-D3: the
//! strict profile needs one elevation to install the host perimeter).
//!
//! A plan moves the perimeter's own rules from what the store holds to the target in an
//! order that never permits more than the old set or the new one at any step: new block
//! rules first, then old allow rules out, then new allow rules in, then old block rules
//! out. Under the store's evaluation model (an explicit block wins and anything unmatched
//! is denied) every intermediate state permits a subset of the old set until the first
//! new allow is added, and a subset of the new set from then on, so an install stopped at
//! any step is no wider than a set the owner approved.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::store::{OwnedRule, OwnerTag, RuleHandle, ScopedRule, StoreEntry, TransactionId};
use crate::foundation::coordination::PerimeterId;
use crate::foundation::ids::{Digest, DigestBuilder};
use crate::sandbox_contract::destinations::{PerimeterPlatform, RuleAction};

/// Domain of [`InstallPlan::digest`].
pub const PLAN_DOMAIN: &str = "yougori/sandbox/perimeter-install-plan/v1";

/// How the platform names the broker's identity (VM §4.4: Linux "dedicated identities/net
/// namespaces"; Windows "the actual process or service identity"; macOS "the exact
/// supported sandbox/network enforcement APIs and identities").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityKind {
    /// Linux: an account only the broker runs as.
    DedicatedAccount,
    /// Linux: a network namespace only the broker runs in.
    NetworkNamespace,
    /// Linux: a cgroup only the broker runs in.
    Cgroup,
    /// Windows: the broker service's SID.
    ServiceSid,
    /// Windows: the broker's AppContainer or package identity.
    AppContainer,
    /// macOS: the broker's code-signing identity, as the supported enforcement API takes
    /// it.
    SigningIdentity,
    /// Never accepted: a user rule cannot single out one same-user process (VM-P27).
    UserAccount,
    /// Never accepted: a process ID changes on every restart and is reused.
    ProcessId,
}

impl IdentityKind {
    /// The platforms on which this kind names one stable broker identity. Empty for the
    /// kinds that never do.
    pub const fn platforms(self) -> &'static [PerimeterPlatform] {
        match self {
            Self::DedicatedAccount | Self::NetworkNamespace | Self::Cgroup => {
                &[PerimeterPlatform::Linux]
            }
            Self::ServiceSid | Self::AppContainer => &[PerimeterPlatform::Windows],
            Self::SigningIdentity => &[PerimeterPlatform::MacOs],
            Self::UserAccount | Self::ProcessId => &[],
        }
    }
}

impl fmt::Display for IdentityKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::DedicatedAccount => "dedicated account",
            Self::NetworkNamespace => "network namespace",
            Self::Cgroup => "cgroup",
            Self::ServiceSid => "service SID",
            Self::AppContainer => "AppContainer",
            Self::SigningIdentity => "signing identity",
            Self::UserAccount => "user account",
            Self::ProcessId => "process ID",
        })
    }
}

/// The broker the perimeter constrains: a stable identity of one kind, by digest. The
/// digest must equal the V02 profile's `broker_identity`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerIdentity {
    pub kind: IdentityKind,
    pub identity: Digest,
}

/// One step of a plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PlanStep {
    Add {
        scoped: ScopedRule,
    },
    Remove {
        handle: RuleHandle,
        scoped: ScopedRule,
    },
}

impl PlanStep {
    pub const fn scoped(&self) -> ScopedRule {
        match self {
            Self::Add { scoped } | Self::Remove { scoped, .. } => *scoped,
        }
    }
}

/// The steps that move `current` to exactly `target`, in the fail-closed order: adds of
/// block rules, removals of allow rules, adds of allow rules, removals of block rules. A
/// rule already present keeps its lowest handle; any further copy is removed.
pub(super) fn ordered_steps(
    current: &BTreeMap<RuleHandle, ScopedRule>,
    target: &BTreeSet<ScopedRule>,
) -> Vec<PlanStep> {
    let mut kept = BTreeSet::new();
    let mut removals = Vec::new();
    for (handle, scoped) in current {
        if target.contains(scoped) && kept.insert(*scoped) {
            continue;
        }
        removals.push(PlanStep::Remove {
            handle: *handle,
            scoped: *scoped,
        });
    }
    let adds: Vec<PlanStep> = target
        .iter()
        .filter(|scoped| !kept.contains(*scoped))
        .map(|scoped| PlanStep::Add { scoped: *scoped })
        .collect();
    let of = |steps: &[PlanStep], action: RuleAction| -> Vec<PlanStep> {
        steps
            .iter()
            .filter(|step| step.scoped().rule.action == action)
            .copied()
            .collect()
    };
    let mut steps = of(&adds, RuleAction::Block);
    steps.extend(of(&removals, RuleAction::Allow));
    steps.extend(of(&adds, RuleAction::Allow));
    steps.extend(of(&removals, RuleAction::Block));
    steps
}

/// A planned transaction of one perimeter: the owned rules it starts from, the target and
/// the ordered steps. Planning writes nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallPlan {
    pub(super) tag: OwnerTag,
    /// `None` for a teardown, which adds nothing.
    pub(super) broker: Option<BrokerIdentity>,
    /// The digest of the V02 profile being installed; `None` for a teardown.
    pub(super) profile: Option<Digest>,
    pub(super) prior: BTreeMap<RuleHandle, ScopedRule>,
    pub(super) target: BTreeSet<ScopedRule>,
    pub(super) steps: Vec<PlanStep>,
}

impl InstallPlan {
    pub const fn perimeter(&self) -> PerimeterId {
        self.tag.perimeter
    }

    pub const fn transaction(&self) -> TransactionId {
        self.tag.transaction
    }

    pub const fn tag(&self) -> OwnerTag {
        self.tag
    }

    pub const fn broker(&self) -> Option<BrokerIdentity> {
        self.broker
    }

    pub fn prior(&self) -> &BTreeMap<RuleHandle, ScopedRule> {
        &self.prior
    }

    pub fn target(&self) -> &BTreeSet<ScopedRule> {
        &self.target
    }

    pub fn steps(&self) -> &[PlanStep] {
        &self.steps
    }

    /// A digest of everything the plan does, which its elevation grant binds.
    pub fn digest(&self) -> Digest {
        let mut builder = DigestBuilder::new(PLAN_DOMAIN)
            .digest(&self.tag.perimeter.digest())
            .u64(self.tag.transaction.get());
        builder = match self.broker {
            Some(broker) => builder
                .str(&format!("{:?}", broker.kind))
                .digest(&broker.identity),
            None => builder.str("teardown"),
        };
        builder = match self.profile {
            Some(profile) => builder.str("profile").digest(&profile),
            None => builder.str("no profile"),
        };
        builder = builder.u64(u64::try_from(self.prior.len()).unwrap_or(u64::MAX));
        for (handle, scoped) in &self.prior {
            builder = builder
                .u64(handle.get())
                .digest(&scoped.identity)
                .digest(&scoped.rule.digest());
        }
        builder = builder.u64(u64::try_from(self.steps.len()).unwrap_or(u64::MAX));
        for step in &self.steps {
            builder = match step {
                PlanStep::Add { .. } => builder.str("add"),
                PlanStep::Remove { handle, .. } => builder.str("remove").u64(handle.get()),
            }
            .digest(&step.scoped().identity)
            .digest(&step.scoped().rule.digest());
        }
        builder.finish()
    }

    /// The grant the elevated side is asked for: it may add the target's rules and the
    /// prior ones (a rollback re-adds them) under this transaction's tag, and remove the
    /// perimeter's committed rules and any rule this transaction tagged. Nothing else.
    pub fn grant_request(&self) -> ElevationGrant {
        ElevationGrant {
            tag: self.tag,
            plan: self.digest(),
            may_add: self
                .target
                .iter()
                .chain(self.prior.values())
                .copied()
                .collect(),
            may_remove: self.prior.keys().copied().collect(),
        }
    }
}

/// What one elevation covers (VM §4.4: "Use elevation only for the concrete operations
/// that require it"). How the one elevation of VM-D3 is realised, a prompt per install or
/// an elevated helper installed once, is production work; either way the elevated side
/// performs only operations its grant covers. A grant is a record of that scope, not a
/// credential.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElevationGrant {
    pub tag: OwnerTag,
    /// The [`InstallPlan::digest`] the grant was issued for.
    pub plan: Digest,
    pub may_add: BTreeSet<ScopedRule>,
    pub may_remove: BTreeSet<RuleHandle>,
}

impl ElevationGrant {
    pub fn permits_add(&self, rule: &OwnedRule) -> bool {
        rule.tag == self.tag && self.may_add.contains(&rule.scoped)
    }

    /// A removal is covered for a committed rule the grant lists, or for a rule this
    /// transaction tagged.
    pub fn permits_remove(&self, handle: RuleHandle, entry: &StoreEntry) -> bool {
        self.may_remove.contains(&handle) || entry.tag == Some(self.tag)
    }
}
