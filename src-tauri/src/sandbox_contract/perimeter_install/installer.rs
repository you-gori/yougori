//! The transactional installer (VM §4.4: "Install/update rules transactionally, verify
//! their scope, preserve unrelated rules, and provide a rollback"; VM-W15).
//!
//! [`Installer::prepare`] reads the store and plans; nothing is written. The owner's one
//! elevation yields an [`ElevationGrant`] for exactly that plan, and
//! [`Installer::execute`] then writes the journal ahead of every step, applies the steps
//! in the fail-closed order, reads the store back and verifies it: the perimeter's own
//! rules equal the target exactly, each is scoped to the broker's identity, the identity
//! is isolated and no other rule constrains it, and every rule that was not the
//! perimeter's own before the transaction is unchanged. Any store failure or failed check
//! rolls the perimeter back to the rules it had before, in the same fail-closed order.
//! An installer that stopped part way (its journal could not be written, or the process
//! died) rolls back through [`Installer::recover`], which also claims rules the pending
//! transaction added but had not yet recorded.
//!
//! A receipt says what the store reported, never that the kernel enforces it: a rule
//! counts as enforced only through CORE-01 `PerimeterRuleEnforced` evidence from a V02
//! must-probe on the actual broker identity.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::journal::{CompletedStep, InstallJournal, JournalFailure, JournalStore, PendingInstall};
use super::plan::{
    ordered_steps, BrokerIdentity, ElevationGrant, IdentityKind, InstallPlan, PlanStep,
};
use super::store::{
    OwnedRule, OwnerTag, RuleHandle, RuleStore, ScopedRule, StoreEntry, StoreFailure,
    StoreSnapshot, TransactionId,
};
use crate::foundation::coordination::PerimeterId;
use crate::foundation::ids::Digest;
use crate::sandbox_contract::destinations::{PerimeterPlatform, PerimeterProfile};

/// Why an install was refused before anything was written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallRefusal {
    /// A remote perimeter is enforced outside this host (VM §4.4, Remote); the local
    /// installer does not install one.
    RemotePerimeter,
    /// The identity kind never names one stable broker process.
    IdentityKindRefused {
        kind: IdentityKind,
    },
    /// The identity kind does not exist on this platform.
    IdentityKindNotOnPlatform {
        kind: IdentityKind,
        platform: PerimeterPlatform,
    },
    /// The broker's identity is not the one the profile constrains.
    IdentityMismatch {
        profile: Digest,
        broker: Digest,
    },
    /// The store does not isolate the broker's identity, so rules outside the perimeter
    /// could permit its traffic.
    ScopeNotIsolated,
    /// A rule the perimeter does not own constrains the broker's identity, including
    /// another perimeter's rule on a shared identity.
    ForeignRuleOnBroker {
        handle: RuleHandle,
    },
    /// A rule carries this perimeter's tag but the journal never recorded it. It is left
    /// alone; an operator decides what it is.
    UnclaimedTaggedRule {
        handle: RuleHandle,
    },
    /// The store holds something else under a handle the journal records.
    OwnedRuleAltered {
        handle: RuleHandle,
    },
    /// A transaction is pending; recover it first.
    PendingTransaction {
        transaction: TransactionId,
    },
    /// Transaction numbers are exhausted; one is never reused.
    TransactionsExhausted,
    Store {
        failure: StoreFailure,
    },
}

impl fmt::Display for InstallRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RemotePerimeter => {
                f.write_str("a remote perimeter is enforced outside this host and is not installed here")
            }
            Self::IdentityKindRefused { kind } => {
                write!(f, "a {kind} does not name one stable broker process")
            }
            Self::IdentityKindNotOnPlatform { kind, platform } => {
                write!(f, "a {kind} is not an identity on {platform:?}")
            }
            Self::IdentityMismatch { profile, broker } => write!(
                f,
                "the profile constrains broker identity {profile}, not {broker}"
            ),
            Self::ScopeNotIsolated => f.write_str(
                "the rule store does not isolate the broker's identity, so other rules could permit its traffic",
            ),
            Self::ForeignRuleOnBroker { handle } => write!(
                f,
                "{handle}, which this perimeter does not own, constrains the broker's identity"
            ),
            Self::UnclaimedTaggedRule { handle } => write!(
                f,
                "{handle} carries this perimeter's tag but the journal never recorded it; it was left alone"
            ),
            Self::OwnedRuleAltered { handle } => {
                write!(f, "the store holds something else under the perimeter's {handle}")
            }
            Self::PendingTransaction { transaction } => {
                write!(f, "transaction {transaction} is pending; recover it first")
            }
            Self::TransactionsExhausted => f.write_str("transaction numbers are exhausted"),
            Self::Store { failure } => write!(f, "{failure}"),
        }
    }
}

impl std::error::Error for InstallRefusal {}

/// What the read-back after the steps found wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum VerificationFailure {
    Unreadable {
        failure: StoreFailure,
    },
    /// A target rule is not in the store.
    Missing {
        scoped: ScopedRule,
    },
    /// The perimeter owns a rule that is not in the target.
    Unexpected {
        handle: RuleHandle,
    },
    /// A target rule is in the store more than once.
    Duplicate {
        scoped: ScopedRule,
    },
    /// A rule that was not the perimeter's own changed or disappeared during the
    /// transaction (VM-W15: "no unrelated PC rule changes"). The installer cannot tell
    /// whether it did this, so the check fails.
    ForeignRuleChanged {
        handle: RuleHandle,
    },
    ForeignRuleOnBroker {
        handle: RuleHandle,
    },
    ScopeNotIsolated,
    UnclaimedTaggedRule {
        handle: RuleHandle,
    },
    OwnedRuleAltered {
        handle: RuleHandle,
    },
}

impl fmt::Display for VerificationFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable { failure } => {
                write!(f, "the store could not be read back: {failure}")
            }
            Self::Missing { scoped } => {
                write!(f, "the store lacks the rule for {}", scoped.rule.prefix)
            }
            Self::Unexpected { handle } => {
                write!(f, "the perimeter owns {handle}, which is not in the target")
            }
            Self::Duplicate { scoped } => {
                write!(
                    f,
                    "the rule for {} is installed more than once",
                    scoped.rule.prefix
                )
            }
            Self::ForeignRuleChanged { handle } => {
                write!(
                    f,
                    "{handle}, which is not the perimeter's, changed during the install"
                )
            }
            Self::ForeignRuleOnBroker { handle } => {
                write!(
                    f,
                    "{handle}, which is not the perimeter's, constrains the broker's identity"
                )
            }
            Self::ScopeNotIsolated => f.write_str("the broker's identity is no longer isolated"),
            Self::UnclaimedTaggedRule { handle } => {
                write!(
                    f,
                    "{handle} carries this perimeter's tag but no recorded transaction"
                )
            }
            Self::OwnedRuleAltered { handle } => {
                write!(
                    f,
                    "the store holds something else under the perimeter's {handle}"
                )
            }
        }
    }
}

/// Why a transaction was abandoned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbortCause {
    Store {
        failure: StoreFailure,
    },
    Verification {
        failure: VerificationFailure,
    },
    /// The installer stopped part way and is recovering.
    Interrupted,
}

impl fmt::Display for AbortCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store { failure } => write!(f, "{failure}"),
            Self::Verification { failure } => write!(f, "{failure}"),
            Self::Interrupted => f.write_str("the installer stopped part way"),
        }
    }
}

/// Why a rollback did not restore the prior rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RollbackFailure {
    Store { failure: StoreFailure },
    OwnedRuleAltered { handle: RuleHandle },
    Verification { failure: VerificationFailure },
    Journal,
}

impl fmt::Display for RollbackFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store { failure } => write!(f, "{failure}"),
            Self::OwnedRuleAltered { handle } => {
                write!(
                    f,
                    "the store holds something else under the perimeter's {handle}"
                )
            }
            Self::Verification { failure } => write!(f, "{failure}"),
            Self::Journal => write!(f, "{JournalFailure}"),
        }
    }
}

/// Why [`Installer::execute`] or [`Installer::recover`] did not finish.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallError {
    /// Nothing was written.
    Refused { refusal: InstallRefusal },
    /// The grant is not the one the plan requested. Nothing was written.
    GrantMismatch,
    /// The store or the journal changed since the plan was made. Nothing was written.
    StalePlan,
    /// The journal could not be written, so the installer stopped. With `pending`, the
    /// store may hold a partial state, which the fail-closed order keeps within the old
    /// or the new rules; [`Installer::recover`] rolls it back.
    Journal { pending: Option<TransactionId> },
    /// The transaction failed and the prior rules were restored and verified.
    RolledBack { cause: AbortCause },
    /// The transaction failed and the rollback did too. The transaction stays pending and
    /// the perimeter is not ready.
    RollbackIncomplete {
        cause: AbortCause,
        rollback: RollbackFailure,
    },
}

impl fmt::Display for InstallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused { refusal } => write!(f, "{refusal}"),
            Self::GrantMismatch => f.write_str("the elevation grant is not for this plan"),
            Self::StalePlan => f.write_str("the rule store or journal changed since the plan was made"),
            Self::Journal { pending: None } => write!(f, "{JournalFailure}; nothing was changed"),
            Self::Journal {
                pending: Some(transaction),
            } => write!(
                f,
                "{JournalFailure}; transaction {transaction} stopped part way and must be recovered"
            ),
            Self::RolledBack { cause } => {
                write!(f, "the install failed ({cause}) and the prior rules were restored")
            }
            Self::RollbackIncomplete { cause, rollback } => write!(
                f,
                "the install failed ({cause}) and so did the rollback ({rollback}); the perimeter is not ready"
            ),
        }
    }
}

impl std::error::Error for InstallError {}

/// A plan with the store state it was made against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedInstall {
    plan: InstallPlan,
    /// Handles the journal recorded that the store no longer has.
    vanished: BTreeSet<RuleHandle>,
}

impl PreparedInstall {
    pub fn plan(&self) -> &InstallPlan {
        &self.plan
    }

    pub fn vanished(&self) -> &BTreeSet<RuleHandle> {
        &self.vanished
    }

    /// The grant to ask the elevated side for.
    pub fn grant_request(&self) -> ElevationGrant {
        self.plan.grant_request()
    }
}

/// What a committed transaction left in the store, as the store reported it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallReceipt {
    pub tag: OwnerTag,
    pub plan: Digest,
    /// The V02 profile digest; `None` for a teardown.
    pub profile: Option<Digest>,
    pub broker: Option<BrokerIdentity>,
    pub owned: Vec<(RuleHandle, ScopedRule)>,
    /// Handles the journal recorded that had disappeared before the transaction.
    pub vanished: BTreeSet<RuleHandle>,
    /// Rules other programs added during the transaction, none on the broker's identity.
    pub foreign_added: usize,
}

/// What [`Installer::recover`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryReport {
    NothingPending,
    /// The pending transaction was rolled back to the last committed rules. `untouched`
    /// lists rules with this perimeter's tag from no known transaction, left alone.
    RolledBack {
        transaction: TransactionId,
        untouched: BTreeSet<RuleHandle>,
    },
}

/// The store split into the perimeter's own rules and everything else.
struct Survey {
    owned: BTreeMap<RuleHandle, ScopedRule>,
    foreign: BTreeMap<RuleHandle, StoreEntry>,
    unclaimed: BTreeSet<RuleHandle>,
}

/// Splits `snapshot`: a rule is the perimeter's own when the journal recorded its handle
/// (and it is still that rule under this perimeter's tag) or when it carries `claim`, the
/// pending transaction's tag. A rule with this perimeter's tag from any other transaction
/// is unclaimed. An altered recorded rule is an error naming its handle.
fn survey(
    journal: &InstallJournal,
    snapshot: &StoreSnapshot,
    claim: Option<OwnerTag>,
) -> Result<Survey, RuleHandle> {
    let perimeter = journal.perimeter();
    let mut found = Survey {
        owned: BTreeMap::new(),
        foreign: BTreeMap::new(),
        unclaimed: BTreeSet::new(),
    };
    for (handle, entry) in &snapshot.entries {
        let ours = entry.tag.map(|tag| tag.perimeter) == Some(perimeter);
        if let Some(recorded) = journal.owned().get(handle) {
            if !ours || entry.scoped() != Some(*recorded) {
                return Err(*handle);
            }
            found.owned.insert(*handle, *recorded);
        } else if claim.is_some() && entry.tag == claim {
            let scoped = entry.scoped().ok_or(*handle)?;
            found.owned.insert(*handle, scoped);
        } else if ours {
            found.unclaimed.insert(*handle);
        } else {
            found.foreign.insert(*handle, *entry);
        }
    }
    Ok(found)
}

/// The first rule outside the perimeter that constrains `identity`.
fn foreign_on(foreign: &BTreeMap<RuleHandle, StoreEntry>, identity: Digest) -> Option<RuleHandle> {
    foreign
        .iter()
        .find(|(_, entry)| entry.constrains(identity))
        .map(|(handle, _)| *handle)
}

fn check_scope(
    snapshot: &StoreSnapshot,
    foreign: &BTreeMap<RuleHandle, StoreEntry>,
    identity: Digest,
) -> Result<(), InstallRefusal> {
    if !snapshot.isolated.contains(&identity) {
        return Err(InstallRefusal::ScopeNotIsolated);
    }
    match foreign_on(foreign, identity) {
        Some(handle) => Err(InstallRefusal::ForeignRuleOnBroker { handle }),
        None => Ok(()),
    }
}

fn apply<S: RuleStore>(
    step: &PlanStep,
    tag: OwnerTag,
    grant: &ElevationGrant,
    store: &mut S,
) -> Result<CompletedStep, StoreFailure> {
    match *step {
        PlanStep::Add { scoped } => {
            let handle = store.add(grant, &OwnedRule { tag, scoped })?;
            Ok(CompletedStep::Added { handle, scoped })
        }
        PlanStep::Remove { handle, scoped } => {
            store.remove(grant, handle)?;
            Ok(CompletedStep::Removed { handle, scoped })
        }
    }
}

struct Verified {
    owned: BTreeMap<RuleHandle, ScopedRule>,
    foreign_added: usize,
}

/// What a read-back checks besides the perimeter's own rules.
struct Checks<'a> {
    /// Every rule that was outside the perimeter before must be unchanged.
    baseline: Option<&'a BTreeMap<RuleHandle, StoreEntry>>,
    /// The broker's identity must still be isolated and constrained by no other rule.
    identity: Option<Digest>,
    /// Unclaimed tagged rules fail the check. A rollback leaves the ones that were there
    /// before it alone instead.
    refuse_unclaimed: bool,
}

/// Reads the store back and checks the perimeter's own rules against `target` and the
/// rest against `checks`.
fn verify<S: RuleStore>(
    store: &S,
    journal: &InstallJournal,
    tag: OwnerTag,
    target: &BTreeSet<ScopedRule>,
    checks: Checks<'_>,
) -> Result<Verified, VerificationFailure> {
    let snapshot = store
        .snapshot()
        .map_err(|failure| VerificationFailure::Unreadable { failure })?;
    let found = survey(journal, &snapshot, Some(tag))
        .map_err(|handle| VerificationFailure::OwnedRuleAltered { handle })?;
    if let (true, Some(handle)) = (checks.refuse_unclaimed, found.unclaimed.first()) {
        return Err(VerificationFailure::UnclaimedTaggedRule { handle: *handle });
    }
    let mut seen = BTreeSet::new();
    for (handle, scoped) in &found.owned {
        if !target.contains(scoped) {
            return Err(VerificationFailure::Unexpected { handle: *handle });
        }
        if !seen.insert(*scoped) {
            return Err(VerificationFailure::Duplicate { scoped: *scoped });
        }
    }
    if let Some(scoped) = target.iter().find(|scoped| !seen.contains(*scoped)) {
        return Err(VerificationFailure::Missing { scoped: *scoped });
    }
    let mut foreign_added = 0_usize;
    if let Some(baseline) = checks.baseline {
        for (handle, entry) in baseline {
            if found.foreign.get(handle) != Some(entry) {
                return Err(VerificationFailure::ForeignRuleChanged { handle: *handle });
            }
        }
        foreign_added = found
            .foreign
            .keys()
            .filter(|handle| !baseline.contains_key(*handle))
            .count();
    }
    if let Some(identity) = checks.identity {
        if !snapshot.isolated.contains(&identity) {
            return Err(VerificationFailure::ScopeNotIsolated);
        }
        if let Some(handle) = foreign_on(&found.foreign, identity) {
            return Err(VerificationFailure::ForeignRuleOnBroker { handle });
        }
    }
    Ok(Verified {
        owned: found.owned,
        foreign_added,
    })
}

fn check_broker(
    platform: PerimeterPlatform,
    broker: BrokerIdentity,
    profile_identity: Digest,
) -> Result<(), InstallRefusal> {
    if platform == PerimeterPlatform::Remote {
        return Err(InstallRefusal::RemotePerimeter);
    }
    let platforms = broker.kind.platforms();
    if platforms.is_empty() {
        return Err(InstallRefusal::IdentityKindRefused { kind: broker.kind });
    }
    if !platforms.contains(&platform) {
        return Err(InstallRefusal::IdentityKindNotOnPlatform {
            kind: broker.kind,
            platform,
        });
    }
    if broker.identity != profile_identity {
        return Err(InstallRefusal::IdentityMismatch {
            profile: profile_identity,
            broker: broker.identity,
        });
    }
    Ok(())
}

/// The installer of one perimeter, over its journal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Installer {
    journal: InstallJournal,
}

impl Installer {
    /// An installer for a perimeter that has never installed anything.
    pub fn new(perimeter: PerimeterId) -> Self {
        Self {
            journal: InstallJournal::new(perimeter),
        }
    }

    /// An installer over its last persisted journal, as after a restart.
    pub fn restore(journal: InstallJournal) -> Self {
        Self { journal }
    }

    /// The last persisted journal.
    pub fn journal(&self) -> &InstallJournal {
        &self.journal
    }

    /// No transaction is pending. Readiness for a boot (VM §6.1 perimeter_ready) also
    /// needs CORE-01 enforcement evidence for the rules; this is only the store side.
    pub fn settled(&self) -> bool {
        self.journal.pending().is_none()
    }

    /// Plans installing `profile`'s rules for `broker`. Reads the store; writes nothing.
    pub fn prepare<S: RuleStore>(
        &self,
        store: &S,
        profile: &PerimeterProfile,
        broker: BrokerIdentity,
    ) -> Result<PreparedInstall, InstallRefusal> {
        check_broker(profile.platform(), broker, profile.broker_identity())?;
        let target = profile
            .rules()
            .iter()
            .map(|rule| ScopedRule {
                identity: broker.identity,
                rule: *rule,
            })
            .collect();
        self.prepare_target(store, Some(broker), Some(profile.digest()), target)
    }

    /// Plans removing every rule the perimeter owns: allow rules first, then block rules.
    pub fn prepare_teardown<S: RuleStore>(
        &self,
        store: &S,
    ) -> Result<PreparedInstall, InstallRefusal> {
        self.prepare_target(store, None, None, BTreeSet::new())
    }

    fn prepare_target<S: RuleStore>(
        &self,
        store: &S,
        broker: Option<BrokerIdentity>,
        profile: Option<Digest>,
        target: BTreeSet<ScopedRule>,
    ) -> Result<PreparedInstall, InstallRefusal> {
        if let Some(pending) = self.journal.pending() {
            return Err(InstallRefusal::PendingTransaction {
                transaction: pending.transaction,
            });
        }
        let transaction = self
            .journal
            .next_transaction()
            .ok_or(InstallRefusal::TransactionsExhausted)?;
        let snapshot = store
            .snapshot()
            .map_err(|failure| InstallRefusal::Store { failure })?;
        let found = self.survey_for_plan(&snapshot, broker)?;
        let vanished = self
            .journal
            .owned()
            .keys()
            .filter(|handle| !found.owned.contains_key(*handle))
            .copied()
            .collect();
        let steps = ordered_steps(&found.owned, &target);
        Ok(PreparedInstall {
            plan: InstallPlan {
                tag: OwnerTag {
                    perimeter: self.journal.perimeter(),
                    transaction,
                },
                broker,
                profile,
                prior: found.owned,
                target,
                steps,
            },
            vanished,
        })
    }

    fn survey_for_plan(
        &self,
        snapshot: &StoreSnapshot,
        broker: Option<BrokerIdentity>,
    ) -> Result<Survey, InstallRefusal> {
        let found = survey(&self.journal, snapshot, None)
            .map_err(|handle| InstallRefusal::OwnedRuleAltered { handle })?;
        if let Some(handle) = found.unclaimed.first() {
            return Err(InstallRefusal::UnclaimedTaggedRule { handle: *handle });
        }
        if let Some(broker) = broker {
            check_scope(snapshot, &found.foreign, broker.identity)?;
        }
        Ok(found)
    }

    /// Runs `prepared` under `grant`, which must be exactly the plan's request.
    pub fn execute<S: RuleStore, J: JournalStore>(
        &mut self,
        prepared: &PreparedInstall,
        grant: &ElevationGrant,
        store: &mut S,
        sink: &mut J,
    ) -> Result<InstallReceipt, InstallError> {
        let plan = &prepared.plan;
        if *grant != plan.grant_request() {
            return Err(InstallError::GrantMismatch);
        }
        if self.journal.pending().is_some()
            || self.journal.next_transaction() != Some(plan.transaction())
        {
            return Err(InstallError::StalePlan);
        }
        let snapshot = store.snapshot().map_err(|failure| InstallError::Refused {
            refusal: InstallRefusal::Store { failure },
        })?;
        let found = self
            .survey_for_plan(&snapshot, plan.broker)
            .map_err(|refusal| InstallError::Refused { refusal })?;
        if found.owned != plan.prior {
            return Err(InstallError::StalePlan);
        }

        let transaction = plan.transaction();
        let mut next = self.journal.clone();
        next.settle(plan.prior.clone());
        next.begin(PendingInstall {
            transaction,
            plan: grant.plan,
            broker: plan.broker,
            target: plan.target.clone(),
            completed: Vec::new(),
        });
        self.persist(next, sink)
            .map_err(|_| InstallError::Journal { pending: None })?;

        for step in &plan.steps {
            let completed = match apply(step, plan.tag, grant, store) {
                Ok(completed) => completed,
                Err(failure) => {
                    return Err(self.roll_back(AbortCause::Store { failure }, grant, store, sink))
                }
            };
            let mut next = self.journal.clone();
            next.record(completed);
            self.persist(next, sink)
                .map_err(|_| InstallError::Journal {
                    pending: Some(transaction),
                })?;
        }

        let checks = Checks {
            baseline: Some(&found.foreign),
            identity: plan.broker.map(|broker| broker.identity),
            refuse_unclaimed: true,
        };
        let verified = match verify(store, &self.journal, plan.tag, &plan.target, checks) {
            Ok(verified) => verified,
            Err(failure) => {
                return Err(self.roll_back(
                    AbortCause::Verification { failure },
                    grant,
                    store,
                    sink,
                ))
            }
        };
        let mut next = self.journal.clone();
        next.settle(verified.owned.clone());
        self.persist(next, sink)
            .map_err(|_| InstallError::Journal {
                pending: Some(transaction),
            })?;
        Ok(InstallReceipt {
            tag: plan.tag,
            plan: grant.plan,
            profile: plan.profile,
            broker: plan.broker,
            owned: verified.owned.into_iter().collect(),
            vanished: prepared.vanished.clone(),
            foreign_added: verified.foreign_added,
        })
    }

    /// The grant recovery needs: the same one the pending transaction was issued.
    pub fn recovery_request(&self) -> Option<ElevationGrant> {
        let tag = self.journal.pending_tag()?;
        let pending = self.journal.pending()?;
        Some(ElevationGrant {
            tag,
            plan: pending.plan,
            may_add: pending
                .target
                .iter()
                .chain(self.journal.owned().values())
                .copied()
                .collect(),
            may_remove: self.journal.owned().keys().copied().collect(),
        })
    }

    /// Rolls a pending transaction back to the last committed rules, claiming rules it
    /// tagged whether or not they were recorded. Always a rollback, even when every step
    /// had completed: the conservative reading of a transaction that did not commit.
    pub fn recover<S: RuleStore, J: JournalStore>(
        &mut self,
        grant: &ElevationGrant,
        store: &mut S,
        sink: &mut J,
    ) -> Result<RecoveryReport, InstallError> {
        let Some(request) = self.recovery_request() else {
            return Ok(RecoveryReport::NothingPending);
        };
        if *grant != request {
            return Err(InstallError::GrantMismatch);
        }
        let transaction = request.tag.transaction;
        self.restore_prior(grant, store, sink)
            .map(|untouched| RecoveryReport::RolledBack {
                transaction,
                untouched,
            })
            .map_err(|rollback| InstallError::RollbackIncomplete {
                cause: AbortCause::Interrupted,
                rollback,
            })
    }

    fn roll_back<S: RuleStore, J: JournalStore>(
        &mut self,
        cause: AbortCause,
        grant: &ElevationGrant,
        store: &mut S,
        sink: &mut J,
    ) -> InstallError {
        match self.restore_prior(grant, store, sink) {
            Ok(_) => InstallError::RolledBack { cause },
            Err(rollback) => InstallError::RollbackIncomplete { cause, rollback },
        }
    }

    /// Moves the perimeter's rules back to the journal's committed set in the fail-closed
    /// order, verifies, and settles the journal. Returns the unclaimed tagged rules it left
    /// alone.
    fn restore_prior<S: RuleStore, J: JournalStore>(
        &mut self,
        grant: &ElevationGrant,
        store: &mut S,
        sink: &mut J,
    ) -> Result<BTreeSet<RuleHandle>, RollbackFailure> {
        let Some(tag) = self.journal.pending_tag() else {
            return Ok(BTreeSet::new());
        };
        let snapshot = store
            .snapshot()
            .map_err(|failure| RollbackFailure::Store { failure })?;
        let found = survey(&self.journal, &snapshot, Some(tag))
            .map_err(|handle| RollbackFailure::OwnedRuleAltered { handle })?;
        let target: BTreeSet<ScopedRule> = self.journal.owned().values().copied().collect();
        for step in ordered_steps(&found.owned, &target) {
            apply(&step, tag, grant, store)
                .map_err(|failure| RollbackFailure::Store { failure })?;
        }
        let checks = Checks {
            baseline: None,
            identity: None,
            refuse_unclaimed: false,
        };
        let verified = verify(store, &self.journal, tag, &target, checks)
            .map_err(|failure| RollbackFailure::Verification { failure })?;
        let mut next = self.journal.clone();
        next.settle(verified.owned);
        self.persist(next, sink)
            .map_err(|_| RollbackFailure::Journal)?;
        Ok(found.unclaimed)
    }

    /// Persists `next` and adopts it only once durable.
    fn persist<J: JournalStore>(
        &mut self,
        next: InstallJournal,
        sink: &mut J,
    ) -> Result<(), JournalFailure> {
        sink.persist(&next)?;
        self.journal = next;
        Ok(())
    }
}
