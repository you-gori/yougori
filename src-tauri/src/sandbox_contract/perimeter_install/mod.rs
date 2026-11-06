//! Installing the independent perimeter transactionally (VM-W15, the pure half: "Transactional
//! platform perimeter with stable process identity, explicit private-endpoint grants and
//! controlled empirical tests"; acceptance "Positive control proves endpoint reachability;
//! intended kernel rule blocks the actual broker identity; no unrelated PC rule changes";
//! VM §4.4: "Install/update rules transactionally, verify their scope, preserve unrelated
//! rules, and provide a rollback. Use elevation only for the concrete operations that
//! require it during implementation"; VM-R33; VM-D3).
//!
//! V02 (`destinations::perimeter`) declares what the perimeter must provide and judges
//! enforcement from CORE-01 must-probe evidence; V11 (`netprofile`) compiles a network
//! profile into V02 rules, including the dedicated enforcement context of a private
//! endpoint grant. This module puts those rules into a host [`RuleStore`]:
//!
//! - [`BrokerIdentity`]: the rules are scoped to one stable identity of the broker, of a
//!   kind the platform offers (never a user account or a process ID), equal to the V02
//!   profile's broker identity, and the store must isolate that identity so no other rule
//!   permits its traffic.
//! - [`InstallPlan`]: the steps from the rules the perimeter owns to the target, ordered so
//!   that no step permits more than the old rules or the new ones.
//! - [`ElevationGrant`]: what one elevation lets the elevated side do: this plan's adds
//!   under its tag and removals of the perimeter's own rules, nothing else.
//! - [`Installer`]: preflight, a write-ahead [`InstallJournal`], the steps, a read-back
//!   that checks the perimeter's rules, their scope and every unrelated rule, and a
//!   rollback in the same fail-closed order on any failure; recovery after a stop part way.
//!
//! Tier 0: everything here runs on the in-memory fake store in the tests. No platform
//! adapter exists yet, nothing here touches a real firewall, and no receipt is evidence
//! that the kernel enforces a rule: that remains CORE-01 `PerimeterRuleEnforced` from a
//! must-probe with a positive control on the actual broker identity (V02 `MustProbe`).

pub mod installer;
pub mod journal;
pub mod plan;
pub mod store;

#[cfg(test)]
mod fakes;
#[cfg(test)]
mod tests;

pub use installer::{
    AbortCause, InstallError, InstallReceipt, InstallRefusal, Installer, PreparedInstall,
    RecoveryReport, RollbackFailure, VerificationFailure,
};
pub use journal::{
    CompletedStep, InstallJournal, JournalError, JournalFailure, JournalStore, PendingInstall,
};
pub use plan::{BrokerIdentity, ElevationGrant, IdentityKind, InstallPlan, PlanStep, PLAN_DOMAIN};
pub use store::{
    OwnedRule, OwnerTag, RuleBody, RuleHandle, RuleScope, RuleStore, ScopedRule, StoreEntry,
    StoreFailure, StoreSnapshot, TransactionId,
};
