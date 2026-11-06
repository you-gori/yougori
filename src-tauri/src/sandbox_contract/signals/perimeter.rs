//! The perimeter installer's outcomes as signals (V16
//! [`Installer`](crate::sandbox_contract::perimeter_install::Installer); VM part §4.4 "The
//! independent perimeter": "verify their scope, preserve unrelated rules"; VM-W15).
//!
//! A survey or read-back that finds the perimeter not holding what it installed is a
//! violation: a target rule missing, an unexpected or duplicated rule of the perimeter's
//! own, a foreign rule on the broker's identity, the identity no longer isolated, or a
//! recorded rule altered, found in the survey before planning, in the read-back after the
//! steps or in the read-back after a rollback. Each says traffic may pass outside the
//! declared rules: [`ViolationKind::PerimeterRule`] by the [`HostObserver::Perimeter`],
//! about the sandbox the perimeter belongs to, with the perimeter as the subject and no
//! grant (the perimeter enforces the sandbox's grants; it is not one).
//!
//! Three findings are host anomalies instead, V14's uncertain result and never a sandbox
//! violation: a rule outside the perimeter changed while the installer worked
//! ([`HostAnomaly::ForeignRuleChanged`](super::HostAnomaly)), a rule under the perimeter's
//! tag that no transaction recorded ([`HostAnomaly::UnclaimedTaggedRule`](super::HostAnomaly)),
//! and such rules that a recovery left alone after its verified rollback
//! ([`HostAnomaly::UnclaimedAfterRecovery`](super::HostAnomaly)).
//!
//! A committed install whose read-back checked everything (the perimeter's rules, every
//! unrelated rule, the broker's isolation) is a host check that passed. A later mismatch
//! supersedes it in the collector, so it never masks one. Every other outcome is ordinary:
//! a configuration the installer refuses (a remote perimeter, an identity kind or broker the
//! platform or profile does not take), a stale plan or a mismatched elevation grant, a
//! pending or exhausted transaction, an unavailable store, an unreadable read-back or an
//! unwritable journal.

use crate::foundation::coordination::PerimeterId;
use crate::sandbox_contract::perimeter_install::{
    AbortCause, InstallError, InstallReceipt, InstallRefusal, RecoveryReport, RollbackFailure,
    VerificationFailure,
};
use crate::sandbox_contract::response::{HostObserver, ViolationKind};

use super::observed::{Classification, Finding, HostAnomaly, Observed, Ordinary};

/// The observer every perimeter signal and notice names.
pub const PERIMETER_OBSERVER: HostObserver = HostObserver::Perimeter;
/// The kind every perimeter violation is filed under.
pub const PERIMETER_VIOLATION_KIND: ViolationKind = ViolationKind::PerimeterRule;

/// What made an installer outcome a violation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PerimeterViolation {
    /// A read-back after the steps or after a rollback found this.
    ReadBack { failure: VerificationFailure },
    /// The survey before planning found this.
    Survey { refusal: InstallRefusal },
}

/// The installer run an outcome came from, as the host knows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PerimeterContext {
    /// The sandbox the perimeter belongs to, and when the outcome was read on the shared
    /// host clock.
    pub observed: Observed,
    /// The perimeter the installer installs.
    pub perimeter: PerimeterId,
}

impl PerimeterContext {
    fn classified(
        &self,
        finding: Finding<PerimeterViolation>,
    ) -> Classification<PerimeterViolation> {
        match finding {
            Finding::Violation(cause) => Classification::Violation {
                cause,
                draft: self.observed.violation(
                    PERIMETER_VIOLATION_KIND,
                    PERIMETER_OBSERVER,
                    self.perimeter.digest(),
                    None,
                ),
            },
            Finding::Anomaly(anomaly) => Classification::HostAnomaly {
                notice: self
                    .observed
                    .anomaly(anomaly, PERIMETER_OBSERVER, self.perimeter.digest()),
            },
            Finding::Ordinary(reason) => Classification::Ordinary { reason },
        }
    }
}

fn verification(failure: &VerificationFailure) -> Finding<PerimeterViolation> {
    match failure {
        VerificationFailure::Unreadable { .. } => Finding::Ordinary(Ordinary::HostFault),
        VerificationFailure::ForeignRuleChanged { .. } => {
            Finding::Anomaly(HostAnomaly::ForeignRuleChanged)
        }
        VerificationFailure::UnclaimedTaggedRule { .. } => {
            Finding::Anomaly(HostAnomaly::UnclaimedTaggedRule)
        }
        VerificationFailure::Missing { .. }
        | VerificationFailure::Unexpected { .. }
        | VerificationFailure::Duplicate { .. }
        | VerificationFailure::ForeignRuleOnBroker { .. }
        | VerificationFailure::ScopeNotIsolated
        | VerificationFailure::OwnedRuleAltered { .. } => {
            Finding::Violation(PerimeterViolation::ReadBack { failure: *failure })
        }
    }
}

fn refusal(refusal: &InstallRefusal) -> Finding<PerimeterViolation> {
    match refusal {
        InstallRefusal::ScopeNotIsolated
        | InstallRefusal::ForeignRuleOnBroker { .. }
        | InstallRefusal::OwnedRuleAltered { .. } => {
            Finding::Violation(PerimeterViolation::Survey { refusal: *refusal })
        }
        InstallRefusal::UnclaimedTaggedRule { .. } => {
            Finding::Anomaly(HostAnomaly::UnclaimedTaggedRule)
        }
        InstallRefusal::RemotePerimeter
        | InstallRefusal::IdentityKindRefused { .. }
        | InstallRefusal::IdentityKindNotOnPlatform { .. }
        | InstallRefusal::IdentityMismatch { .. }
        | InstallRefusal::PendingTransaction { .. }
        | InstallRefusal::TransactionsExhausted => Finding::Ordinary(Ordinary::HostConfiguration),
        InstallRefusal::Store { .. } => Finding::Ordinary(Ordinary::HostFault),
    }
}

fn cause(cause: &AbortCause) -> Finding<PerimeterViolation> {
    match cause {
        AbortCause::Verification { failure } => verification(failure),
        AbortCause::Store { .. } | AbortCause::Interrupted => {
            Finding::Ordinary(Ordinary::HostFault)
        }
    }
}

fn rollback(rollback: &RollbackFailure) -> Finding<PerimeterViolation> {
    match rollback {
        RollbackFailure::Verification { failure } => verification(failure),
        // The rollback's survey found a recorded rule altered: the read-back finding.
        RollbackFailure::OwnedRuleAltered { handle } => {
            Finding::Violation(PerimeterViolation::ReadBack {
                failure: VerificationFailure::OwnedRuleAltered { handle: *handle },
            })
        }
        RollbackFailure::Store { .. } | RollbackFailure::Journal => {
            Finding::Ordinary(Ordinary::HostFault)
        }
    }
}

/// A failed execute or recover: the stronger of what the failure and the rollback after it
/// found.
fn error(error: &InstallError) -> Finding<PerimeterViolation> {
    match error {
        InstallError::Refused { refusal: refused } => refusal(refused),
        InstallError::RolledBack { cause: aborted } => cause(aborted),
        InstallError::RollbackIncomplete {
            cause: aborted,
            rollback: failed,
        } => cause(aborted).or(rollback(failed)),
        InstallError::GrantMismatch => Finding::Ordinary(Ordinary::HostConfiguration),
        InstallError::StalePlan => Finding::Ordinary(Ordinary::NotCurrent),
        InstallError::Journal { .. } => Finding::Ordinary(Ordinary::HostFault),
    }
}

/// The signal of a refused [`Installer::prepare`] (pure).
///
/// [`Installer::prepare`]: crate::sandbox_contract::perimeter_install::Installer::prepare
pub fn install_refusal_signal(
    refused: &InstallRefusal,
    context: &PerimeterContext,
) -> Classification<PerimeterViolation> {
    context.classified(refusal(refused))
}

/// The signal of one [`Installer::execute`] outcome (pure): a committed install is a
/// passed check of the perimeter, a mismatch a violation, a host anomaly a notice,
/// anything else ordinary. A receipt for another perimeter than the context's is a host
/// call that names the wrong one.
///
/// [`Installer::execute`]: crate::sandbox_contract::perimeter_install::Installer::execute
pub fn install_signal(
    outcome: &Result<InstallReceipt, InstallError>,
    context: &PerimeterContext,
) -> Classification<PerimeterViolation> {
    match outcome {
        Ok(receipt) if receipt.tag.perimeter == context.perimeter => Classification::CheckPassed {
            draft: context.observed.check_passed(
                PERIMETER_VIOLATION_KIND,
                PERIMETER_OBSERVER,
                context.perimeter.digest(),
            ),
        },
        Ok(_) => Classification::Ordinary {
            reason: Ordinary::HostConfiguration,
        },
        Err(failed) => context.classified(error(failed)),
    }
}

/// The signal of one [`Installer::recover`] outcome (pure). A rollback's read-back checks
/// only the perimeter's own rules, not the broker's isolation or unrelated rules, so a
/// clean recovery is no passed check; rules it left under the perimeter's tag are a host
/// anomaly.
///
/// [`Installer::recover`]: crate::sandbox_contract::perimeter_install::Installer::recover
pub fn recovery_signal(
    outcome: &Result<RecoveryReport, InstallError>,
    context: &PerimeterContext,
) -> Classification<PerimeterViolation> {
    match outcome {
        Ok(RecoveryReport::RolledBack { untouched, .. }) if !untouched.is_empty() => context
            .classified(Finding::Anomaly(HostAnomaly::UnclaimedAfterRecovery {
                rules: untouched.len(),
            })),
        Ok(RecoveryReport::RolledBack { .. } | RecoveryReport::NothingPending) => {
            Classification::Ordinary {
                reason: Ordinary::NothingObserved,
            }
        }
        Err(failed) => context.classified(error(failed)),
    }
}
