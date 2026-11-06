//! The perimeter installer adapter: every class of installer outcome, fed through V14's
//! assessment and responder (VM part §4.4; VM-W15; VM-W43).

use std::collections::BTreeSet;

use super::fixtures::*;
use super::*;
use crate::foundation::coordination::PerimeterId;
use crate::foundation::ids::{digest, Digest, ManualClock};
use crate::sandbox_contract::destinations::{
    DestinationPort, IpPrefix, PerimeterOptions, PerimeterPlatform, PerimeterProfile,
    PerimeterRule, PortSelector, RuleAction,
};
use crate::sandbox_contract::perimeter_install::{
    AbortCause, BrokerIdentity, ElevationGrant, IdentityKind, InstallError, InstallJournal,
    InstallRefusal, Installer, JournalFailure, JournalStore, OwnedRule, RecoveryReport,
    RollbackFailure, RuleBody, RuleHandle, RuleScope, RuleStore, ScopedRule, StoreEntry,
    StoreFailure, StoreSnapshot, TransactionId, VerificationFailure,
};
use crate::sandbox_contract::response::{
    Conflict, DecisionReason, Freshness, HostObserver, Reading, SignalClass, SignalSource,
    ViolationKind,
};

fn id(seed: &str) -> Digest {
    digest("yougori/test/perimeter/v1", &[seed.as_bytes()])
}

fn perimeter() -> PerimeterId {
    PerimeterId::new(id("perimeter-exe-a"))
}

fn broker() -> BrokerIdentity {
    BrokerIdentity {
        kind: IdentityKind::ServiceSid,
        identity: id("broker"),
    }
}

fn allow(address: &str, length: u8) -> PerimeterRule {
    PerimeterRule {
        action: RuleAction::Allow,
        prefix: IpPrefix::new(address.parse().unwrap(), length).unwrap(),
        ports: PortSelector::Only(DestinationPort::HTTPS),
    }
}

fn rules() -> Vec<PerimeterRule> {
    vec![allow("203.0.113.0", 24), allow("198.51.100.7", 32)]
}

fn profile() -> PerimeterProfile {
    let platform = PerimeterPlatform::Windows;
    let options = PerimeterOptions::default();
    PerimeterProfile::declare(
        platform,
        options,
        platform.required_properties(options),
        None,
        broker().identity,
        rules(),
    )
    .unwrap()
}

fn scoped() -> ScopedRule {
    ScopedRule {
        identity: broker().identity,
        rule: rules()[0],
    }
}

fn handle() -> RuleHandle {
    RuleHandle::new(7)
}

fn context(now: &ManualClock) -> PerimeterContext {
    PerimeterContext {
        observed: observed("exe-a", now),
        perimeter: perimeter(),
    }
}

/// A rule store in memory that isolates the broker; a lossy one reports a handle for an
/// add and keeps nothing, so the read-back misses the rule.
struct Store {
    state: StoreSnapshot,
    next: u64,
    lossy: bool,
}

impl Store {
    fn new(lossy: bool) -> Self {
        let mut state = StoreSnapshot::default();
        state.isolated.insert(broker().identity);
        Self {
            state,
            next: 100,
            lossy,
        }
    }
}

impl RuleStore for Store {
    fn snapshot(&self) -> Result<StoreSnapshot, StoreFailure> {
        Ok(self.state.clone())
    }

    fn add(
        &mut self,
        grant: &ElevationGrant,
        rule: &OwnedRule,
    ) -> Result<RuleHandle, StoreFailure> {
        if !grant.permits_add(rule) {
            return Err(StoreFailure::NotGranted);
        }
        self.next += 1;
        let handle = RuleHandle::new(self.next);
        if !self.lossy {
            self.state.entries.insert(
                handle,
                StoreEntry {
                    tag: Some(rule.tag),
                    scope: RuleScope::Identity {
                        identity: rule.scoped.identity,
                    },
                    body: RuleBody::Perimeter {
                        rule: rule.scoped.rule,
                    },
                },
            );
        }
        Ok(handle)
    }

    fn remove(&mut self, grant: &ElevationGrant, handle: RuleHandle) -> Result<(), StoreFailure> {
        let entry = *self
            .state
            .entries
            .get(&handle)
            .ok_or(StoreFailure::UnknownHandle { handle })?;
        if !grant.permits_remove(handle, &entry) {
            return Err(StoreFailure::NotGranted);
        }
        self.state.entries.remove(&handle);
        Ok(())
    }
}

struct Journal;

impl JournalStore for Journal {
    fn persist(&mut self, _journal: &InstallJournal) -> Result<(), JournalFailure> {
        Ok(())
    }
}

/// One install on `store`, returning exactly what V16's `Installer::execute` returns.
#[allow(clippy::result_large_err)]
fn install(
    store: &mut Store,
) -> Result<crate::sandbox_contract::perimeter_install::InstallReceipt, InstallError> {
    let mut installer = Installer::new(perimeter());
    let prepared = installer.prepare(store, &profile(), broker()).unwrap();
    let grant = prepared.grant_request();
    installer.execute(&prepared, &grant, store, &mut Journal)
}

/// Every read-back mismatch that says the perimeter does not hold what it installed.
fn mismatches() -> Vec<VerificationFailure> {
    vec![
        VerificationFailure::Missing { scoped: scoped() },
        VerificationFailure::Unexpected { handle: handle() },
        VerificationFailure::Duplicate { scoped: scoped() },
        VerificationFailure::ForeignRuleOnBroker { handle: handle() },
        VerificationFailure::ScopeNotIsolated,
        VerificationFailure::OwnedRuleAltered { handle: handle() },
    ]
}

/// The read-back findings that are host anomalies, with the anomaly each is.
fn anomalies() -> Vec<(VerificationFailure, HostAnomaly)> {
    vec![
        (
            VerificationFailure::ForeignRuleChanged { handle: handle() },
            HostAnomaly::ForeignRuleChanged,
        ),
        (
            VerificationFailure::UnclaimedTaggedRule { handle: handle() },
            HostAnomaly::UnclaimedTaggedRule,
        ),
    ]
}

fn unreadable() -> VerificationFailure {
    VerificationFailure::Unreadable {
        failure: StoreFailure::Unavailable,
    }
}

/// The ways a failed install can carry a read-back finding: the read-back after the steps,
/// the rollback's read-back after a store failure, and the read-back that made a rollback
/// necessary when the rollback then failed.
fn carrying(failure: VerificationFailure) -> [InstallError; 3] {
    [
        InstallError::RolledBack {
            cause: AbortCause::Verification { failure },
        },
        InstallError::RollbackIncomplete {
            cause: AbortCause::Store {
                failure: StoreFailure::Rejected,
            },
            rollback: RollbackFailure::Verification { failure },
        },
        InstallError::RollbackIncomplete {
            cause: AbortCause::Verification { failure },
            rollback: RollbackFailure::Journal,
        },
    ]
}

#[test]
fn a_read_back_that_misses_a_rule_is_a_perimeter_violation_that_isolates() {
    let now = clock();
    let mut store = Store::new(true);
    let outcome = install(&mut store);
    let error = outcome.as_ref().unwrap_err();
    assert!(
        matches!(
            error,
            InstallError::RolledBack {
                cause: AbortCause::Verification {
                    failure: VerificationFailure::Missing { .. }
                }
            }
        ),
        "{error:?}"
    );
    let classified = install_signal(&outcome, &context(&now));
    assert!(matches!(
        classified.cause(),
        Some(PerimeterViolation::ReadBack {
            failure: VerificationFailure::Missing { .. }
        })
    ));
    let draft = classified.into_draft().unwrap();
    assert_eq!(draft.sandbox, execution("exe-a"));
    assert_eq!(
        draft.class,
        SignalClass::Violation {
            kind: ViolationKind::PerimeterRule
        }
    );
    assert_eq!(
        draft.source,
        SignalSource::HostObserved {
            observer: HostObserver::Perimeter
        }
    );
    assert_eq!(draft.subject, perimeter().digest());
    assert_eq!(draft.violated_grant, None);
    let record = respond_alone(draft, &now);
    assert_eq!(record.decision.actions, violation_actions(true));
    assert_eq!(
        record.decision.reason,
        DecisionReason::KnownViolation {
            kind: ViolationKind::PerimeterRule,
            observer: HostObserver::Perimeter,
            meaning: None
        }
    );
}

#[test]
fn every_read_back_mismatch_is_a_violation_and_an_unreadable_store_is_not() {
    let now = clock();
    let context = context(&now);
    for failure in mismatches() {
        let expected = PerimeterViolation::ReadBack { failure };
        for error in carrying(failure) {
            let classified = install_signal(&Err(error), &context);
            assert_eq!(classified.cause(), Some(&expected), "{error:?}");
            let record = respond_alone(classified.into_draft().unwrap(), &now);
            assert_eq!(record.decision.actions, violation_actions(true));
        }
    }
    // A rollback whose own survey found a recorded rule altered.
    let altered = InstallError::RollbackIncomplete {
        cause: AbortCause::Interrupted,
        rollback: RollbackFailure::OwnedRuleAltered { handle: handle() },
    };
    assert_eq!(
        install_signal(&Err(altered), &context).cause(),
        Some(&PerimeterViolation::ReadBack {
            failure: VerificationFailure::OwnedRuleAltered { handle: handle() }
        })
    );
    // An unreadable store is no reading at all.
    for error in carrying(unreadable()) {
        assert_eq!(
            install_signal(&Err(error), &context),
            Classification::Ordinary {
                reason: Ordinary::HostFault
            }
        );
    }
}

#[test]
fn a_foreign_rule_changed_or_an_unclaimed_tagged_rule_is_a_host_anomaly() {
    let now = clock();
    let context = context(&now);
    for (failure, anomaly) in anomalies() {
        for error in carrying(failure) {
            let classified = install_signal(&Err(error), &context);
            assert!(!classified.is_violation(), "{error:?}");
            assert!(classified.draft().is_none());
            let notice = classified.anomaly().unwrap();
            assert_eq!(notice.anomaly, anomaly);
            assert_eq!(notice.sandbox, execution("exe-a"));
            assert_eq!(notice.observer, HostObserver::Perimeter);
            assert_eq!(notice.subject, perimeter().digest());
            assert_eq!(notice.actions(), uncertain_actions());
        }
    }
    // A mismatch found with an anomaly is still a violation, whichever came first.
    let both = InstallError::RollbackIncomplete {
        cause: AbortCause::Verification {
            failure: VerificationFailure::ForeignRuleChanged { handle: handle() },
        },
        rollback: RollbackFailure::Verification {
            failure: VerificationFailure::ScopeNotIsolated,
        },
    };
    assert_eq!(
        install_signal(&Err(both), &context).cause(),
        Some(&PerimeterViolation::ReadBack {
            failure: VerificationFailure::ScopeNotIsolated
        })
    );
    // An anomaly found where the rest failed outright stays an anomaly.
    let faulted = InstallError::RollbackIncomplete {
        cause: AbortCause::Interrupted,
        rollback: RollbackFailure::Verification {
            failure: VerificationFailure::UnclaimedTaggedRule { handle: handle() },
        },
    };
    assert_eq!(
        install_signal(&Err(faulted), &context)
            .anomaly()
            .map(|notice| notice.anomaly),
        Some(HostAnomaly::UnclaimedTaggedRule)
    );
}

#[test]
fn survey_findings_are_violations_or_anomalies_and_configuration_refusals_are_neither() {
    let now = clock();
    let context = context(&now);
    for refusal in [
        InstallRefusal::ScopeNotIsolated,
        InstallRefusal::ForeignRuleOnBroker { handle: handle() },
        InstallRefusal::OwnedRuleAltered { handle: handle() },
    ] {
        let expected = PerimeterViolation::Survey { refusal };
        assert_eq!(
            install_refusal_signal(&refusal, &context).cause(),
            Some(&expected)
        );
        let refused = install_signal(&Err(InstallError::Refused { refusal }), &context);
        assert_eq!(refused.cause(), Some(&expected));
        let record = respond_alone(refused.into_draft().unwrap(), &now);
        assert_eq!(record.decision.actions, violation_actions(true));
    }
    let unclaimed = InstallRefusal::UnclaimedTaggedRule { handle: handle() };
    assert_eq!(
        install_refusal_signal(&unclaimed, &context)
            .anomaly()
            .map(|notice| notice.anomaly),
        Some(HostAnomaly::UnclaimedTaggedRule)
    );
    for (refusal, reason) in [
        (InstallRefusal::RemotePerimeter, Ordinary::HostConfiguration),
        (
            InstallRefusal::IdentityKindRefused {
                kind: IdentityKind::ServiceSid,
            },
            Ordinary::HostConfiguration,
        ),
        (
            InstallRefusal::IdentityKindNotOnPlatform {
                kind: IdentityKind::ServiceSid,
                platform: PerimeterPlatform::Linux,
            },
            Ordinary::HostConfiguration,
        ),
        (
            InstallRefusal::IdentityMismatch {
                profile: id("profile"),
                broker: id("broker"),
            },
            Ordinary::HostConfiguration,
        ),
        (
            InstallRefusal::PendingTransaction {
                transaction: TransactionId::FIRST,
            },
            Ordinary::HostConfiguration,
        ),
        (
            InstallRefusal::TransactionsExhausted,
            Ordinary::HostConfiguration,
        ),
        (
            InstallRefusal::Store {
                failure: StoreFailure::Unavailable,
            },
            Ordinary::HostFault,
        ),
    ] {
        assert_eq!(
            install_refusal_signal(&refusal, &context),
            Classification::Ordinary { reason },
            "{refusal:?}"
        );
        assert_eq!(
            install_signal(&Err(InstallError::Refused { refusal }), &context).ordinary(),
            Some(reason)
        );
    }
    // A real install the profile's broker identity does not match is refused before
    // anything is written, and is no violation.
    let store = Store::new(false);
    let other = BrokerIdentity {
        kind: IdentityKind::ServiceSid,
        identity: id("someone-else"),
    };
    let refusal = Installer::new(perimeter())
        .prepare(&store, &profile(), other)
        .unwrap_err();
    assert_eq!(
        install_refusal_signal(&refusal, &context).ordinary(),
        Some(Ordinary::HostConfiguration)
    );
}

#[test]
fn installer_failures_without_a_finding_are_ordinary() {
    let now = clock();
    let context = context(&now);
    for (error, reason) in [
        (InstallError::GrantMismatch, Ordinary::HostConfiguration),
        (InstallError::StalePlan, Ordinary::NotCurrent),
        (InstallError::Journal { pending: None }, Ordinary::HostFault),
        (
            InstallError::Journal {
                pending: Some(TransactionId::FIRST),
            },
            Ordinary::HostFault,
        ),
        (
            InstallError::RolledBack {
                cause: AbortCause::Store {
                    failure: StoreFailure::Rejected,
                },
            },
            Ordinary::HostFault,
        ),
        (
            InstallError::RollbackIncomplete {
                cause: AbortCause::Store {
                    failure: StoreFailure::Unavailable,
                },
                rollback: RollbackFailure::Store {
                    failure: StoreFailure::Unavailable,
                },
            },
            Ordinary::HostFault,
        ),
        (
            InstallError::RollbackIncomplete {
                cause: AbortCause::Interrupted,
                rollback: RollbackFailure::Journal,
            },
            Ordinary::HostFault,
        ),
    ] {
        assert_eq!(
            install_signal(&Err(error), &context),
            Classification::Ordinary { reason },
            "{error:?}"
        );
    }
}

#[test]
fn an_earlier_passed_check_never_masks_a_later_mismatch() {
    let now = clock();
    let receipt = install(&mut Store::new(false));
    let passed = install_signal(&receipt, &context(&now));
    let Classification::CheckPassed { draft: check } = passed else {
        panic!("expected a passed check, got {passed:?}");
    };
    assert_eq!(check.reading, Reading::CheckPassed);
    now.advance(5 * SECOND);
    let mismatch = install_signal(
        &Err(InstallError::RolledBack {
            cause: AbortCause::Verification {
                failure: VerificationFailure::ScopeNotIsolated,
            },
        }),
        &context(&now),
    );
    assert!(mismatch.is_violation());
    let mismatch = mismatch.into_draft().unwrap();

    // In arrival order: the mismatch supersedes the earlier check.
    let mut collector = SignalCollector::new(CollectorBounds::new(8, 4, 4).unwrap());
    assert_eq!(collector.collect(check.clone()), Ok(Collected::Kept));
    assert_eq!(collector.collect(mismatch.clone()), Ok(Collected::Kept));
    assert_eq!(collector.totals().superseded, 1);
    let batch = collector.take(&execution("exe-a")).unwrap();
    let incidents = batch.incidents();
    assert_eq!(incidents.len(), 1);
    assert_eq!(incidents[0].1.len(), 1);
    let assessment = assess(&incidents[0].1, &now);
    assert!(assessment.freshness().is_fresh());
    let mut responder = responder_with(
        &now,
        &[(
            "exe-a",
            crate::sandbox_contract::files::SandboxClass::Task,
            &[],
        )],
    );
    let record = responded(responder.respond_to(&assessment).unwrap());
    assert_eq!(record.decision.actions, violation_actions(true));

    // Arriving late, the earlier check is dropped as superseded.
    assert_eq!(collector.collect(mismatch), Ok(Collected::Kept));
    assert_eq!(collector.collect(check), Ok(Collected::Superseded));
    assert_eq!(collector.totals().superseded, 2);
    assert_eq!(collector.pending(&execution("exe-a")), 1);
}

#[test]
fn a_later_passed_check_contradicts_an_earlier_mismatch_and_never_clears_it() {
    let now = clock();
    let mismatch = install_signal(&install(&mut Store::new(true)), &context(&now))
        .into_draft()
        .unwrap();
    now.advance(5 * SECOND);
    let receipt = install(&mut Store::new(false));
    assert!(receipt.is_ok(), "{receipt:?}");
    let passed = install_signal(&receipt, &context(&now));
    let Classification::CheckPassed { draft } = &passed else {
        panic!("expected a passed check, got {passed:?}");
    };
    assert_eq!(draft.subject, mismatch.subject);
    assert_eq!(draft.violated_grant, None);
    let mut collector = SignalCollector::new(CollectorBounds::new(8, 4, 4).unwrap());
    collector.collect(mismatch).unwrap();
    assert_eq!(collector.collect(draft.clone()), Ok(Collected::Kept));
    let batch = collector.take(&execution("exe-a")).unwrap();
    let incidents = batch.incidents();
    let assessment = assess(&incidents[0].1, &now);
    assert_eq!(
        assessment.freshness(),
        Freshness::Conflicting {
            conflict: Conflict {
                reported_by: HostObserver::Perimeter,
                contradicted_by: HostObserver::Perimeter
            }
        }
    );
    let mut responder = responder_with(
        &now,
        &[(
            "exe-a",
            crate::sandbox_contract::files::SandboxClass::Task,
            &[],
        )],
    );
    let record = responded(responder.respond_to(&assessment).unwrap());
    assert_eq!(record.decision.actions, uncertain_actions());

    // A receipt for another perimeter than the context names is a host mistake.
    let mut elsewhere = context(&now);
    elsewhere.perimeter = PerimeterId::new(id("perimeter-exe-b"));
    assert_eq!(
        install_signal(&receipt, &elsewhere).ordinary(),
        Some(Ordinary::HostConfiguration)
    );
}

#[test]
fn recovery_outcomes_are_classified_and_a_clean_recovery_is_no_passed_check() {
    let now = clock();
    let context = context(&now);
    for report in [
        RecoveryReport::NothingPending,
        RecoveryReport::RolledBack {
            transaction: TransactionId::FIRST,
            untouched: BTreeSet::new(),
        },
    ] {
        assert_eq!(
            recovery_signal(&Ok(report), &context),
            Classification::Ordinary {
                reason: Ordinary::NothingObserved
            }
        );
    }
    let left = RecoveryReport::RolledBack {
        transaction: TransactionId::FIRST,
        untouched: BTreeSet::from([handle(), RuleHandle::new(8)]),
    };
    let classified = recovery_signal(&Ok(left), &context);
    assert!(classified.draft().is_none());
    let notice = classified.anomaly().unwrap();
    assert_eq!(
        notice.anomaly,
        HostAnomaly::UnclaimedAfterRecovery { rules: 2 }
    );
    assert_eq!(notice.actions(), uncertain_actions());

    let failed = Err(InstallError::RollbackIncomplete {
        cause: AbortCause::Interrupted,
        rollback: RollbackFailure::Verification {
            failure: VerificationFailure::Missing { scoped: scoped() },
        },
    });
    assert!(recovery_signal(&failed, &context).is_violation());
    assert_eq!(
        recovery_signal(&Err(InstallError::GrantMismatch), &context).ordinary(),
        Some(Ordinary::HostConfiguration)
    );
}
