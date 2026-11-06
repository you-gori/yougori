//! Rollback on store and verification failures, a failed rollback, journal failures and
//! recovery after a stop part way.

use super::super::fakes::{FakeJournal, FakeRuleStore, ForeignChange};
use super::*;

fn installed_old() -> (Installer, FakeRuleStore, FakeJournal) {
    let mut installer = Installer::new(perimeter());
    let mut store = store();
    let mut journal = FakeJournal::default();
    install(&mut installer, &mut store, &mut journal, old_rules()).unwrap();
    (installer, store, journal)
}

/// The installer's journal agrees with the store about which rules are the perimeter's.
fn journal_matches_store(installer: &Installer, store: &FakeRuleStore) {
    let recorded: BTreeSet<(RuleHandle, ScopedRule)> = installer
        .journal()
        .owned()
        .iter()
        .map(|(handle, rule)| (*handle, *rule))
        .collect();
    let present: BTreeSet<(RuleHandle, ScopedRule)> = handles(store)
        .into_iter()
        .map(|(rule, handle)| (handle, rule))
        .collect();
    assert_eq!(recorded, present);
}

#[test]
fn a_store_failure_part_way_restores_the_prior_rules() {
    let (mut installer, mut store, mut journal) = installed_old();
    let before = foreign(&store);
    let attempts = store.write_attempts();
    // The third step of the update (adding the new allow) fails.
    store.fail.insert(attempts + 2, StoreFailure::Rejected);
    let error = install(&mut installer, &mut store, &mut journal, new_rules()).unwrap_err();
    assert_eq!(
        error,
        InstallError::RolledBack {
            cause: AbortCause::Store {
                failure: StoreFailure::Rejected
            }
        }
    );
    assert_eq!(tagged_set(&store), scoped(&old_rules()));
    assert_eq!(tagged(&store).len(), 4);
    assert_eq!(foreign(&store), before);
    assert!(installer.settled());
    journal_matches_store(&installer, &store);
    assert_eq!(journal.last(), Some(installer.journal()));
    // The transaction number is spent; the next install uses a new one.
    let receipt = install(&mut installer, &mut store, &mut journal, new_rules()).unwrap();
    assert_eq!(receipt.tag.transaction, TransactionId::new(3));
}

#[test]
fn a_store_that_loses_rules_fails_verification_and_rolls_back() {
    let mut installer = Installer::new(perimeter());
    let mut store = store();
    let mut journal = FakeJournal::default();
    store.lossy = true;
    let error = install(&mut installer, &mut store, &mut journal, old_rules()).unwrap_err();
    let InstallError::RolledBack {
        cause:
            AbortCause::Verification {
                failure: VerificationFailure::Missing { .. },
            },
    } = error
    else {
        panic!("unexpected {error:?}");
    };
    assert!(tagged(&store).is_empty());
    assert!(installer.settled());
}

#[test]
fn an_unrelated_rule_that_changes_during_the_install_fails_it() {
    let (mut installer, mut store, mut journal) = installed_old();
    let (vpn, entry) = foreign(&store)[0];
    let attempts = store.write_attempts();
    store
        .after
        .insert(attempts, vec![ForeignChange::Remove(vpn)]);
    let error = install(&mut installer, &mut store, &mut journal, new_rules()).unwrap_err();
    assert_eq!(
        error,
        InstallError::RolledBack {
            cause: AbortCause::Verification {
                failure: VerificationFailure::ForeignRuleChanged { handle: vpn }
            }
        }
    );
    assert_eq!(tagged_set(&store), scoped(&old_rules()));

    // A changed body counts the same as a removal.
    let (mut installer, mut store, mut journal) = installed_old();
    let mut changed = entry;
    changed.body = RuleBody::Opaque {
        digest: id("edited"),
    };
    let (vpn, _) = foreign(&store)[0];
    let attempts = store.write_attempts();
    store
        .after
        .insert(attempts, vec![ForeignChange::Replace(vpn, changed)]);
    let error = install(&mut installer, &mut store, &mut journal, new_rules()).unwrap_err();
    assert_eq!(
        error,
        InstallError::RolledBack {
            cause: AbortCause::Verification {
                failure: VerificationFailure::ForeignRuleChanged { handle: vpn }
            }
        }
    );
}

#[test]
fn a_rule_on_the_broker_or_a_lost_isolation_during_the_install_fails_it() {
    let (mut installer, mut store, mut journal) = installed_old();
    let attempts = store.write_attempts();
    store.after.insert(
        attempts,
        vec![ForeignChange::Insert(StoreEntry {
            tag: None,
            scope: RuleScope::Identity {
                identity: broker().identity,
            },
            body: RuleBody::Opaque {
                digest: id("allow all"),
            },
        })],
    );
    let error = install(&mut installer, &mut store, &mut journal, new_rules()).unwrap_err();
    assert!(matches!(
        error,
        InstallError::RolledBack {
            cause: AbortCause::Verification {
                failure: VerificationFailure::ForeignRuleOnBroker { .. }
            }
        }
    ));
    assert_eq!(tagged_set(&store), scoped(&old_rules()));

    let (mut installer, mut store, mut journal) = installed_old();
    let attempts = store.write_attempts();
    store
        .after
        .insert(attempts, vec![ForeignChange::Unisolate(broker().identity)]);
    let error = install(&mut installer, &mut store, &mut journal, new_rules()).unwrap_err();
    assert_eq!(
        error,
        InstallError::RolledBack {
            cause: AbortCause::Verification {
                failure: VerificationFailure::ScopeNotIsolated
            }
        }
    );
}

#[test]
fn a_failed_rollback_stays_pending_within_old_or_new_and_recovers_later() {
    let (mut installer, mut store, mut journal) = installed_old();
    let start = store.state.clone();
    let old = permitted(&start);
    let attempts = store.write_attempts();
    // The store goes down after the first step and stays down through the rollback.
    store.down_from = Some(attempts + 1);
    let error = install(&mut installer, &mut store, &mut journal, new_rules()).unwrap_err();
    assert_eq!(
        error,
        InstallError::RollbackIncomplete {
            cause: AbortCause::Store {
                failure: StoreFailure::Unavailable
            },
            rollback: RollbackFailure::Store {
                failure: StoreFailure::Unavailable
            },
        }
    );
    assert!(!installer.settled());
    // The stuck state is no wider than the old rules: only the new block went in.
    assert!(permitted(&store.state).is_subset(&old));
    assert_eq!(
        installer.prepare(&store, &profile(new_rules()), broker()),
        Err(InstallRefusal::PendingTransaction {
            transaction: TransactionId::new(2)
        })
    );

    store.down_from = None;
    let grant = installer.recovery_request().unwrap();
    let report = installer.recover(&grant, &mut store, &mut journal).unwrap();
    assert_eq!(
        report,
        RecoveryReport::RolledBack {
            transaction: TransactionId::new(2),
            untouched: BTreeSet::new(),
        }
    );
    assert_eq!(tagged_set(&store), scoped(&old_rules()));
    assert_eq!(tagged(&store).len(), 4);
    assert!(installer.settled());
    journal_matches_store(&installer, &store);
}

#[test]
fn a_rule_added_but_not_yet_recorded_is_claimed_by_recovery() {
    let (installer, mut store, mut journal) = installed_old();
    let mut installer = installer;
    // The journal accepts the transaction's start and then fails, so the first step's
    // rule is in the store but not in the journal: the window of a crash.
    journal.fail_from = Some(journal.calls() + 1);
    let error = install(&mut installer, &mut store, &mut journal, new_rules()).unwrap_err();
    assert_eq!(
        error,
        InstallError::Journal {
            pending: Some(TransactionId::new(2))
        }
    );
    let pending = installer.journal().pending().unwrap();
    assert!(pending.completed.is_empty());
    assert_eq!(installer.journal(), journal.last().unwrap());
    assert_eq!(tagged(&store).len(), 5);

    // A restart from the persisted journal.
    journal.fail_from = None;
    let mut restarted = Installer::restore(journal.last().unwrap().clone());
    let grant = restarted.recovery_request().unwrap();
    let report = restarted.recover(&grant, &mut store, &mut journal).unwrap();
    assert!(matches!(report, RecoveryReport::RolledBack { .. }));
    assert_eq!(tagged_set(&store), scoped(&old_rules()));
    assert_eq!(tagged(&store).len(), 4);
    journal_matches_store(&restarted, &store);
}

#[test]
fn a_journal_that_cannot_start_the_transaction_changes_nothing() {
    let (mut installer, mut store, mut journal) = installed_old();
    let attempts = store.write_attempts();
    let committed = installer.journal().clone();
    journal.fail_from = Some(journal.calls());
    let error = install(&mut installer, &mut store, &mut journal, new_rules()).unwrap_err();
    assert_eq!(error, InstallError::Journal { pending: None });
    assert_eq!(store.write_attempts(), attempts);
    assert_eq!(installer.journal(), &committed);
    assert!(installer.settled());
}

#[test]
fn a_transaction_whose_commit_was_not_recorded_is_rolled_back() {
    let (mut installer, mut store, mut journal) = installed_old();
    // Start, four steps, then the commit write fails.
    journal.fail_from = Some(journal.calls() + 5);
    let error = install(&mut installer, &mut store, &mut journal, new_rules()).unwrap_err();
    assert_eq!(
        error,
        InstallError::Journal {
            pending: Some(TransactionId::new(2))
        }
    );
    assert_eq!(tagged_set(&store), scoped(&new_rules()));
    assert_eq!(installer.journal().pending().unwrap().completed.len(), 4);

    journal.fail_from = None;
    let grant = installer.recovery_request().unwrap();
    installer.recover(&grant, &mut store, &mut journal).unwrap();
    assert_eq!(tagged_set(&store), scoped(&old_rules()));
    journal_matches_store(&installer, &store);
}

#[test]
fn recovery_needs_the_pending_transactions_grant_and_reports_stray_tags() {
    let (mut installer, mut store, mut journal) = installed_old();
    assert_eq!(installer.recovery_request(), None);
    let anything = ElevationGrant {
        tag: OwnerTag {
            perimeter: perimeter(),
            transaction: TransactionId::new(2),
        },
        plan: id("plan"),
        may_add: BTreeSet::new(),
        may_remove: BTreeSet::new(),
    };
    assert_eq!(
        installer.recover(&anything, &mut store, &mut journal),
        Ok(RecoveryReport::NothingPending)
    );

    let attempts = store.write_attempts();
    store.down_from = Some(attempts + 1);
    install(&mut installer, &mut store, &mut journal, new_rules()).unwrap_err();
    store.down_from = None;
    assert_eq!(
        installer.recover(&anything, &mut store, &mut journal),
        Err(InstallError::GrantMismatch)
    );
    let stray = store.insert_foreign(StoreEntry {
        tag: Some(OwnerTag {
            perimeter: perimeter(),
            transaction: TransactionId::new(9),
        }),
        scope: RuleScope::Identity {
            identity: broker().identity,
        },
        body: RuleBody::Perimeter {
            rule: allow("8.8.8.0", 24, 53),
        },
    });
    let grant = installer.recovery_request().unwrap();
    assert_eq!(
        installer.recover(&grant, &mut store, &mut journal),
        Ok(RecoveryReport::RolledBack {
            transaction: TransactionId::new(2),
            untouched: [stray].into_iter().collect(),
        })
    );
    assert!(store.state.entries.contains_key(&stray));
    assert!(installer.settled());
}
