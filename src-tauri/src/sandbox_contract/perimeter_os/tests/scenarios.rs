//! V16's own installer end to end over each platform store that can isolate the broker
//! (nftables and WFP; pf cannot, see `pf`) and its fake port: install, verification by
//! read-back, update and teardown; rollback after a store failure, including one that
//! must add back rules the update had removed; recovery after a stop part way; a
//! read-back that differs from what was installed; malformed output that stops the store
//! writing; and the grant checked before anything reaches the port. Rules outside the
//! owned object, look-alikes with a forged marker included, never change.

use std::collections::{BTreeMap, BTreeSet};

use super::super::fakes::FakeJournal;
use super::nft::NftBench;
use super::wfp::WfpBench;
use super::*;
use crate::sandbox_contract::perimeter_install::{
    AbortCause, OwnedRule, RecoveryReport, RollbackFailure, StoreEntry, VerificationFailure,
};

/// One platform store over its fake port, set up for the scenarios.
pub trait Bench {
    type Store: RuleStore;
    const PLATFORM: PerimeterPlatform;

    fn broker() -> BrokerIdentity;

    /// A provisioned store isolating the broker, with rules of other programs outside the
    /// owned object, some carrying the marker the store will give its first rule.
    fn store() -> Self::Store;

    /// Write attempts so far.
    fn writes(store: &Self::Store) -> usize;

    /// Whether write attempt `index` removed a rule.
    fn is_removal(store: &Self::Store, index: usize) -> bool;

    fn fail_write(store: &mut Self::Store, index: usize, failure: StoreFailure);

    /// Writes report success from now on but change nothing.
    fn lossy(store: &mut Self::Store);

    /// Right after write `index`, another program turns the rule that write added (an
    /// IPv4 block) into a different rule this product could have rendered, under the
    /// same marker.
    fn alter_after(store: &mut Self::Store, index: usize);

    /// Right after write `index`, another program puts something this product never
    /// renders into the owned object.
    fn corrupt_after(store: &mut Self::Store, index: usize);

    /// Everything outside the owned object.
    fn outside(store: &Self::Store) -> String;
}

/// A store with the old rules installed.
pub fn installed<B: Bench>() -> (Installer, B::Store, FakeJournal) {
    let mut installer = Installer::new(perimeter());
    let mut store = B::store();
    let mut journal = FakeJournal::default();
    install(
        &mut installer,
        &mut store,
        &mut journal,
        B::PLATFORM,
        B::broker(),
        old_rules(),
    )
    .unwrap();
    (installer, store, journal)
}

/// The store holds exactly `rules` for the perimeter, under the journal's handles, and
/// isolates the broker; nothing outside the owned object carries a tag.
fn holds<B: Bench>(store: &B::Store, installer: &Installer, rules: &[PerimeterRule]) {
    let broker = B::broker();
    let snapshot = store.snapshot().unwrap();
    assert_eq!(owned(&snapshot), scoped(broker.identity, rules));
    assert_eq!(tagged(&snapshot), rules.len());
    assert!(snapshot.isolated.contains(&broker.identity));
    for (handle, rule) in installer.journal().owned() {
        assert_eq!(
            snapshot.entry(*handle).and_then(StoreEntry::scoped),
            Some(*rule)
        );
    }
    assert_eq!(installer.journal().owned().len(), rules.len());
    // The read-back means what the profile says under V16's evaluation model.
    assert_eq!(permitted(&snapshot, broker.identity), expected(rules));
}

pub fn installs_updates_and_tears_down<B: Bench>() {
    let mut store = B::store();
    let outside = B::outside(&store);
    let broker = B::broker();
    let mut installer = Installer::new(perimeter());
    let mut journal = FakeJournal::default();

    let receipt = install(
        &mut installer,
        &mut store,
        &mut journal,
        B::PLATFORM,
        broker,
        old_rules(),
    )
    .unwrap();
    assert_eq!(receipt.tag.transaction, TransactionId::FIRST);
    assert_eq!(
        receipt.owned.iter().copied().collect::<BTreeMap<_, _>>(),
        *installer.journal().owned()
    );
    holds::<B>(&store, &installer, &old_rules());

    let kept: BTreeMap<RuleHandle, ScopedRule> = installer
        .journal()
        .owned()
        .iter()
        .filter(|(_, rule)| new_rules().contains(&rule.rule))
        .map(|(handle, rule)| (*handle, *rule))
        .collect();
    assert_eq!(kept.len(), 2);
    install(
        &mut installer,
        &mut store,
        &mut journal,
        B::PLATFORM,
        broker,
        new_rules(),
    )
    .unwrap();
    holds::<B>(&store, &installer, &new_rules());
    // Unchanged rules keep their handles.
    for (handle, rule) in &kept {
        assert_eq!(installer.journal().owned().get(handle), Some(rule));
    }

    teardown(&mut installer, &mut store, &mut journal).unwrap();
    let snapshot = store.snapshot().unwrap();
    assert!(owned(&snapshot).is_empty());
    assert_eq!(tagged(&snapshot), 0);
    // The broker stays isolated with nothing allowed.
    assert!(snapshot.isolated.contains(&broker.identity));
    assert!(permitted(&snapshot, broker.identity).is_empty());
    assert!(installer.settled());
    assert_eq!(B::outside(&store), outside);
}

pub fn rolls_back_a_failed_update<B: Bench>() {
    let (mut installer, mut store, mut journal) = installed::<B>();
    let outside = B::outside(&store);
    let writes = B::writes(&store);
    // The third step of the update fails.
    B::fail_write(&mut store, writes + 2, StoreFailure::Rejected);
    let error = install(
        &mut installer,
        &mut store,
        &mut journal,
        B::PLATFORM,
        B::broker(),
        new_rules(),
    )
    .unwrap_err();
    assert_eq!(
        error,
        InstallError::RolledBack {
            cause: AbortCause::Store {
                failure: StoreFailure::Rejected
            }
        }
    );
    assert!(installer.settled());
    holds::<B>(&store, &installer, &old_rules());
    assert_eq!(B::outside(&store), outside);
    // The transaction number is spent; the next install uses a new one.
    let receipt = install(
        &mut installer,
        &mut store,
        &mut journal,
        B::PLATFORM,
        B::broker(),
        new_rules(),
    )
    .unwrap();
    assert_eq!(receipt.tag.transaction, TransactionId::new(3));
    holds::<B>(&store, &installer, &new_rules());
}

/// An update that fails after it removed old rules: the rollback must add them back.
pub fn rolls_back_after_removing_prior_rules<B: Bench>() {
    let (mut installer, mut store, mut journal) = installed::<B>();
    let outside = B::outside(&store);
    let writes = B::writes(&store);
    // The fifth step of the update fails: the add of the newly allowed 192.0.2.0/24.
    let failing = writes + 4;
    B::fail_write(&mut store, failing, StoreFailure::Rejected);
    let error = install(
        &mut installer,
        &mut store,
        &mut journal,
        B::PLATFORM,
        B::broker(),
        new_rules(),
    )
    .unwrap_err();
    assert_eq!(
        error,
        InstallError::RolledBack {
            cause: AbortCause::Store {
                failure: StoreFailure::Rejected
            }
        }
    );
    // Steps before the failure removed old rules, and the failing one was an add.
    assert!((writes..failing).any(|index| B::is_removal(&store, index)));
    assert!(!B::is_removal(&store, failing));
    assert!(installer.settled());
    holds::<B>(&store, &installer, &old_rules());
    assert_eq!(B::outside(&store), outside);
}

pub fn recovers_after_a_stop_part_way<B: Bench>() {
    let (mut installer, mut store, mut journal) = installed::<B>();
    let outside = B::outside(&store);
    let before = owned(&store.snapshot().unwrap());
    // The journal records the start and the first step, then cannot record the second,
    // which the store has already made.
    journal.fail_from = Some(journal.calls() + 2);
    let error = install(
        &mut installer,
        &mut store,
        &mut journal,
        B::PLATFORM,
        B::broker(),
        new_rules(),
    )
    .unwrap_err();
    let InstallError::Journal {
        pending: Some(transaction),
    } = error
    else {
        panic!("unexpected {error:?}");
    };
    assert_ne!(owned(&store.snapshot().unwrap()), before);

    // The process stops; a new one starts from the last persisted journal.
    let mut restarted = Installer::restore(journal.last().unwrap().clone());
    assert!(!restarted.settled());
    let mut fresh = FakeJournal::default();
    let grant = restarted.recovery_request().unwrap();
    let report = restarted.recover(&grant, &mut store, &mut fresh).unwrap();
    assert_eq!(
        report,
        RecoveryReport::RolledBack {
            transaction,
            untouched: BTreeSet::new()
        }
    );
    assert!(restarted.settled());
    holds::<B>(&store, &restarted, &old_rules());
    assert_eq!(B::outside(&store), outside);
}

pub fn catches_a_read_back_that_differs<B: Bench>() {
    // A store that acknowledges adds but keeps nothing.
    let mut store = B::store();
    B::lossy(&mut store);
    let mut installer = Installer::new(perimeter());
    let mut journal = FakeJournal::default();
    let error = install(
        &mut installer,
        &mut store,
        &mut journal,
        B::PLATFORM,
        B::broker(),
        old_rules(),
    )
    .unwrap_err();
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

    // Another program rewrites the first rule added into another valid rule.
    let mut store = B::store();
    let outside = B::outside(&store);
    let writes = B::writes(&store);
    B::alter_after(&mut store, writes);
    let mut installer = Installer::new(perimeter());
    let mut journal = FakeJournal::default();
    let error = install(
        &mut installer,
        &mut store,
        &mut journal,
        B::PLATFORM,
        B::broker(),
        old_rules(),
    )
    .unwrap_err();
    assert!(
        matches!(
            error,
            InstallError::RolledBack {
                cause: AbortCause::Verification {
                    failure: VerificationFailure::Unexpected { .. }
                }
            }
        ),
        "{error:?}"
    );
    // The rollback removed every rule the transaction tagged, the altered one included.
    let snapshot = store.snapshot().unwrap();
    assert_eq!(tagged(&snapshot), 0);
    assert!(installer.settled());
    assert_eq!(B::outside(&store), outside);
}

pub fn refuses_malformed_output_and_stops_writing<B: Bench>() {
    let mut store = B::store();
    let writes = B::writes(&store);
    B::corrupt_after(&mut store, writes);
    let mut installer = Installer::new(perimeter());
    let mut journal = FakeJournal::default();
    let error = install(
        &mut installer,
        &mut store,
        &mut journal,
        B::PLATFORM,
        B::broker(),
        old_rules(),
    )
    .unwrap_err();
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
    // Past the corruption no add and no rollback step reached the port: the store never
    // writes over a listing it cannot parse.
    assert_eq!(B::writes(&store), writes + 1);
    assert_eq!(store.snapshot(), Err(StoreFailure::Unavailable));
    assert!(!installer.settled());
}

pub fn checks_the_grant_before_the_port<B: Bench>() {
    let (installer, mut store, _) = installed::<B>();
    let writes = B::writes(&store);
    let prepared = installer
        .prepare(
            &store,
            &profile(B::PLATFORM, B::broker(), new_rules()),
            B::broker(),
        )
        .unwrap();
    let mut grant = prepared.grant_request();
    let unlisted = OwnedRule {
        tag: grant.tag,
        scoped: ScopedRule {
            identity: B::broker().identity,
            rule: allow("8.8.8.8", 32, 53),
        },
    };
    assert_eq!(store.add(&grant, &unlisted), Err(StoreFailure::NotGranted));
    let other_tag = OwnedRule {
        tag: OwnerTag {
            perimeter: perimeter(),
            transaction: TransactionId::new(9),
        },
        scoped: *grant.may_add.iter().next().unwrap(),
    };
    assert_eq!(store.add(&grant, &other_tag), Err(StoreFailure::NotGranted));
    let committed = *installer.journal().owned().keys().next().unwrap();
    grant.may_remove.remove(&committed);
    assert_eq!(
        store.remove(&grant, committed),
        Err(StoreFailure::NotGranted)
    );
    assert_eq!(B::writes(&store), writes);
    assert_eq!(
        owned(&store.snapshot().unwrap()),
        scoped(B::broker().identity, &old_rules())
    );
}

macro_rules! scenarios {
    ($platform:ident, $bench:ty) => {
        mod $platform {
            use super::*;

            #[test]
            fn installs_updates_and_tears_down() {
                super::installs_updates_and_tears_down::<$bench>();
            }

            #[test]
            fn rolls_back_a_failed_update() {
                super::rolls_back_a_failed_update::<$bench>();
            }

            #[test]
            fn rolls_back_after_removing_prior_rules() {
                super::rolls_back_after_removing_prior_rules::<$bench>();
            }

            #[test]
            fn recovers_after_a_stop_part_way() {
                super::recovers_after_a_stop_part_way::<$bench>();
            }

            #[test]
            fn catches_a_read_back_that_differs() {
                super::catches_a_read_back_that_differs::<$bench>();
            }

            #[test]
            fn refuses_malformed_output_and_stops_writing() {
                super::refuses_malformed_output_and_stops_writing::<$bench>();
            }

            #[test]
            fn checks_the_grant_before_the_port() {
                super::checks_the_grant_before_the_port::<$bench>();
            }
        }
    };
}

scenarios!(linux_nftables, NftBench);
scenarios!(windows_wfp, WfpBench);
