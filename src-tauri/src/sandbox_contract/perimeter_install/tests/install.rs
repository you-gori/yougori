//! Installs, updates and teardowns that commit, and the refusals that write nothing.

use super::super::fakes::{FakeJournal, FakeRuleStore, ForeignChange, Write};
use super::*;

fn refused(store: &FakeRuleStore, refusal: InstallRefusal, expected: InstallRefusal) {
    assert_eq!(refusal, expected);
    assert_eq!(store.write_attempts(), 0);
}

#[test]
fn a_first_install_commits_exactly_the_profile_scoped_to_the_broker() {
    let mut installer = Installer::new(perimeter());
    let mut store = store();
    let mut journal = FakeJournal::default();
    let before = foreign(&store);
    let receipt = install(&mut installer, &mut store, &mut journal, old_rules()).unwrap();

    assert_eq!(receipt.tag.transaction, TransactionId::FIRST);
    assert_eq!(receipt.profile, Some(profile(old_rules()).digest()));
    assert_eq!(receipt.broker, Some(broker()));
    assert_eq!(
        receipt
            .owned
            .iter()
            .map(|(_, rule)| *rule)
            .collect::<BTreeSet<_>>(),
        scoped(&old_rules())
    );
    assert_eq!(tagged_set(&store), scoped(&old_rules()));
    assert_eq!(foreign(&store), before);
    assert!(installer.settled());
    assert_eq!(
        installer
            .journal()
            .owned()
            .iter()
            .map(|(h, r)| (*h, *r))
            .collect::<Vec<_>>(),
        receipt.owned
    );
    assert_eq!(journal.last(), Some(installer.journal()));
    // Every write was an add of a broker-scoped rule under this transaction's tag; nothing
    // machine-wide was ever written.
    assert_eq!(store.writes.len(), 4);
    for write in &store.writes {
        let Write::Added(_, rule) = write else {
            panic!("unexpected {write:?}")
        };
        assert_eq!(rule.tag, receipt.tag);
        assert_eq!(rule.scoped.identity, broker().identity);
    }
    // Blocks went in before allows.
    let actions: Vec<RuleAction> = store
        .writes
        .iter()
        .map(|write| match write {
            Write::Added(_, rule) => rule.scoped.rule.action,
            Write::Removed(_, _) => unreachable!(),
        })
        .collect();
    assert_eq!(
        actions,
        vec![
            RuleAction::Block,
            RuleAction::Block,
            RuleAction::Allow,
            RuleAction::Allow
        ]
    );
}

#[test]
fn an_update_keeps_unchanged_rules_under_their_handles() {
    let mut installer = Installer::new(perimeter());
    let mut store = store();
    let mut journal = FakeJournal::default();
    install(&mut installer, &mut store, &mut journal, old_rules()).unwrap();
    let before = handles(&store);
    let writes_before = store.writes.len();

    let receipt = install(&mut installer, &mut store, &mut journal, new_rules()).unwrap();
    assert_eq!(receipt.tag.transaction, TransactionId::new(2));
    assert_eq!(tagged_set(&store), scoped(&new_rules()));
    let after = handles(&store);
    for kept in [allow("198.51.100.7", 32, 443), block("10.0.0.0", 8)] {
        let rule = ScopedRule {
            identity: broker().identity,
            rule: kept,
        };
        assert_eq!(before[&rule], after[&rule]);
    }
    assert_eq!(store.writes.len() - writes_before, 4);
}

#[test]
fn installing_the_same_profile_again_writes_nothing_but_still_commits() {
    let mut installer = Installer::new(perimeter());
    let mut store = store();
    let mut journal = FakeJournal::default();
    install(&mut installer, &mut store, &mut journal, old_rules()).unwrap();
    let attempts = store.write_attempts();
    let receipt = install(&mut installer, &mut store, &mut journal, old_rules()).unwrap();
    assert_eq!(store.write_attempts(), attempts);
    assert_eq!(receipt.tag.transaction, TransactionId::new(2));
    assert!(installer.settled());
}

#[test]
fn a_teardown_removes_allows_before_blocks_and_leaves_the_broker_nothing() {
    let mut installer = Installer::new(perimeter());
    let mut store = store();
    let mut journal = FakeJournal::default();
    install(&mut installer, &mut store, &mut journal, old_rules()).unwrap();
    let before = foreign(&store);
    let writes_before = store.writes.len();

    let prepared = installer.prepare_teardown(&store).unwrap();
    let grant = prepared.grant_request();
    let receipt = installer
        .execute(&prepared, &grant, &mut store, &mut journal)
        .unwrap();
    assert!(receipt.owned.is_empty());
    assert_eq!(receipt.broker, None);
    assert_eq!(receipt.profile, None);
    assert!(tagged(&store).is_empty());
    assert!(installer.journal().owned().is_empty());
    assert_eq!(foreign(&store), before);
    let actions: Vec<RuleAction> = store.writes[writes_before..]
        .iter()
        .map(|write| match write {
            Write::Removed(_, entry) => entry.scoped().unwrap().rule.action,
            Write::Added(_, _) => unreachable!(),
        })
        .collect();
    assert_eq!(
        actions,
        vec![
            RuleAction::Allow,
            RuleAction::Allow,
            RuleAction::Block,
            RuleAction::Block
        ]
    );
    // The broker's identity stays isolated with no rule: it may reach nothing.
    assert!(permitted(&store.state).is_empty());
}

#[test]
fn unrelated_rules_survive_install_update_and_teardown_untouched() {
    let mut installer = Installer::new(perimeter());
    let mut store = store();
    let mut journal = FakeJournal::default();
    let before = foreign(&store);
    let foreign_handles: BTreeSet<RuleHandle> = before.iter().map(|(handle, _)| *handle).collect();
    install(&mut installer, &mut store, &mut journal, old_rules()).unwrap();
    install(&mut installer, &mut store, &mut journal, new_rules()).unwrap();
    let prepared = installer.prepare_teardown(&store).unwrap();
    let grant = prepared.grant_request();
    installer
        .execute(&prepared, &grant, &mut store, &mut journal)
        .unwrap();
    assert_eq!(foreign(&store), before);
    assert!(store.writes.iter().all(|write| match write {
        Write::Removed(handle, _) => !foreign_handles.contains(handle),
        Write::Added(_, _) => true,
    }));
}

#[test]
fn a_remote_perimeter_is_not_installed_locally() {
    let installer = Installer::new(perimeter());
    let store = store();
    let refusal = installer
        .prepare(
            &store,
            &profile_on(PerimeterPlatform::Remote, old_rules()),
            broker(),
        )
        .unwrap_err();
    refused(&store, refusal, InstallRefusal::RemotePerimeter);
}

#[test]
fn a_user_account_or_process_id_is_never_the_broker_identity() {
    let installer = Installer::new(perimeter());
    let store = store();
    for kind in [IdentityKind::UserAccount, IdentityKind::ProcessId] {
        let refusal = installer
            .prepare(
                &store,
                &profile(old_rules()),
                BrokerIdentity {
                    kind,
                    identity: broker().identity,
                },
            )
            .unwrap_err();
        refused(
            &store,
            refusal,
            InstallRefusal::IdentityKindRefused { kind },
        );
    }
}

#[test]
fn an_identity_kind_from_another_platform_is_refused() {
    let installer = Installer::new(perimeter());
    let store = store();
    let refusal = installer
        .prepare(
            &store,
            &profile(old_rules()),
            BrokerIdentity {
                kind: IdentityKind::SigningIdentity,
                identity: broker().identity,
            },
        )
        .unwrap_err();
    refused(
        &store,
        refusal,
        InstallRefusal::IdentityKindNotOnPlatform {
            kind: IdentityKind::SigningIdentity,
            platform: PerimeterPlatform::Windows,
        },
    );
    let linux = installer
        .prepare(
            &store,
            &profile_on(PerimeterPlatform::Linux, old_rules()),
            BrokerIdentity {
                kind: IdentityKind::NetworkNamespace,
                identity: broker().identity,
            },
        )
        .unwrap();
    assert_eq!(linux.plan().steps().len(), 4);
}

#[test]
fn a_broker_other_than_the_profiles_is_refused() {
    let installer = Installer::new(perimeter());
    let store = store();
    let other = BrokerIdentity {
        kind: IdentityKind::ServiceSid,
        identity: id("someone else"),
    };
    let refusal = installer
        .prepare(&store, &profile(old_rules()), other)
        .unwrap_err();
    refused(
        &store,
        refusal,
        InstallRefusal::IdentityMismatch {
            profile: broker().identity,
            broker: other.identity,
        },
    );
}

#[test]
fn an_identity_the_store_does_not_isolate_is_refused() {
    let installer = Installer::new(perimeter());
    let mut store = store();
    store.state.isolated.clear();
    let refusal = installer
        .prepare(&store, &profile(old_rules()), broker())
        .unwrap_err();
    refused(&store, refusal, InstallRefusal::ScopeNotIsolated);
}

#[test]
fn another_rule_on_the_broker_identity_is_refused_even_from_another_perimeter() {
    let installer = Installer::new(perimeter());
    let mut store = store();
    let untagged = store.insert_foreign(StoreEntry {
        tag: None,
        scope: RuleScope::Identity {
            identity: broker().identity,
        },
        body: RuleBody::Opaque {
            digest: id("allow all"),
        },
    });
    let refusal = installer
        .prepare(&store, &profile(old_rules()), broker())
        .unwrap_err();
    refused(
        &store,
        refusal,
        InstallRefusal::ForeignRuleOnBroker { handle: untagged },
    );

    let mut store = super::store();
    let shared = store.insert_foreign(StoreEntry {
        tag: Some(OwnerTag {
            perimeter: PerimeterId::new(id("another sandbox")),
            transaction: TransactionId::FIRST,
        }),
        scope: RuleScope::Identity {
            identity: broker().identity,
        },
        body: RuleBody::Perimeter {
            rule: allow("192.0.2.0", 24, 443),
        },
    });
    let refusal = installer
        .prepare(&store, &profile(old_rules()), broker())
        .unwrap_err();
    refused(
        &store,
        refusal,
        InstallRefusal::ForeignRuleOnBroker { handle: shared },
    );
}

#[test]
fn a_tagged_rule_the_journal_never_recorded_is_left_alone() {
    let installer = Installer::new(perimeter());
    let mut store = store();
    let stray = store.insert_foreign(StoreEntry {
        tag: Some(OwnerTag {
            perimeter: perimeter(),
            transaction: TransactionId::new(7),
        }),
        scope: RuleScope::Identity {
            identity: broker().identity,
        },
        body: RuleBody::Perimeter {
            rule: allow("192.0.2.0", 24, 443),
        },
    });
    let refusal = installer
        .prepare(&store, &profile(old_rules()), broker())
        .unwrap_err();
    refused(
        &store,
        refusal,
        InstallRefusal::UnclaimedTaggedRule { handle: stray },
    );
    let refusal = installer.prepare_teardown(&store).unwrap_err();
    refused(
        &store,
        refusal,
        InstallRefusal::UnclaimedTaggedRule { handle: stray },
    );
    assert!(store.state.entries.contains_key(&stray));
}

#[test]
fn something_else_under_a_recorded_handle_is_refused() {
    let mut installer = Installer::new(perimeter());
    let mut store = store();
    let mut journal = FakeJournal::default();
    install(&mut installer, &mut store, &mut journal, old_rules()).unwrap();
    let (handle, entry) = store
        .state
        .entries
        .iter()
        .find(|(_, entry)| entry.tag.is_some())
        .map(|(handle, entry)| (*handle, *entry))
        .unwrap();
    let mut altered = entry;
    altered.body = RuleBody::Perimeter {
        rule: allow("8.8.8.0", 24, 53),
    };
    store.state.entries.insert(handle, altered);
    let attempts = store.write_attempts();
    assert_eq!(
        installer.prepare(&store, &profile(new_rules()), broker()),
        Err(InstallRefusal::OwnedRuleAltered { handle })
    );
    assert_eq!(store.write_attempts(), attempts);
}

#[test]
fn an_unreadable_store_and_exhausted_transactions_are_refused() {
    let installer = Installer::new(perimeter());
    let mut store = store();
    store.unreadable = true;
    let refusal = installer
        .prepare(&store, &profile(old_rules()), broker())
        .unwrap_err();
    refused(
        &store,
        refusal,
        InstallRefusal::Store {
            failure: StoreFailure::Unavailable,
        },
    );

    let exhausted: InstallJournal = serde_json::from_value(serde_json::json!({
        "perimeter": perimeter(),
        "last_transaction": u64::MAX,
        "owned": [],
        "pending": null,
    }))
    .unwrap();
    let installer = Installer::restore(exhausted);
    let store = super::store();
    let refusal = installer
        .prepare(&store, &profile(old_rules()), broker())
        .unwrap_err();
    refused(&store, refusal, InstallRefusal::TransactionsExhausted);
}

#[test]
fn a_grant_for_anything_but_the_plan_writes_nothing() {
    let mut installer = Installer::new(perimeter());
    let mut store = store();
    let mut journal = FakeJournal::default();
    let prepared = installer
        .prepare(&store, &profile(old_rules()), broker())
        .unwrap();
    let mut wider = prepared.grant_request();
    wider.may_add.insert(ScopedRule {
        identity: broker().identity,
        rule: allow("8.8.8.0", 24, 53),
    });
    let other = installer
        .prepare(&store, &profile(new_rules()), broker())
        .unwrap()
        .grant_request();
    for grant in [wider, other] {
        assert_eq!(
            installer.execute(&prepared, &grant, &mut store, &mut journal),
            Err(InstallError::GrantMismatch)
        );
    }
    assert_eq!(store.write_attempts(), 0);
    assert_eq!(journal.calls(), 0);
}

#[test]
fn the_elevated_side_refuses_operations_outside_its_grant() {
    let installer = Installer::new(perimeter());
    let mut store = store();
    let prepared = installer
        .prepare(&store, &profile(old_rules()), broker())
        .unwrap();
    let grant = prepared.grant_request();
    let outside = OwnedRule {
        tag: grant.tag,
        scoped: ScopedRule {
            identity: broker().identity,
            rule: allow("8.8.8.0", 24, 53),
        },
    };
    assert_eq!(store.add(&grant, &outside), Err(StoreFailure::NotGranted));
    let (vpn, _) = foreign(&store)[0];
    assert_eq!(store.remove(&grant, vpn), Err(StoreFailure::NotGranted));
    assert!(store.state.entries.contains_key(&vpn));
    assert!(store.writes.is_empty());
}

#[test]
fn a_plan_made_before_the_store_changed_is_stale() {
    let mut installer = Installer::new(perimeter());
    let mut store = store();
    let mut journal = FakeJournal::default();
    install(&mut installer, &mut store, &mut journal, old_rules()).unwrap();
    let prepared = installer
        .prepare(&store, &profile(new_rules()), broker())
        .unwrap();
    // Someone deletes one of the perimeter's rules before the plan runs.
    let (handle, _) = handles(&store)
        .into_iter()
        .next()
        .map(|(r, h)| (h, r))
        .unwrap();
    store.state.entries.remove(&handle);
    let attempts = store.write_attempts();
    let grant = prepared.grant_request();
    assert_eq!(
        installer.execute(&prepared, &grant, &mut store, &mut journal),
        Err(InstallError::StalePlan)
    );
    assert_eq!(store.write_attempts(), attempts);

    // A plan whose transaction was already used is stale too.
    let mut store = super::store();
    let mut installer = Installer::new(perimeter());
    let first = installer
        .prepare(&store, &profile(old_rules()), broker())
        .unwrap();
    let grant = first.grant_request();
    installer
        .execute(&first, &grant, &mut store, &mut journal)
        .unwrap();
    assert_eq!(
        installer.execute(&first, &grant, &mut store, &mut journal),
        Err(InstallError::StalePlan)
    );
}

#[test]
fn a_committed_rule_someone_deleted_is_reported_and_put_back() {
    let mut installer = Installer::new(perimeter());
    let mut store = store();
    let mut journal = FakeJournal::default();
    install(&mut installer, &mut store, &mut journal, old_rules()).unwrap();
    let metadata = ScopedRule {
        identity: broker().identity,
        rule: block("169.254.169.254", 32),
    };
    let handle = handles(&store)[&metadata];
    store.state.entries.remove(&handle);

    let receipt = install(&mut installer, &mut store, &mut journal, old_rules()).unwrap();
    assert_eq!(receipt.vanished, [handle].into_iter().collect());
    assert_eq!(tagged_set(&store), scoped(&old_rules()));
    assert!(!installer.journal().owned().contains_key(&handle));
}

#[test]
fn rules_other_programs_add_meanwhile_are_counted_not_touched() {
    let mut installer = Installer::new(perimeter());
    let mut store = store();
    let mut journal = FakeJournal::default();
    store.after.insert(
        1,
        vec![ForeignChange::Insert(StoreEntry {
            tag: None,
            scope: RuleScope::Machine,
            body: RuleBody::Opaque {
                digest: id("updater"),
            },
        })],
    );
    let receipt = install(&mut installer, &mut store, &mut journal, old_rules()).unwrap();
    assert_eq!(receipt.foreign_added, 1);
    assert_eq!(foreign(&store).len(), 3);
}
