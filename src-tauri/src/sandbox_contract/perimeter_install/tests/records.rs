//! Persisted records read back exactly and strictly.

use super::super::fakes::FakeJournal;
use super::*;

#[test]
fn a_journal_with_a_pending_transaction_round_trips() {
    let mut installer = Installer::new(perimeter());
    let mut store = store();
    let mut journal = FakeJournal::default();
    install(&mut installer, &mut store, &mut journal, old_rules()).unwrap();
    journal.fail_from = Some(journal.calls() + 2);
    install(&mut installer, &mut store, &mut journal, new_rules()).unwrap_err();
    let pending = installer.journal().clone();
    assert!(pending.pending().is_some());
    let json = serde_json::to_string(&pending).unwrap();
    assert_eq!(
        serde_json::from_str::<InstallJournal>(&json).unwrap(),
        pending
    );
}

#[test]
fn a_journal_is_read_strictly() {
    let base = serde_json::json!({
        "perimeter": perimeter(),
        "last_transaction": 2,
        "owned": [],
        "pending": null,
    });
    assert!(serde_json::from_value::<InstallJournal>(base.clone()).is_ok());

    let mut unknown = base.clone();
    unknown["high_water"] = serde_json::json!(5);
    assert!(serde_json::from_value::<InstallJournal>(unknown).is_err());

    let pending = serde_json::json!({
        "transaction": 1,
        "plan": id("plan"),
        "broker": null,
        "target": [],
        "completed": [],
    });
    let mut not_last = base.clone();
    not_last["pending"] = pending.clone();
    assert!(serde_json::from_value::<InstallJournal>(not_last).is_err());
    let mut last = base.clone();
    last["pending"] = pending;
    last["last_transaction"] = serde_json::json!(1);
    assert!(serde_json::from_value::<InstallJournal>(last).is_ok());

    let rule = ScopedRule {
        identity: broker().identity,
        rule: allow("192.0.2.0", 24, 443),
    };
    let mut duplicate = base;
    duplicate["owned"] = serde_json::json!([[4, rule], [4, rule]]);
    assert!(serde_json::from_value::<InstallJournal>(duplicate).is_err());
}

#[test]
fn receipts_grants_and_snapshots_round_trip() {
    let mut installer = Installer::new(perimeter());
    let mut store = store();
    let mut journal = FakeJournal::default();
    let prepared = installer
        .prepare(&store, &profile(old_rules()), broker())
        .unwrap();
    let grant = prepared.grant_request();
    let json = serde_json::to_string(&grant).unwrap();
    assert_eq!(
        serde_json::from_str::<ElevationGrant>(&json).unwrap(),
        grant
    );

    let receipt = installer
        .execute(&prepared, &grant, &mut store, &mut journal)
        .unwrap();
    let json = serde_json::to_string(&receipt).unwrap();
    assert_eq!(
        serde_json::from_str::<InstallReceipt>(&json).unwrap(),
        receipt
    );

    let json = serde_json::to_string(&store.state).unwrap();
    assert_eq!(
        serde_json::from_str::<StoreSnapshot>(&json).unwrap(),
        store.state
    );
}

#[test]
fn record_shapes_are_stable() {
    assert_eq!(
        serde_json::to_value(RuleScope::Machine).unwrap(),
        serde_json::json!("machine")
    );
    assert_eq!(
        serde_json::to_value(IdentityKind::ServiceSid).unwrap(),
        serde_json::json!("service_sid")
    );
    let tag = OwnerTag {
        perimeter: perimeter(),
        transaction: TransactionId::new(3),
    };
    let value = serde_json::to_value(tag).unwrap();
    assert_eq!(value["transaction"], serde_json::json!(3));
    assert_eq!(serde_json::from_value::<OwnerTag>(value).unwrap(), tag);
    assert!(serde_json::from_value::<OwnerTag>(serde_json::json!({
        "perimeter": perimeter(),
        "transaction": 3,
        "owner": "me",
    }))
    .is_err());
    assert!(serde_json::from_value::<IdentityKind>(serde_json::json!("program_path")).is_err());
}

#[test]
fn transaction_numbers_are_never_reused() {
    assert_eq!(TransactionId::new(u64::MAX).next(), None);
    assert_eq!(TransactionId::FIRST.next(), Some(TransactionId::new(2)));
}
