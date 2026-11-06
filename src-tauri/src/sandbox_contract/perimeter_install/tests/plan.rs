//! The fail-closed order, plan digests, grants and identity kinds.

use std::collections::{BTreeMap, BTreeSet};

use super::super::fakes::{FakeJournal, FakeRuleStore};
use super::super::plan::ordered_steps;
use super::*;

/// Applies `steps` to a copy of `start`, returning the state after each step.
fn states(start: &StoreSnapshot, steps: &[PlanStep], tag: OwnerTag) -> Vec<StoreSnapshot> {
    let mut state = start.clone();
    let mut next = 10_000;
    let mut all = Vec::new();
    for step in steps {
        match *step {
            PlanStep::Add { scoped } => {
                next += 1;
                state.entries.insert(
                    RuleHandle::new(next),
                    StoreEntry {
                        tag: Some(tag),
                        scope: RuleScope::Identity {
                            identity: scoped.identity,
                        },
                        body: RuleBody::Perimeter { rule: scoped.rule },
                    },
                );
            }
            PlanStep::Remove { handle, .. } => {
                state.entries.remove(&handle);
            }
        }
        all.push(state.clone());
    }
    all
}

fn installed_old() -> (Installer, FakeRuleStore, FakeJournal) {
    let mut installer = Installer::new(perimeter());
    let mut store = store();
    let mut journal = FakeJournal::default();
    install(&mut installer, &mut store, &mut journal, old_rules()).unwrap();
    (installer, store, journal)
}

#[test]
fn steps_follow_the_fail_closed_order_and_keep_unchanged_rules() {
    let (installer, store, _) = installed_old();
    let prepared = installer
        .prepare(&store, &profile(new_rules()), broker())
        .unwrap();
    let kinds: Vec<(bool, RuleAction, IpPrefix)> = prepared
        .plan()
        .steps()
        .iter()
        .map(|step| {
            (
                matches!(step, PlanStep::Add { .. }),
                step.scoped().rule.action,
                step.scoped().rule.prefix,
            )
        })
        .collect();
    assert_eq!(
        kinds,
        vec![
            (true, RuleAction::Block, prefix("203.0.113.0", 24)),
            (false, RuleAction::Allow, prefix("203.0.113.0", 24)),
            (true, RuleAction::Allow, prefix("192.0.2.0", 24)),
            (false, RuleAction::Block, prefix("169.254.169.254", 32)),
        ]
    );
    assert_eq!(prepared.plan().prior().len(), 4);
    assert_eq!(*prepared.plan().target(), scoped(&new_rules()));
}

/// The old perimeter with 203.0.113.0/24 simply dropped, not blocked, and 192.0.2.0/24
/// newly allowed.
fn dropped_rules() -> Vec<PerimeterRule> {
    vec![
        allow("192.0.2.0", 24, 443),
        allow("198.51.100.7", 32, 443),
        block("10.0.0.0", 8),
    ]
}

#[test]
fn no_step_mixes_old_and_new_permissions_while_a_naive_order_does() {
    let (installer, store, _) = installed_old();
    let start = store.state.clone();
    let old = permitted(&start);
    for target in [new_rules(), dropped_rules()] {
        let prepared = installer
            .prepare(&store, &profile(target), broker())
            .unwrap();
        let plan = prepared.plan();
        let all = states(&start, plan.steps(), plan.tag());
        let new = permitted(all.last().unwrap());
        assert_ne!(old, new);
        let first_allow_add = plan
            .steps()
            .iter()
            .position(|step| {
                matches!(step, PlanStep::Add { scoped } if scoped.rule.action == RuleAction::Allow)
            })
            .unwrap();
        for (index, state) in all.iter().enumerate() {
            let now = permitted(state);
            if index < first_allow_add {
                assert!(
                    now.is_subset(&old),
                    "step {index} permits beyond the old rules"
                );
            } else {
                assert!(
                    now.is_subset(&new),
                    "step {index} permits beyond the new rules"
                );
            }
        }
    }

    // Adding everything first and removing afterwards passes through a state that permits
    // both an old-only and a new-only destination.
    let prepared = installer
        .prepare(&store, &profile(dropped_rules()), broker())
        .unwrap();
    let plan = prepared.plan();
    let new = permitted(states(&start, plan.steps(), plan.tag()).last().unwrap());
    let (adds, removes): (Vec<PlanStep>, Vec<PlanStep>) = plan
        .steps()
        .iter()
        .partition(|step| matches!(step, PlanStep::Add { .. }));
    let naive: Vec<PlanStep> = adds.into_iter().chain(removes).collect();
    let mixed = states(&start, &naive, plan.tag()).iter().any(|state| {
        let now = permitted(state);
        !now.is_subset(&old) && !now.is_subset(&new)
    });
    assert!(mixed);
}

#[test]
fn a_duplicate_owned_rule_keeps_its_lowest_handle() {
    let rule = ScopedRule {
        identity: broker().identity,
        rule: allow("192.0.2.0", 24, 443),
    };
    let current: BTreeMap<RuleHandle, ScopedRule> =
        [(RuleHandle::new(7), rule), (RuleHandle::new(3), rule)]
            .into_iter()
            .collect();
    let target: BTreeSet<ScopedRule> = [rule].into_iter().collect();
    assert_eq!(
        ordered_steps(&current, &target),
        vec![PlanStep::Remove {
            handle: RuleHandle::new(7),
            scoped: rule
        }]
    );
}

#[test]
fn a_new_broker_identity_moves_every_rule_in_the_same_order() {
    let other = id("new broker build");
    let current: BTreeMap<RuleHandle, ScopedRule> = scoped(&old_rules())
        .into_iter()
        .enumerate()
        .map(|(index, rule)| (RuleHandle::new(u64::try_from(index).unwrap()), rule))
        .collect();
    let target: BTreeSet<ScopedRule> = old_rules()
        .into_iter()
        .map(|rule| ScopedRule {
            identity: other,
            rule,
        })
        .collect();
    let steps = ordered_steps(&current, &target);
    assert_eq!(steps.len(), 8);
    let phases: Vec<(bool, RuleAction)> = steps
        .iter()
        .map(|step| {
            (
                matches!(step, PlanStep::Add { .. }),
                step.scoped().rule.action,
            )
        })
        .collect();
    assert_eq!(
        phases,
        vec![
            (true, RuleAction::Block),
            (true, RuleAction::Block),
            (false, RuleAction::Allow),
            (false, RuleAction::Allow),
            (true, RuleAction::Allow),
            (true, RuleAction::Allow),
            (false, RuleAction::Block),
            (false, RuleAction::Block),
        ]
    );
    assert!(steps
        .iter()
        .filter(|step| matches!(step, PlanStep::Add { .. }))
        .all(|step| step.scoped().identity == other));
}

#[test]
fn the_grant_request_covers_exactly_the_plan_and_its_rollback() {
    let (installer, store, _) = installed_old();
    let prepared = installer
        .prepare(&store, &profile(new_rules()), broker())
        .unwrap();
    let plan = prepared.plan();
    let grant = prepared.grant_request();
    assert_eq!(grant.plan, plan.digest());
    assert_eq!(grant.tag, plan.tag());
    let mut adds = scoped(&new_rules());
    adds.extend(scoped(&old_rules()));
    assert_eq!(grant.may_add, adds);
    assert_eq!(
        grant.may_remove,
        plan.prior().keys().copied().collect::<BTreeSet<_>>()
    );
    // Not a rule of either set, and not under another tag.
    let stranger = OwnedRule {
        tag: plan.tag(),
        scoped: ScopedRule {
            identity: broker().identity,
            rule: allow("8.8.8.0", 24, 53),
        },
    };
    assert!(!grant.permits_add(&stranger));
    let mut other_tag = plan.tag();
    other_tag.transaction = TransactionId::new(99);
    assert!(!grant.permits_add(&OwnedRule {
        tag: other_tag,
        scoped: ScopedRule {
            identity: broker().identity,
            rule: allow("192.0.2.0", 24, 443),
        },
    }));
}

#[test]
fn the_plan_digest_changes_with_the_transaction_and_the_steps() {
    let (installer, store, _) = installed_old();
    let a = installer
        .prepare(&store, &profile(new_rules()), broker())
        .unwrap();
    let b = installer
        .prepare(&store, &profile(old_rules()), broker())
        .unwrap();
    assert_ne!(a.plan().digest(), b.plan().digest());
    let mut later = a.plan().clone();
    later.tag.transaction = TransactionId::new(later.tag.transaction.get() + 1);
    assert_ne!(a.plan().digest(), later.digest());
    assert_eq!(
        a.plan().digest(),
        installer
            .prepare(&store, &profile(new_rules()), broker())
            .unwrap()
            .plan()
            .digest()
    );
}

#[test]
fn identity_kinds_name_one_stable_process_on_their_platform_only() {
    use PerimeterPlatform::*;
    for kind in [IdentityKind::UserAccount, IdentityKind::ProcessId] {
        assert!(kind.platforms().is_empty(), "{kind}");
    }
    assert_eq!(IdentityKind::ServiceSid.platforms(), &[Windows]);
    assert_eq!(IdentityKind::AppContainer.platforms(), &[Windows]);
    assert_eq!(IdentityKind::NetworkNamespace.platforms(), &[Linux]);
    assert_eq!(IdentityKind::SigningIdentity.platforms(), &[MacOs]);
    for kind in [
        IdentityKind::DedicatedAccount,
        IdentityKind::NetworkNamespace,
        IdentityKind::Cgroup,
        IdentityKind::ServiceSid,
        IdentityKind::AppContainer,
        IdentityKind::SigningIdentity,
    ] {
        assert!(!kind.platforms().contains(&Remote));
    }
}

#[test]
fn an_unknown_or_opaque_rule_on_the_identity_denies() {
    let mut snapshot = StoreSnapshot::default();
    let identity = broker().identity;
    let address = "192.0.2.9".parse().unwrap();
    assert_eq!(snapshot.permits(identity, address, port(443)), None);
    snapshot.isolated.insert(identity);
    assert_eq!(snapshot.permits(identity, address, port(443)), Some(false));
    snapshot.entries.insert(
        RuleHandle::new(1),
        StoreEntry {
            tag: None,
            scope: RuleScope::Identity { identity },
            body: RuleBody::Perimeter {
                rule: allow("192.0.2.0", 24, 443),
            },
        },
    );
    assert_eq!(snapshot.permits(identity, address, port(443)), Some(true));
    assert_eq!(snapshot.permits(identity, address, port(80)), Some(false));
    snapshot.entries.insert(
        RuleHandle::new(2),
        StoreEntry {
            tag: None,
            scope: RuleScope::Identity { identity },
            body: RuleBody::Opaque { digest: id("x") },
        },
    );
    assert_eq!(snapshot.permits(identity, address, port(443)), Some(false));
}
