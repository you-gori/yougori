//! The nftables store: the rendered statements and batches, the chain order that carries
//! the evaluation model, look-alikes outside the owned table, a namespace binding, cgroup
//! bindings that stay isolated by their account, overlapping bindings refused, isolation
//! that never writes over a read it could not make, and the listings it refuses.

use std::collections::BTreeSet;

use serde_json::{json, Value};

use super::super::common::{allocate_handle, bind, owned_marker};
use super::super::fakes::{FakeJournal, FakeNft, NftChain, NftRuleset};
use super::super::nft::{isolation_statements, parse_listing, rule_statements};
use super::scenarios::{installed, Bench};
use super::*;
use crate::sandbox_contract::perimeter_install::{IdentityKind, InstallRefusal};

pub struct NftBench;

pub fn broker() -> BrokerIdentity {
    BrokerIdentity {
        kind: IdentityKind::DedicatedAccount,
        identity: id("linux broker"),
    }
}

pub fn binding() -> Binding<NftSelector> {
    Binding {
        broker: broker(),
        selector: NftSelector::SocketUid { uid: 961 },
    }
}

fn skuid(uid: u32) -> Value {
    json!({"match": {"op": "==", "left": {"meta": {"key": "skuid"}}, "right": uid}})
}

/// The marker the store gives the first rule of transaction 1, which the look-alikes
/// forge.
pub fn first_marker() -> String {
    let tag = OwnerTag {
        perimeter: perimeter(),
        transaction: TransactionId::FIRST,
    };
    owned_marker(tag, allocate_handle(tag, &BTreeSet::new()).unwrap())
}

fn chain(port: &FakeNft) -> &NftChain {
    port.ruleset
        .table("inet", "yougori")
        .unwrap()
        .chain("perimeter")
        .unwrap()
}

impl Bench for NftBench {
    type Store = NftStore<FakeNft>;
    const PLATFORM: PerimeterPlatform = PerimeterPlatform::Linux;

    fn broker() -> BrokerIdentity {
        broker()
    }

    fn store() -> Self::Store {
        let mut port = FakeNft::default();
        let forged = first_marker();
        // A table of the same name in another family and a look-alike table, both with
        // the first rule's marker forged, and an unrelated program's rule.
        port.ruleset.push_rule(
            "ip",
            "yougori",
            "perimeter",
            Some(&forged),
            vec![json!({"accept": null})],
        );
        port.ruleset.push_rule(
            "inet",
            "yougori-shadow",
            "perimeter",
            Some(&forged),
            rule_statements(&binding().selector, &block("10.0.0.0", 8)),
        );
        port.ruleset.push_rule(
            "inet",
            "filter",
            "output",
            Some("ssh"),
            vec![json!({"accept": null})],
        );
        let mut store = NftStore::new(port, vec![binding()]).unwrap();
        store.isolate(broker().identity).unwrap();
        store
    }

    fn writes(store: &Self::Store) -> usize {
        store.port().script.writes()
    }

    fn is_removal(store: &Self::Store, index: usize) -> bool {
        store
            .port()
            .writes
            .get(index)
            .and_then(|invocation| invocation.input.as_deref())
            .is_some_and(|input| input.contains("\"delete\""))
    }

    fn fail_write(store: &mut Self::Store, index: usize, failure: StoreFailure) {
        store.port_mut().script.fail.insert(index, failure);
    }

    fn lossy(store: &mut Self::Store) {
        store.port_mut().script.lossy = true;
    }

    fn alter_after(store: &mut Self::Store, index: usize) {
        let edit = |ruleset: &mut NftRuleset| {
            let chain = ruleset
                .table_mut("inet", "yougori")
                .unwrap()
                .chain_mut("perimeter")
                .unwrap();
            let rule = chain
                .rules
                .iter_mut()
                .filter(|rule| !rule.comment.as_deref().unwrap().contains("isolate"))
                .max_by_key(|rule| rule.handle)
                .unwrap();
            for statement in &mut rule.expr {
                if statement["match"]["left"]["payload"]["field"] == "daddr" {
                    statement["match"]["right"] = json!("192.0.2.77");
                }
            }
        };
        store.port_mut().script.after.insert(index, Box::new(edit));
    }

    fn corrupt_after(store: &mut Self::Store, index: usize) {
        let edit = |ruleset: &mut NftRuleset| {
            ruleset.push_rule(
                "inet",
                "yougori",
                "perimeter",
                Some("added by hand"),
                vec![json!({"accept": null})],
            );
        };
        store.port_mut().script.after.insert(index, Box::new(edit));
    }

    fn outside(store: &Self::Store) -> String {
        let tables: Vec<_> = store
            .port()
            .ruleset
            .tables
            .iter()
            .filter(|table| !(table.family == "inet" && table.name == "yougori"))
            .collect();
        format!("{tables:?}")
    }
}

#[test]
fn renders_each_identity_kind_as_nft_json() {
    let uid = NftSelector::SocketUid { uid: 961 };
    assert_eq!(
        rule_statements(&uid, &allow("192.0.2.0", 24, 443)),
        vec![
            skuid(961),
            json!({"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": {"prefix": {"addr": "192.0.2.0", "len": 24}}}}),
            json!({"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": {"set": ["tcp", "udp"]}}}),
            json!({"match": {"op": "==", "left": {"payload": {"protocol": "th", "field": "dport"}}, "right": 443}}),
            json!({"accept": null}),
        ]
    );
    let cgroup = NftSelector::Cgroup {
        path: CgroupPath::new("system.slice/yougori-broker.service").unwrap(),
        uid: 963,
    };
    assert_eq!(
        rule_statements(&cgroup, &block("2001:db8::1", 128)),
        vec![
            skuid(963),
            json!({"match": {"op": "==", "left": {"socket": {"key": "cgroupv2", "level": 2}}, "right": "system.slice/yougori-broker.service"}}),
            json!({"match": {"op": "==", "left": {"payload": {"protocol": "ip6", "field": "daddr"}}, "right": "2001:db8::1"}}),
            json!({"drop": null}),
        ]
    );
    let namespace = NftSelector::Namespace {
        name: NamespaceName::new("yougori-broker").unwrap(),
    };
    assert_eq!(
        rule_statements(&namespace, &block("::", 0)),
        vec![
            json!({"match": {"op": "==", "left": {"meta": {"key": "nfproto"}}, "right": "ipv6"}}),
            json!({"drop": null}),
        ]
    );
    assert_eq!(
        isolation_statements(&uid),
        vec![skuid(961), json!({"drop": null})]
    );
    assert_eq!(
        isolation_statements(&namespace),
        vec![json!({"drop": null})]
    );
    // A cgroup binding's isolation matches its account alone.
    assert_eq!(
        isolation_statements(&cgroup),
        vec![skuid(963), json!({"drop": null})]
    );
}

#[test]
fn every_write_is_one_batch_in_the_owned_chain_and_order_carries_the_model() {
    let (installer, store, _) = installed::<NftBench>();
    assert_eq!(
        store.list_invocation().argv,
        ["nft", "-j", "list", "table", "inet", "yougori"]
    );
    let writes = &store.port().writes;
    // The isolation, then one write per rule.
    assert_eq!(writes.len(), 1 + old_rules().len());
    let isolation_handle = chain(store.port())
        .rules
        .last()
        .map(|rule| rule.handle)
        .unwrap();
    for invocation in &writes[1..] {
        assert_eq!(invocation.argv, ["nft", "-j", "-f", "-"]);
        let batch: Value = serde_json::from_str(invocation.input.as_deref().unwrap()).unwrap();
        let commands = batch["nftables"].as_array().unwrap();
        assert_eq!(commands.len(), 1);
        let (verb, rule) = commands[0].as_object().unwrap().iter().next().unwrap();
        assert_eq!(verb, "insert");
        let rule = &rule["rule"];
        assert_eq!(
            (&rule["family"], &rule["table"], &rule["chain"]),
            (&json!("inet"), &json!("yougori"), &json!("perimeter"))
        );
        let comment = rule["comment"].as_str().unwrap();
        assert!(comment.starts_with(&format!("yg1 {}:1:", perimeter().digest().to_hex())));
        assert!(comment.len() <= 128);
        // An allow goes just before the isolation rule; a block goes to the head.
        match rule["expr"].as_array().unwrap().last().unwrap() {
            verdict if *verdict == json!({"accept": null}) => {
                assert_eq!(rule["handle"], json!(isolation_handle))
            }
            _ => assert!(rule.get("handle").is_none()),
        }
    }
    let verdicts: Vec<&Value> = chain(store.port())
        .rules
        .iter()
        .map(|rule| rule.expr.last().unwrap())
        .collect();
    let (drop, accept) = (json!({"drop": null}), json!({"accept": null}));
    assert_eq!(
        verdicts,
        vec![&drop, &drop, &accept, &accept, &accept, &drop]
    );
    let last = chain(store.port()).rules.last().unwrap();
    assert_eq!(
        last.comment.as_deref(),
        Some(format!("yg1 isolate {}", broker().identity.to_hex()).as_str())
    );
    // Each owned rule's comment names the handle the journal recorded.
    for handle in installer.journal().owned().keys() {
        assert!(chain(store.port()).rules.iter().any(|rule| rule
            .comment
            .as_deref()
            .unwrap()
            .ends_with(&format!(":{}", handle.get()))));
    }
}

#[test]
fn look_alikes_outside_the_owned_table_are_never_read_or_removed() {
    let (installer, mut store, _) = installed::<NftBench>();
    let snapshot = store.snapshot().unwrap();
    assert_eq!(snapshot.entries.len(), old_rules().len());
    // The first rule's marker appears three times on the machine but once in the store.
    let forged = first_marker();
    let ours: Vec<&RuleHandle> = installer
        .journal()
        .owned()
        .keys()
        .filter(|handle| forged.ends_with(&format!(":{}", handle.get())))
        .collect();
    assert_eq!(ours.len(), 1);
    // A marker forged in another table with a handle the store does not hold names
    // nothing the store can remove.
    let lonely = format!("yg1 {}:1:4242", perimeter().digest().to_hex());
    store.port_mut().ruleset.push_rule(
        "inet",
        "yougori-shadow",
        "perimeter",
        Some(&lonely),
        vec![json!({"drop": null})],
    );
    let writes = NftBench::writes(&store);
    assert_eq!(
        store.remove(
            &removal_grant([RuleHandle::new(4242)]),
            RuleHandle::new(4242)
        ),
        Err(StoreFailure::UnknownHandle {
            handle: RuleHandle::new(4242)
        })
    );
    assert_eq!(NftBench::writes(&store), writes);
    assert_eq!(store.snapshot().unwrap(), snapshot);
}

#[test]
fn an_unmarked_rule_in_the_owned_table_refuses_reads_and_writes() {
    let (installer, mut store, _) = installed::<NftBench>();
    store.port_mut().ruleset.push_rule(
        "inet",
        "yougori",
        "perimeter",
        None,
        vec![json!({"accept": null})],
    );
    assert!(matches!(
        store.read(),
        Err(ReadError::Refused {
            problem: ReadProblem::Unmarked,
            ..
        })
    ));
    let writes = NftBench::writes(&store);
    assert_eq!(
        installer
            .prepare(
                &store,
                &profile(PerimeterPlatform::Linux, broker(), new_rules()),
                broker()
            )
            .unwrap_err(),
        InstallRefusal::Store {
            failure: StoreFailure::Unavailable
        }
    );
    let handles: Vec<RuleHandle> = installer.journal().owned().keys().copied().collect();
    let grant = removal_grant(handles.clone());
    for handle in handles {
        assert_eq!(store.remove(&grant, handle), Err(StoreFailure::Unavailable));
    }
    assert_eq!(
        store.isolate(broker().identity),
        Err(StoreFailure::Unavailable)
    );
    assert_eq!(NftBench::writes(&store), writes);
}

#[test]
fn a_misordered_chain_does_not_isolate_the_broker() {
    // The isolation rule ahead of the broker's rules would drop what they allow.
    let (installer, mut store, _) = installed::<NftBench>();
    let rules = &mut store
        .port_mut()
        .ruleset
        .table_mut("inet", "yougori")
        .unwrap()
        .chain_mut("perimeter")
        .unwrap()
        .rules;
    let isolation = rules.pop().unwrap();
    rules.insert(0, isolation);
    let snapshot = store.snapshot().unwrap();
    assert!(!snapshot.isolated.contains(&broker().identity));
    assert_eq!(owned(&snapshot), scoped(broker().identity, &old_rules()));
    assert_eq!(
        installer
            .prepare(
                &store,
                &profile(PerimeterPlatform::Linux, broker(), new_rules()),
                broker()
            )
            .unwrap_err(),
        InstallRefusal::ScopeNotIsolated
    );

    // An allow ahead of a block would let the allow win.
    let (_, mut store, _) = installed::<NftBench>();
    let rules = &mut store
        .port_mut()
        .ruleset
        .table_mut("inet", "yougori")
        .unwrap()
        .chain_mut("perimeter")
        .unwrap()
        .rules;
    rules.swap(0, 2);
    assert!(!store
        .snapshot()
        .unwrap()
        .isolated
        .contains(&broker().identity));
}

#[test]
fn a_namespace_binding_runs_every_command_in_the_namespace() {
    let broker = BrokerIdentity {
        kind: IdentityKind::NetworkNamespace,
        identity: id("namespaced broker"),
    };
    let binding = Binding {
        broker,
        selector: NftSelector::Namespace {
            name: NamespaceName::new("yougori-broker").unwrap(),
        },
    };
    let port = FakeNft {
        namespace: Some("yougori-broker".to_owned()),
        ..FakeNft::default()
    };
    let mut store = NftStore::new(port, vec![binding]).unwrap();
    store.isolate(broker.identity).unwrap();
    let mut installer = Installer::new(perimeter());
    let mut journal = FakeJournal::default();
    install(
        &mut installer,
        &mut store,
        &mut journal,
        PerimeterPlatform::Linux,
        broker,
        old_rules(),
    )
    .unwrap();
    let snapshot = store.snapshot().unwrap();
    assert_eq!(owned(&snapshot), scoped(broker.identity, &old_rules()));
    assert!(snapshot.isolated.contains(&broker.identity));
    assert_eq!(
        store.list_invocation().argv[..5],
        ["ip", "netns", "exec", "yougori-broker", "nft"]
    );
    assert!(store
        .port()
        .writes
        .iter()
        .all(|invocation| invocation.argv[..4] == ["ip", "netns", "exec", "yougori-broker"]));
}

/// A listing after installing the old rules: metainfo, table, chain, then the rules in
/// chain order (two blocks, three allows, the isolation rule).
fn good_listing() -> Value {
    let (_, store, _) = installed::<NftBench>();
    let text = store.port().read(&store.list_invocation()).unwrap();
    serde_json::from_str(&text).unwrap()
}

fn refusal(listing: &Value, edit: impl FnOnce(&mut Vec<Value>)) -> ReadError {
    let mut items = listing["nftables"].as_array().unwrap().clone();
    edit(&mut items);
    let text = json!({ "nftables": items }).to_string();
    parse_listing(&text, &bind(vec![binding()]).unwrap()).unwrap_err()
}

fn at(item: usize, problem: ReadProblem) -> ReadError {
    ReadError::Refused { item, problem }
}

#[test]
fn malformed_listings_are_refused_not_guessed() {
    use ReadProblem as P;
    let listing = good_listing();
    let bindings = bind(vec![binding()]).unwrap();
    assert!(parse_listing(&listing.to_string(), &bindings).is_ok());
    assert_eq!(
        parse_listing("not json", &bindings).unwrap_err(),
        at(0, P::Malformed)
    );
    let mut extra = listing.clone();
    extra["extra"] = json!(1);
    assert_eq!(
        parse_listing(&extra.to_string(), &bindings).unwrap_err(),
        at(0, P::Malformed)
    );
    // Items 3 to 8: block 169.254.169.254/32, block 10.0.0.0/8, three allows, isolation.
    type Edit = Box<dyn FnOnce(&mut Vec<Value>)>;
    let cases: Vec<(Edit, ReadError)> = vec![
        (
            Box::new(|items: &mut Vec<Value>| {
                items.remove(0);
            }),
            at(0, P::Malformed),
        ),
        (
            Box::new(|items: &mut Vec<Value>| {
                items.push(json!({"set": {"family": "inet", "table": "yougori", "name": "s"}}))
            }),
            at(9, P::Malformed),
        ),
        (
            Box::new(|items: &mut Vec<Value>| items[1]["table"]["name"] = json!("other")),
            at(1, P::WrongObject),
        ),
        (
            Box::new(|items: &mut Vec<Value>| items[2]["chain"]["policy"] = json!("drop")),
            at(2, P::ObjectShape),
        ),
        (
            Box::new(|items: &mut Vec<Value>| {
                let mut second = items[2].clone();
                second["chain"]["name"] = json!("second");
                items.insert(3, second);
            }),
            at(3, P::ObjectShape),
        ),
        (
            // The chain listed before its table.
            Box::new(|items: &mut Vec<Value>| {
                items.remove(1);
            }),
            at(1, P::OutOfOrder),
        ),
        (
            // A rule listed before its chain.
            Box::new(|items: &mut Vec<Value>| {
                let rule = items.remove(3);
                items.insert(2, rule);
            }),
            at(2, P::OutOfOrder),
        ),
        (
            Box::new(|items: &mut Vec<Value>| items[3]["rule"]["table"] = json!("filter")),
            at(3, P::WrongObject),
        ),
        (
            Box::new(|items: &mut Vec<Value>| items[3]["rule"]["index"] = json!(0)),
            at(3, P::Malformed),
        ),
        (
            Box::new(|items: &mut Vec<Value>| {
                let comment = items[3]["rule"]["comment"].as_str().unwrap().to_uppercase();
                items[3]["rule"]["comment"] = json!(comment.replacen("YG1", "yg1", 1));
            }),
            at(3, P::BadMarker),
        ),
        (
            Box::new(|items: &mut Vec<Value>| items[3]["rule"]["comment"] = json!("yg1 nonsense")),
            at(3, P::BadMarker),
        ),
        (
            Box::new(|items: &mut Vec<Value>| {
                items[3]["rule"].as_object_mut().unwrap().remove("comment");
            }),
            at(3, P::Unmarked),
        ),
        (
            Box::new(|items: &mut Vec<Value>| items[3]["rule"]["comment"] = json!("ssh")),
            at(3, P::Unmarked),
        ),
        (
            Box::new(|items: &mut Vec<Value>| {
                items[3]["rule"]["expr"]
                    .as_array_mut()
                    .unwrap()
                    .insert(1, json!({"counter": null}))
            }),
            at(3, P::NotRendered),
        ),
        (
            Box::new(|items: &mut Vec<Value>| items[3]["rule"]["expr"][0] = skuid(962)),
            at(3, P::NotRendered),
        ),
        (
            // A /32 spelled as a prefix object, which nft never prints.
            Box::new(|items: &mut Vec<Value>| {
                items[3]["rule"]["expr"][1]["match"]["right"] =
                    json!({"prefix": {"addr": "169.254.169.254", "len": 32}})
            }),
            at(3, P::NotRendered),
        ),
        (
            // 10.0.0.0/8 with a host bit set.
            Box::new(|items: &mut Vec<Value>| {
                items[4]["rule"]["expr"][1]["match"]["right"]["prefix"]["addr"] = json!("10.0.0.1")
            }),
            at(4, P::NotRendered),
        ),
        (
            Box::new(|items: &mut Vec<Value>| {
                let mut copy = items[3].clone();
                copy["rule"]["handle"] = json!(999);
                items.insert(4, copy);
            }),
            at(4, P::DuplicateHandle),
        ),
        (
            Box::new(|items: &mut Vec<Value>| {
                let mut copy = items[8].clone();
                copy["rule"]["handle"] = json!(999);
                items.push(copy);
            }),
            at(9, P::DuplicateIsolation),
        ),
        (
            Box::new(|items: &mut Vec<Value>| {
                items[8]["rule"]["comment"] =
                    json!(format!("yg1 isolate {}", id("stranger").to_hex()))
            }),
            at(8, P::UnboundIdentity),
        ),
        (
            Box::new(|items: &mut Vec<Value>| items[8]["rule"]["expr"] = json!([{"accept": null}])),
            at(8, P::NotRendered),
        ),
    ];
    for (index, (edit, expected)) in cases.into_iter().enumerate() {
        assert_eq!(refusal(&listing, edit), expected, "case {index}");
    }
}

#[test]
fn bindings_are_checked() {
    let store = |bindings| NftStore::new(FakeNft::default(), bindings).err();
    let uid = |uid| NftSelector::SocketUid { uid };
    assert_eq!(
        store(vec![Binding {
            broker: broker(),
            selector: uid(0)
        }]),
        Some(BindingError::PrivilegedAccount { uid: 0 })
    );
    for kind in [
        IdentityKind::ServiceSid,
        IdentityKind::UserAccount,
        IdentityKind::ProcessId,
        IdentityKind::Cgroup,
    ] {
        assert_eq!(
            store(vec![Binding {
                broker: BrokerIdentity {
                    kind,
                    identity: id("broker")
                },
                selector: uid(961)
            }]),
            Some(BindingError::KindMismatch {
                broker: kind,
                selector: IdentityKind::DedicatedAccount
            })
        );
    }
    let other = BrokerIdentity {
        kind: IdentityKind::DedicatedAccount,
        identity: id("other broker"),
    };
    assert_eq!(
        store(vec![
            binding(),
            Binding {
                broker: other,
                selector: uid(961)
            }
        ]),
        Some(BindingError::OverlappingSelector {
            identity: other.identity
        })
    );
    // A cgroup binding names an account too, which must not be root.
    let cgroup = |path: &str, uid| NftSelector::Cgroup {
        path: CgroupPath::new(path).unwrap(),
        uid,
    };
    let in_cgroup = BrokerIdentity {
        kind: IdentityKind::Cgroup,
        identity: id("cgroup broker"),
    };
    assert_eq!(
        store(vec![Binding {
            broker: in_cgroup,
            selector: cgroup("yougori.slice", 0)
        }]),
        Some(BindingError::PrivilegedAccount { uid: 0 })
    );
    // One account under two identities overlaps whatever else the selectors name.
    assert_eq!(
        store(vec![
            binding(),
            Binding {
                broker: in_cgroup,
                selector: cgroup("yougori.slice", 961)
            }
        ]),
        Some(BindingError::OverlappingSelector {
            identity: in_cgroup.identity
        })
    );
    assert_eq!(
        store(vec![
            binding(),
            Binding {
                broker: broker(),
                selector: uid(962)
            }
        ]),
        Some(BindingError::DuplicateIdentity {
            identity: broker().identity
        })
    );
    let namespace = Binding {
        broker: BrokerIdentity {
            kind: IdentityKind::NetworkNamespace,
            identity: id("namespaced broker"),
        },
        selector: NftSelector::Namespace {
            name: NamespaceName::new("yougori-broker").unwrap(),
        },
    };
    assert_eq!(
        store(vec![binding(), namespace]),
        Some(BindingError::NamespaceNotAlone)
    );
    for path in [
        "",
        "/system.slice",
        "system.slice/",
        "a//b",
        "a/../b",
        "a b",
        "a/\u{e9}",
    ] {
        assert_eq!(
            CgroupPath::new(path),
            Err(BindingError::InvalidName),
            "{path:?}"
        );
    }
    assert_eq!(
        CgroupPath::new("system.slice/yougori-broker.service")
            .unwrap()
            .level(),
        2
    );
    for name in ["", ".", "..", "a/b", "x".repeat(65).as_str()] {
        assert_eq!(
            NamespaceName::new(name),
            Err(BindingError::InvalidName),
            "{name:?}"
        );
    }
}

/// Two cgroup bindings where one path is an ancestor of the other: `socket cgroupv2 level
/// 1 "yougori.slice"` matches every socket below it, the child broker's included, so the
/// store binds at most one of them (review R10's nested-cgroup case).
#[test]
fn nested_cgroups_are_refused() {
    let parent = BrokerIdentity {
        kind: IdentityKind::Cgroup,
        identity: id("parent broker"),
    };
    let child = BrokerIdentity {
        kind: IdentityKind::Cgroup,
        identity: id("child broker"),
    };
    let bind_both = |first: &str, second: &str| {
        let binding = |broker, path: &str, uid| Binding {
            broker,
            selector: NftSelector::Cgroup {
                path: CgroupPath::new(path).unwrap(),
                uid,
            },
        };
        NftStore::new(
            FakeNft::default(),
            vec![binding(parent, first, 961), binding(child, second, 962)],
        )
        .err()
    };
    for (first, second) in [
        ("yougori.slice", "yougori.slice/child.scope"),
        ("yougori.slice/child.scope", "yougori.slice"),
        ("yougori.slice", "yougori.slice"),
    ] {
        assert_eq!(
            bind_both(first, second),
            Some(BindingError::OverlappingSelector {
                identity: child.identity
            }),
            "{first} {second}"
        );
    }
    // Siblings, and a name that merely starts with the other's, do not nest.
    for (first, second) in [
        ("yougori.slice/a.scope", "yougori.slice/b.scope"),
        ("yougori.slice/a", "yougori.slice/ab"),
    ] {
        assert_eq!(bind_both(first, second), None, "{first} {second}");
    }
}

/// A cgroup binding's rules match its account and its cgroup, and its isolation rule the
/// account alone: after a restart that recreates the cgroup, the rules no longer match and
/// the isolation rule still drops everything. The stale rules, which we expect nft to list
/// with the old cgroup's numeric id, refuse the read.
#[test]
fn a_cgroup_binding_stays_isolated_by_its_account() {
    let broker = BrokerIdentity {
        kind: IdentityKind::Cgroup,
        identity: id("cgroup broker"),
    };
    let binding = Binding {
        broker,
        selector: NftSelector::Cgroup {
            path: CgroupPath::new("system.slice/yougori-broker.service").unwrap(),
            uid: 963,
        },
    };
    let mut store = NftStore::new(FakeNft::default(), vec![binding]).unwrap();
    store.isolate(broker.identity).unwrap();
    let mut installer = Installer::new(perimeter());
    let mut journal = FakeJournal::default();
    install(
        &mut installer,
        &mut store,
        &mut journal,
        PerimeterPlatform::Linux,
        broker,
        old_rules(),
    )
    .unwrap();
    let snapshot = store.snapshot().unwrap();
    assert_eq!(owned(&snapshot), scoped(broker.identity, &old_rules()));
    assert!(snapshot.isolated.contains(&broker.identity));
    let (isolation, rules) = chain(store.port()).rules.split_last().unwrap();
    assert_eq!(isolation.expr, vec![skuid(963), json!({"drop": null})]);
    assert_eq!(rules.len(), old_rules().len());
    for rule in rules {
        assert_eq!(rule.expr[0], skuid(963));
        assert_eq!(rule.expr[1]["match"]["left"]["socket"]["key"], "cgroupv2");
    }

    let rules = &mut store
        .port_mut()
        .ruleset
        .table_mut("inet", "yougori")
        .unwrap()
        .chain_mut("perimeter")
        .unwrap()
        .rules;
    for statement in rules.iter_mut().flat_map(|rule| rule.expr.iter_mut()) {
        if statement["match"]["left"]["socket"]["key"] == "cgroupv2" {
            statement["match"]["right"] = json!(4242);
        }
    }
    assert!(matches!(
        store.read(),
        Err(ReadError::Refused {
            problem: ReadProblem::NotRendered,
            ..
        })
    ));
}

/// `isolate` writes over a listing it accepts, or when the list of tables proves the owned
/// table absent; any other read that fails or is refused writes nothing.
#[test]
fn isolate_never_writes_when_it_cannot_read() {
    let (_, mut store, _) = installed::<NftBench>();
    let writes = NftBench::writes(&store);
    // Listing the owned table fails, and the list of tables shows that it exists.
    store.port_mut().refuse_list_table = true;
    assert_eq!(
        store.isolate(broker().identity),
        Err(StoreFailure::Rejected)
    );
    // The list of tables fails too.
    store.port_mut().refuse_list_tables = true;
    assert_eq!(
        store.isolate(broker().identity),
        Err(StoreFailure::Rejected)
    );
    // No read runs at all.
    store.port_mut().script.unreadable = true;
    assert_eq!(
        store.isolate(broker().identity),
        Err(StoreFailure::Unavailable)
    );
    assert_eq!(NftBench::writes(&store), writes);

    // A listing the parser refuses is never written over either.
    let (_, mut store, _) = installed::<NftBench>();
    store.port_mut().ruleset.push_rule(
        "inet",
        "yougori",
        "perimeter",
        Some("added by hand"),
        vec![json!({"accept": null})],
    );
    let writes = NftBench::writes(&store);
    assert_eq!(
        store.isolate(broker().identity),
        Err(StoreFailure::Unavailable)
    );
    assert_eq!(NftBench::writes(&store), writes);

    // A table of the same name in another family is not the owned one: the list of tables
    // proves the owned table absent, so isolate provisions it.
    let mut store = NftStore::new(FakeNft::default(), vec![binding()]).unwrap();
    store.port_mut().ruleset.push_rule(
        "ip",
        "yougori",
        "perimeter",
        None,
        vec![json!({"accept": null})],
    );
    store.isolate(broker().identity).unwrap();
    assert_eq!(store.port().writes.len(), 1);
    assert!(store
        .snapshot()
        .unwrap()
        .isolated
        .contains(&broker().identity));
}

#[test]
fn the_list_of_tables_is_read_strictly() {
    use super::super::nft::lists_owned_table;
    let listing = |tables: Vec<Value>| {
        let mut items = vec![
            json!({"metainfo": {"version": "1.1.1", "release_name": "r", "json_schema_version": 1}}),
        ];
        items.extend(tables);
        json!({ "nftables": items }).to_string()
    };
    assert_eq!(lists_owned_table(&listing(Vec::new())), Ok(false));
    assert_eq!(
        lists_owned_table(&listing(vec![
            json!({"table": {"family": "ip", "name": "yougori", "handle": 1}}),
            json!({"table": {"family": "inet", "name": "filter", "handle": 2, "flags": ["owner"]}}),
        ])),
        Ok(false)
    );
    assert_eq!(
        lists_owned_table(&listing(vec![
            json!({"table": {"family": "inet", "name": "yougori", "handle": 3}})
        ])),
        Ok(true)
    );
    for text in [
        String::new(),
        "[]".to_owned(),
        json!({"nftables": []}).to_string(),
        json!({"nftables": [{"table": {"family": "inet", "name": "x", "handle": 1}}]}).to_string(),
        listing(vec![
            json!({"chain": {"family": "inet", "table": "x", "name": "c", "handle": 2}}),
        ]),
        listing(vec![json!({"table": {"family": "inet", "handle": 3}})]),
    ] {
        assert!(lists_owned_table(&text).is_err(), "{text}");
    }
}
