//! The pf store: it never reports the broker isolated, since ICMP escapes pf's `user`
//! match, so V16 refuses to install over it; the store's own rendering in pfctl's printed
//! form, its adds and removes driven directly with a grant, the anchor name, other anchors
//! and the main ruleset left alone, ports printed as service names, and the listings it
//! refuses.

use std::collections::BTreeSet;

use super::super::common::{allocate_handle, bind, short_owned_marker};
use super::super::fakes::FakePf;
use super::super::pf::{deny_lines, parse_anchor, rule_lines};
use super::*;
use crate::foundation::ids::Digest;
use crate::sandbox_contract::perimeter_install::{IdentityKind, InstallRefusal, OwnedRule};

const UID: u32 = 498;

pub fn broker() -> BrokerIdentity {
    BrokerIdentity {
        kind: IdentityKind::SigningIdentity,
        identity: id("macos broker"),
    }
}

pub fn binding() -> Binding<PfSelector> {
    Binding {
        broker: broker(),
        selector: PfSelector::User { uid: UID },
    }
}

fn anchor() -> String {
    PfAnchor::for_perimeter(perimeter()).as_str().to_owned()
}

fn first_label() -> String {
    let tag = OwnerTag {
        perimeter: perimeter(),
        transaction: TransactionId::FIRST,
    };
    short_owned_marker(
        tag.transaction,
        allocate_handle(tag, &BTreeSet::new()).unwrap(),
    )
}

fn lines(store: &PfStore<FakePf>) -> Vec<String> {
    store
        .port()
        .state
        .anchors
        .get(&anchor())
        .cloned()
        .unwrap_or_default()
}

fn writes(store: &PfStore<FakePf>) -> usize {
    store.port().script.writes()
}

/// A store whose anchor holds the broker's TCP and UDP deny, with the main ruleset and
/// another perimeter's anchor carrying the first rule's label forged.
pub fn store() -> PfStore<FakePf> {
    let mut port = FakePf::default();
    let label = first_label();
    port.state.main = vec![
        "anchor \"yougori/*\"".to_owned(),
        format!("pass out quick proto tcp all user = {UID} label \"{label}\""),
    ];
    let other = PfAnchor::for_perimeter(PerimeterId::new(id("other perimeter")));
    port.state.anchors.insert(
        other.as_str().to_owned(),
        rule_lines(UID, &block("10.0.0.0", 8), &label).to_vec(),
    );
    let mut store = PfStore::new(port, perimeter(), vec![binding()]).unwrap();
    store.add_tcp_udp_deny(broker().identity).unwrap();
    store
}

/// Everything outside the store's anchor.
fn outside(store: &PfStore<FakePf>) -> String {
    let state = &store.port().state;
    let anchors: Vec<_> = state
        .anchors
        .iter()
        .filter(|(name, _)| **name != anchor())
        .collect();
    format!("{:?} {anchors:?}", state.main)
}

/// A grant that adds `rules` for the broker under transaction 1.
fn grant_for(rules: &[PerimeterRule]) -> ElevationGrant {
    ElevationGrant {
        tag: OwnerTag {
            perimeter: perimeter(),
            transaction: TransactionId::FIRST,
        },
        plan: id("plan"),
        may_add: scoped(broker().identity, rules),
        may_remove: BTreeSet::new(),
    }
}

/// [`store`] with `rules` added directly under [`grant_for`], since V16 does not install
/// over pf; with the handles in order.
fn loaded(rules: &[PerimeterRule]) -> (PfStore<FakePf>, Vec<RuleHandle>) {
    let mut store = store();
    let grant = grant_for(rules);
    let handles = rules
        .iter()
        .map(|rule| {
            let scoped = ScopedRule {
                identity: broker().identity,
                rule: *rule,
            };
            store
                .add(
                    &grant,
                    &OwnedRule {
                        tag: grant.tag,
                        scoped,
                    },
                )
                .unwrap()
        })
        .collect();
    (store, handles)
}

/// pf's `user` match covers TCP and UDP sockets only, and ICMP from a datagram socket gets
/// through, so the store never reports the broker isolated and V16 refuses to install,
/// before writing anything (review R10's pf rollback case: no install starts, so there is
/// nothing to roll back).
#[test]
fn the_installer_refuses_pf_because_icmp_escapes() {
    let store = store();
    assert!(store.denies_tcp_udp(broker().identity).unwrap());
    let snapshot = store.snapshot().unwrap();
    assert!(snapshot.isolated.is_empty());
    assert_eq!(
        snapshot.permits(broker().identity, "192.0.2.9".parse().unwrap(), port(443)),
        None
    );
    let before = writes(&store);
    let installer = Installer::new(perimeter());
    assert_eq!(
        installer
            .prepare(
                &store,
                &profile(PerimeterPlatform::MacOs, broker(), old_rules()),
                broker()
            )
            .unwrap_err(),
        InstallRefusal::ScopeNotIsolated
    );
    assert_eq!(writes(&store), before);
    assert!(installer.settled());

    // Rules added directly do not make it isolated either.
    let (store, _) = loaded(&old_rules());
    let snapshot = store.snapshot().unwrap();
    assert_eq!(owned(&snapshot), scoped(broker().identity, &old_rules()));
    assert!(snapshot.isolated.is_empty());
}

#[test]
fn renders_rules_as_pfctl_prints_them() {
    let label = "yg1 1:5";
    assert_eq!(
        rule_lines(UID, &block("10.0.0.0", 8), label),
        [
            "block drop out quick inet proto tcp from any to 10.0.0.0/8 user = 498 label \"yg1 1:5\"",
            "block drop out quick inet proto udp from any to 10.0.0.0/8 user = 498 label \"yg1 1:5\"",
        ]
    );
    assert_eq!(
        rule_lines(UID, &allow("198.51.100.7", 32, 443), label),
        [
            "pass out quick inet proto tcp from any to 198.51.100.7 port = 443 user = 498 flags S/SA keep state label \"yg1 1:5\"",
            "pass out quick inet proto udp from any to 198.51.100.7 port = 443 user = 498 keep state label \"yg1 1:5\"",
        ]
    );
    assert_eq!(
        rule_lines(UID, &allow_all("2001:db8::", 32), label)[0],
        "pass out quick inet6 proto tcp from any to 2001:db8::/32 user = 498 flags S/SA keep state label \"yg1 1:5\""
    );
    // `from any to any` with no port prints as `all`; with a port it does not.
    assert_eq!(
        rule_lines(UID, &block("::", 0), label)[1],
        "block drop out quick inet6 proto udp all user = 498 label \"yg1 1:5\""
    );
    assert_eq!(
        rule_lines(UID, &allow("0.0.0.0", 0, 53), label)[1],
        "pass out quick inet proto udp from any to any port = 53 user = 498 keep state label \"yg1 1:5\""
    );
    assert_eq!(
        deny_lines(UID),
        [
            "block drop out quick proto tcp all user = 498 label \"yg1 isolate\"",
            "block drop out quick proto udp all user = 498 label \"yg1 isolate\"",
        ]
    );
}

#[test]
fn an_anchor_names_its_perimeter_in_base32() {
    let zero = PfAnchor::for_perimeter(PerimeterId::new(Digest::from_bytes([0; 32])));
    assert_eq!(zero.as_str(), format!("yougori/{}", "a".repeat(52)));
    let ones = PfAnchor::for_perimeter(PerimeterId::new(Digest::from_bytes([0xff; 32])));
    assert_eq!(ones.as_str(), format!("yougori/{}q", "7".repeat(51)));
    let name = anchor();
    let component = name.strip_prefix("yougori/").unwrap();
    assert_eq!(component.len(), 52);
    assert!(component
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte)));
    assert_ne!(
        PfAnchor::for_perimeter(PerimeterId::new(id("other perimeter"))).as_str(),
        name
    );
}

#[test]
fn the_anchor_is_loaded_whole_in_order() {
    let (store, _) = loaded(&old_rules());
    assert_eq!(
        store.list_invocation().argv,
        ["pfctl", "-a", anchor().as_str(), "-sr"]
    );
    let loads = &store.port().loads;
    assert_eq!(loads.len(), 1 + old_rules().len());
    for load in loads {
        assert_eq!(load.argv, ["pfctl", "-a", anchor().as_str(), "-f", "-"]);
    }
    let lines = lines(&store);
    assert_eq!(lines.len(), 2 * old_rules().len() + 2);
    assert!(lines[..4]
        .iter()
        .all(|line| line.starts_with("block drop out quick inet ")));
    assert!(lines[4..10]
        .iter()
        .all(|line| line.starts_with("pass out quick ")));
    assert_eq!(lines[10..], deny_lines(UID));
    for line in &lines {
        let label = line.rsplit_once(" label \"").unwrap().1;
        assert!(label.len() <= PF_LABEL_MAX + 1);
    }
}

#[test]
fn adds_and_removes_only_in_its_anchor_and_only_as_granted() {
    let outside_before = outside(&store());
    let (mut store, handles) = loaded(&new_rules());
    // `block ::/0` round trips through `all`.
    assert!(lines(&store)
        .iter()
        .any(|line| line.starts_with("block drop out quick inet6 proto tcp all user = 498")));
    assert_eq!(
        owned(&store.snapshot().unwrap()),
        scoped(broker().identity, &new_rules())
    );
    let before = writes(&store);
    // A later transaction's grant that lists no removal.
    let grant = ElevationGrant {
        tag: OwnerTag {
            perimeter: perimeter(),
            transaction: TransactionId::new(2),
        },
        ..grant_for(&new_rules())
    };
    let unlisted = OwnedRule {
        tag: grant.tag,
        scoped: ScopedRule {
            identity: broker().identity,
            rule: allow("8.8.8.8", 32, 53),
        },
    };
    assert_eq!(store.add(&grant, &unlisted), Err(StoreFailure::NotGranted));
    assert_eq!(
        store.remove(&grant, handles[0]),
        Err(StoreFailure::NotGranted)
    );
    assert_eq!(writes(&store), before);
    let removal = removal_grant([handles[0]]);
    store.remove(&removal, handles[0]).unwrap();
    assert_eq!(
        owned(&store.snapshot().unwrap()),
        scoped(broker().identity, &new_rules()[1..])
    );
    assert!(store.denies_tcp_udp(broker().identity).unwrap());
    assert_eq!(outside(&store), outside_before);
}

#[test]
fn a_line_this_product_did_not_render_refuses_reads_and_writes() {
    let (mut store, handles) = loaded(&old_rules());
    let name = anchor();
    store
        .port_mut()
        .state
        .anchors
        .get_mut(&name)
        .unwrap()
        .push(format!(
            "pass out quick proto tcp all user = {UID} label \"vpn\""
        ));
    assert!(matches!(
        store.read(),
        Err(ReadError::Refused {
            problem: ReadProblem::Unmarked,
            ..
        })
    ));
    let before = writes(&store);
    let grant = removal_grant(handles.clone());
    for handle in handles {
        assert_eq!(store.remove(&grant, handle), Err(StoreFailure::Unavailable));
    }
    assert_eq!(
        store.add_tcp_udp_deny(broker().identity),
        Err(StoreFailure::Unavailable)
    );
    assert_eq!(writes(&store), before);
}

/// pfctl prints a port as the name `getservbyport` finds: the names in
/// `PF_SERVICE_NAMES` read as their numbers, and no other name is accepted.
#[test]
fn ports_printed_as_service_names_read_as_their_numbers() {
    let (store, _) = loaded(&old_rules());
    let good = store.port().read(&store.list_invocation()).unwrap();
    assert!(good.contains(" port = 443 "));
    let bindings = bind(vec![binding()]).unwrap();
    let expected = parse_anchor(&good, perimeter(), &bindings).unwrap();
    let named = good.replace(" port = 443 ", " port = https ");
    assert_eq!(parse_anchor(&named, perimeter(), &bindings), Ok(expected));
    for unknown in [" port = www ", " port = HTTPS ", " port = 0443 "] {
        let text = good.replacen(" port = 443 ", unknown, 1);
        assert!(
            matches!(
                parse_anchor(&text, perimeter(), &bindings),
                Err(ReadError::Refused {
                    problem: ReadProblem::NotRendered,
                    ..
                })
            ),
            "{unknown}"
        );
    }
    assert_eq!(
        PF_SERVICE_NAMES,
        [
            (22, "ssh"),
            (53, "domain"),
            (80, "http"),
            (123, "ntp"),
            (443, "https")
        ]
    );
}

#[test]
fn malformed_listings_are_refused_not_guessed() {
    use ReadProblem as P;
    let (store, _) = loaded(&old_rules());
    let good = store.port().read(&store.list_invocation()).unwrap();
    let bindings = bind(vec![binding()]).unwrap();
    assert!(parse_anchor(&good, perimeter(), &bindings).is_ok());
    let parse = |text: &str| parse_anchor(text, perimeter(), &bindings).unwrap_err();
    let at = |item: usize, problem: ReadProblem| ReadError::Refused { item, problem };
    let edited = |edit: &dyn Fn(&mut Vec<String>)| {
        let mut lines: Vec<String> = good.lines().map(str::to_owned).collect();
        edit(&mut lines);
        lines
            .iter()
            .map(|line| format!("{line}\n"))
            .collect::<String>()
    };
    assert_eq!(parse(good.trim_end()), at(0, P::Malformed));
    assert_eq!(parse(&good.replace('\n', "\r\n")), at(0, P::Malformed));
    let label_of = |line: &str| line.rsplit_once(" label ").unwrap().1.to_owned();
    let ten = good
        .lines()
        .position(|line| line.contains("10.0.0.0/8"))
        .unwrap();
    // Lines 0 to 9: two lines per rule, blocks first; 10 and 11: the deny.
    let cases: Vec<(String, ReadError)> = vec![
        (
            edited(&|lines: &mut Vec<String>| {
                lines.remove(1);
            }),
            at(1, P::NotRendered),
        ),
        (
            edited(&|lines: &mut Vec<String>| lines.swap(0, 4)),
            at(0, P::NotRendered),
        ),
        (
            edited(&|lines: &mut Vec<String>| {
                lines[0] = lines[0].replacen("block drop", "block  drop", 1)
            }),
            at(0, P::NotRendered),
        ),
        (
            edited(&|lines: &mut Vec<String>| {
                lines[ten] = lines[ten].replacen("10.0.0.0/8", "10.0.0.1/8", 1)
            }),
            at(ten, P::NotRendered),
        ),
        (
            // pfctl prints `all`, never `from any to any` without a port.
            edited(&|lines: &mut Vec<String>| {
                lines[10] = lines[10].replacen(" all ", " from any to any ", 1)
            }),
            at(10, P::NotRendered),
        ),
        (
            edited(&|lines: &mut Vec<String>| {
                let label = label_of(&lines[0]);
                lines[0] = lines[0].replace(&label, "\"yg1 x:1\"");
            }),
            at(0, P::BadMarker),
        ),
        (
            edited(&|lines: &mut Vec<String>| {
                let label = label_of(&lines[0]);
                lines[0] = lines[0].replace(&label, "\"vpn\"");
            }),
            at(0, P::Unmarked),
        ),
        (
            edited(&|lines: &mut Vec<String>| {
                let label = label_of(&lines[0]);
                lines[0] = lines[0].replace(&format!(" label {label}"), "");
            }),
            at(0, P::Malformed),
        ),
        (
            edited(&|lines: &mut Vec<String>| {
                lines[0] = lines[0].replace("user = 498", "user = 499")
            }),
            at(0, P::UnboundIdentity),
        ),
        (
            edited(&|lines: &mut Vec<String>| {
                let label = label_of(&lines[0]);
                let other = label_of(&lines[2]);
                lines[2] = lines[2].replace(&other, &label);
            }),
            at(2, P::DuplicateHandle),
        ),
        (
            edited(&|lines: &mut Vec<String>| {
                lines[11] = lines[11].replace("user = 498", "user = 499")
            }),
            at(11, P::UnboundIdentity),
        ),
        (
            edited(&|lines: &mut Vec<String>| {
                lines.pop();
            }),
            at(11, P::NotRendered),
        ),
    ];
    for (index, (text, expected)) in cases.into_iter().enumerate() {
        assert_eq!(parse(&text), expected, "case {index}");
    }
}

#[test]
fn only_this_perimeters_rules_fit_its_anchor() {
    let mut store = store();
    let tag = OwnerTag {
        perimeter: PerimeterId::new(id("other perimeter")),
        transaction: TransactionId::FIRST,
    };
    let scoped = ScopedRule {
        identity: broker().identity,
        rule: allow("192.0.2.0", 24, 443),
    };
    let grant = ElevationGrant {
        tag,
        plan: id("plan"),
        may_add: BTreeSet::from([scoped]),
        may_remove: BTreeSet::new(),
    };
    let before = writes(&store);
    assert_eq!(
        store.add(&grant, &OwnedRule { tag, scoped }),
        Err(StoreFailure::Rejected)
    );
    assert_eq!(writes(&store), before);
}

#[test]
fn bindings_are_checked() {
    let store = |bindings| PfStore::new(FakePf::default(), perimeter(), bindings).err();
    assert_eq!(
        store(vec![Binding {
            broker: broker(),
            selector: PfSelector::User { uid: 0 }
        }]),
        Some(BindingError::PrivilegedAccount { uid: 0 })
    );
    assert_eq!(
        store(vec![Binding {
            broker: BrokerIdentity {
                kind: IdentityKind::DedicatedAccount,
                identity: id("broker")
            },
            selector: PfSelector::User { uid: UID }
        }]),
        Some(BindingError::KindMismatch {
            broker: IdentityKind::DedicatedAccount,
            selector: IdentityKind::SigningIdentity
        })
    );
    let other = BrokerIdentity {
        kind: IdentityKind::SigningIdentity,
        identity: id("other broker"),
    };
    assert_eq!(
        store(vec![
            binding(),
            Binding {
                broker: other,
                selector: PfSelector::User { uid: UID }
            }
        ]),
        Some(BindingError::OverlappingSelector {
            identity: other.identity
        })
    );
}
