//! The WFP store: the rendered filter specifications and transactions, isolation at the
//! connect and receive/accept layers, the service SID checked against the service's
//! token, the owned sublayer's provider and weight, foreign filters (look-alikes
//! included) reported without a tag and never removed, a foreign filter on the broker,
//! overlapping SIDs refused, and the enumerations it refuses.

use std::collections::BTreeSet;
use std::net::IpAddr;

use super::super::common::{allocate_handle, bind, owned_marker};
use super::super::fakes::{FakeWfp, WfpEngine};
use super::super::wfp::{
    isolation_filter, parse_filters, rule_filter, WFP_BLOCK_WEIGHT, WFP_ISOLATION_WEIGHT,
    WFP_PERMIT_WEIGHT, WFP_PROVIDER_NAME, WFP_SUBLAYER_NAME, WFP_SUBLAYER_WEIGHT,
};
use super::scenarios::{installed, Bench};
use super::*;
use crate::sandbox_contract::perimeter_install::{
    IdentityKind, InstallRefusal, RuleScope, StoreEntry,
};

pub struct WfpBench;

pub fn sid() -> Sid {
    Sid::parse("S-1-5-80-1111111111-2222222222-3333333333-444444444-555555555").unwrap()
}

pub fn broker() -> BrokerIdentity {
    BrokerIdentity {
        kind: IdentityKind::ServiceSid,
        identity: id("windows broker"),
    }
}

pub fn service() -> ServiceName {
    ServiceName::new("YougoriBroker").unwrap()
}

pub fn selector() -> WfpSelector {
    WfpSelector::ServiceSid {
        service: service(),
        sid: sid(),
    }
}

pub fn binding() -> Binding<WfpSelector> {
    Binding {
        broker: broker(),
        selector: selector(),
    }
}

/// The Service Control Manager's answer for the broker service.
fn configured(sid_type: ServiceSidType) -> ServiceSidInfo {
    ServiceSidInfo {
        sid: sid(),
        sid_type,
    }
}

/// A port that knows the broker service, with its SID in the token.
fn port() -> FakeWfp {
    let mut port = FakeWfp::default();
    port.services.insert(
        service().as_str().to_owned(),
        configured(ServiceSidType::Unrestricted),
    );
    port
}

fn address(text: &str) -> IpAddr {
    text.parse().unwrap()
}

fn guid(last: u8) -> WfpGuid {
    WfpGuid::from_bytes([
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0, 0, 0, 0, 0, 0, 0, last,
    ])
}

/// A filter another program owns, at the IPv4 connect layer.
fn foreign(
    name: &str,
    provider: Option<WfpGuid>,
    sublayer: WfpGuid,
    conditions: Vec<WfpCondition>,
    action: WfpAction,
) -> WfpFilterSpec {
    WfpFilterSpec {
        key: guid(name.len().try_into().unwrap()),
        name: name.to_owned(),
        provider,
        sublayer,
        layer: WfpLayer::AleAuthConnectV4,
        weight: 9,
        conditions,
        action,
        flags: WfpFlags {
            persistent: true,
            clear_action_right: false,
        },
    }
}

fn first_marker() -> String {
    let tag = OwnerTag {
        perimeter: perimeter(),
        transaction: TransactionId::FIRST,
    };
    owned_marker(tag, allocate_handle(tag, &BTreeSet::new()).unwrap())
}

fn anywhere() -> WfpCondition {
    WfpCondition::RemoteAddress {
        low: address("0.0.0.0"),
        high: address("255.255.255.255"),
    }
}

impl Bench for WfpBench {
    type Store = WfpStore<FakeWfp>;
    const PLATFORM: PerimeterPlatform = PerimeterPlatform::Windows;

    fn broker() -> BrokerIdentity {
        broker()
    }

    fn store() -> Self::Store {
        let mut port = port();
        let forged = first_marker();
        let other_sid = Sid::parse("S-1-5-80-1-2-3-4-5").unwrap();
        // Another product's permit named with the first rule's marker, a filter using
        // this product's provider key in another sublayer, and a callout.
        port.engine.insert(foreign(
            &forged,
            Some(guid(1)),
            guid(2),
            vec![WfpCondition::ServiceSid { sid: other_sid }, anywhere()],
            WfpAction::Permit,
        ));
        port.engine.insert(foreign(
            &forged,
            Some(WFP_PROVIDER),
            guid(3),
            vec![anywhere()],
            WfpAction::Block,
        ));
        port.engine.insert(foreign(
            "stealth",
            None,
            guid(4),
            vec![WfpCondition::Other {
                field: guid(5),
                value: id("value"),
            }],
            WfpAction::Callout { callout: guid(6) },
        ));
        let mut store = WfpStore::new(port, vec![binding()]).unwrap();
        store.isolate(broker().identity).unwrap();
        store
    }

    fn writes(store: &Self::Store) -> usize {
        store.port().script.writes()
    }

    fn is_removal(store: &Self::Store, index: usize) -> bool {
        store.port().transactions.get(index).is_some_and(|changes| {
            changes
                .iter()
                .any(|change| matches!(change, WfpChange::DeleteFilter { .. }))
        })
    }

    fn fail_write(store: &mut Self::Store, index: usize, failure: StoreFailure) {
        store.port_mut().script.fail.insert(index, failure);
    }

    fn lossy(store: &mut Self::Store) {
        store.port_mut().script.lossy = true;
    }

    fn alter_after(store: &mut Self::Store, index: usize) {
        let edit = |engine: &mut WfpEngine| {
            let spec = engine
                .filters
                .values_mut()
                .filter(|spec| spec.sublayer == WFP_SUBLAYER && spec.name.contains(':'))
                .last()
                .unwrap();
            spec.conditions[1] = WfpCondition::RemoteAddress {
                low: address("192.0.2.77"),
                high: address("192.0.2.77"),
            };
        };
        store.port_mut().script.after.insert(index, Box::new(edit));
    }

    fn corrupt_after(store: &mut Self::Store, index: usize) {
        let edit = |engine: &mut WfpEngine| {
            engine.insert(foreign(
                "added by hand",
                Some(WFP_PROVIDER),
                WFP_SUBLAYER,
                vec![anywhere()],
                WfpAction::Permit,
            ));
        };
        store.port_mut().script.after.insert(index, Box::new(edit));
    }

    fn outside(store: &Self::Store) -> String {
        let engine = &store.port().engine;
        let filters: Vec<_> = engine
            .filters
            .iter()
            .filter(|(_, spec)| spec.sublayer != WFP_SUBLAYER)
            .collect();
        format!("{filters:?}")
    }
}

#[test]
fn renders_typed_filter_specifications() {
    let tag = OwnerTag {
        perimeter: perimeter(),
        transaction: TransactionId::new(4),
    };
    let handle = RuleHandle::new(77);
    let selector = selector();
    let filter = rule_filter(tag, handle, &selector, &block("10.0.0.0", 8));
    assert_eq!(filter.name, owned_marker(tag, handle));
    assert_eq!(filter.provider, Some(WFP_PROVIDER));
    assert_eq!(filter.sublayer, WFP_SUBLAYER);
    assert_eq!(filter.layer, WfpLayer::AleAuthConnectV4);
    assert_eq!(filter.weight, WFP_BLOCK_WEIGHT);
    assert_eq!(filter.action, WfpAction::Block);
    assert_eq!(filter.flags, WfpFlags::OWNED);
    assert_eq!(
        filter.conditions,
        vec![
            WfpCondition::ServiceSid { sid: sid() },
            WfpCondition::RemoteAddress {
                low: address("10.0.0.0"),
                high: address("10.255.255.255")
            },
        ]
    );
    // The key follows the tag's perimeter and the handle, and differs per handle.
    assert_eq!(
        filter.key,
        rule_filter(tag, handle, &selector, &allow("192.0.2.0", 24, 443)).key
    );
    assert_ne!(
        filter.key,
        rule_filter(tag, RuleHandle::new(78), &selector, &block("10.0.0.0", 8)).key
    );

    let package = WfpSelector::PackageSid {
        sid: Sid::parse("S-1-15-2-1-2-3-4-5-6-7").unwrap(),
    };
    let filter = rule_filter(tag, handle, &package, &allow("198.51.100.7", 32, 443));
    assert_eq!(filter.weight, WFP_PERMIT_WEIGHT);
    assert_eq!(filter.action, WfpAction::Permit);
    assert_eq!(
        filter.conditions,
        vec![
            WfpCondition::PackageSid {
                sid: Sid::parse("S-1-15-2-1-2-3-4-5-6-7").unwrap()
            },
            WfpCondition::RemoteAddress {
                low: address("198.51.100.7"),
                high: address("198.51.100.7")
            },
            WfpCondition::RemotePort {
                low: 443,
                high: 443
            },
        ]
    );
    let filter = rule_filter(tag, handle, &selector, &block("::", 0));
    assert_eq!(filter.layer, WfpLayer::AleAuthConnectV6);
    assert_eq!(
        filter.conditions[1],
        WfpCondition::RemoteAddress {
            low: address("::"),
            high: address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
        }
    );

    let isolation = isolation_filter(broker().identity, &selector, WfpLayer::AleAuthConnectV6);
    assert_eq!(isolation.weight, WFP_ISOLATION_WEIGHT);
    assert_eq!(isolation.action, WfpAction::Block);
    assert_eq!(
        isolation.conditions,
        vec![WfpCondition::ServiceSid { sid: sid() }]
    );
    assert_eq!(
        isolation.name,
        format!("yg1 isolate {}", broker().identity.to_hex())
    );
    const { assert!(WFP_BLOCK_WEIGHT > WFP_PERMIT_WEIGHT && WFP_PERMIT_WEIGHT > WFP_ISOLATION_WEIGHT) };
    assert_eq!(WFP_SUBLAYER_WEIGHT, u16::MAX);
    assert_eq!(
        WFP_PROVIDER.to_string(),
        "{79673170-2d70-8e72-9d69-6d6574657201}"
    );
}

#[test]
fn isolation_provisions_the_owned_objects_in_one_transaction() {
    let store = WfpBench::store();
    let transactions = &store.port().transactions;
    assert_eq!(transactions.len(), 1);
    let mut expected = vec![
        WfpChange::AddProvider {
            key: WFP_PROVIDER,
            name: WFP_PROVIDER_NAME.to_owned(),
        },
        WfpChange::AddSublayer {
            key: WFP_SUBLAYER,
            provider: WFP_PROVIDER,
            name: WFP_SUBLAYER_NAME.to_owned(),
            weight: WFP_SUBLAYER_WEIGHT,
        },
    ];
    // The default deny at the connect and the receive/accept layers, IPv4 and IPv6.
    expected.extend(WfpLayer::ALL.map(|layer| WfpChange::AddFilter {
        spec: isolation_filter(broker().identity, &selector(), layer),
    }));
    assert_eq!(transactions[0], expected);
    assert_eq!(
        WfpLayer::ALL,
        [
            WfpLayer::AleAuthConnectV4,
            WfpLayer::AleAuthConnectV6,
            WfpLayer::AleAuthRecvAcceptV4,
            WfpLayer::AleAuthRecvAcceptV6,
        ]
    );
    // Isolating again changes nothing.
    let mut store = store;
    store.isolate(broker().identity).unwrap();
    assert_eq!(store.port().transactions.len(), 1);
}

#[test]
fn filters_outside_the_owned_sublayer_are_foreign_and_never_removed() {
    let (mut installer, mut store, mut journal) = installed::<WfpBench>();
    let snapshot = store.snapshot().unwrap();
    let foreign: Vec<(&RuleHandle, &StoreEntry)> = snapshot
        .entries
        .iter()
        .filter(|(handle, _)| handle.get() & FOREIGN_HANDLE_BIT != 0)
        .collect();
    assert_eq!(foreign.len(), 3);
    for (_, entry) in &foreign {
        // Two of them carry the first rule's marker in their name; none is owned.
        assert_eq!(entry.tag, None);
        assert_eq!(entry.scope, RuleScope::Machine);
        assert!(entry.scoped().is_none());
    }
    let handles: Vec<RuleHandle> = foreign.iter().map(|(handle, _)| **handle).collect();
    let grant = removal_grant(handles.clone());
    for handle in handles {
        assert_eq!(store.remove(&grant, handle), Err(StoreFailure::NotGranted));
    }
    assert_eq!(store.port().transactions.len(), 1 + old_rules().len());
    let outside = WfpBench::outside(&store);
    teardown(&mut installer, &mut store, &mut journal).unwrap();
    assert_eq!(WfpBench::outside(&store), outside);
}

#[test]
fn a_foreign_filter_on_the_broker_blocks_the_install() {
    // Say a firewall rule another program made for the broker service.
    let mut store = WfpBench::store();
    let id_on_broker = store.port_mut().engine.insert(foreign(
        "Allow broker",
        Some(guid(7)),
        guid(8),
        vec![WfpCondition::ServiceSid { sid: sid() }, anywhere()],
        WfpAction::Permit,
    ));
    let handle = RuleHandle::new(FOREIGN_HANDLE_BIT | id_on_broker);
    let snapshot = store.snapshot().unwrap();
    assert_eq!(
        snapshot.entry(handle).map(|entry| (entry.tag, entry.scope)),
        Some((
            None,
            RuleScope::Identity {
                identity: broker().identity
            }
        ))
    );
    let installer = Installer::new(perimeter());
    assert_eq!(
        installer
            .prepare(
                &store,
                &profile(PerimeterPlatform::Windows, broker(), old_rules()),
                broker()
            )
            .unwrap_err(),
        InstallRefusal::ForeignRuleOnBroker { handle }
    );
}

#[test]
fn a_filter_in_the_owned_sublayer_this_product_did_not_render_refuses_reads() {
    let mut store = WfpBench::store();
    store.port_mut().engine.insert(foreign(
        "other provider",
        Some(guid(9)),
        WFP_SUBLAYER,
        vec![anywhere()],
        WfpAction::Permit,
    ));
    assert!(matches!(
        store.read(),
        Err(ReadError::Refused {
            problem: ReadProblem::WrongObject,
            ..
        })
    ));
    let writes = WfpBench::writes(&store);
    assert_eq!(
        store.isolate(broker().identity),
        Err(StoreFailure::Unavailable)
    );
    assert_eq!(WfpBench::writes(&store), writes);
}

fn refusal(filters: &[WfpFilter], edit: impl FnOnce(&mut Vec<WfpFilter>)) -> ReadError {
    let mut filters = filters.to_vec();
    edit(&mut filters);
    parse_filters(
        &filters,
        Some(&provisioned()),
        &bind(vec![binding()]).unwrap(),
    )
    .unwrap_err()
}

/// The owned sublayer as this module provisions it.
fn provisioned() -> WfpSublayer {
    WfpSublayer {
        key: WFP_SUBLAYER,
        provider: Some(WFP_PROVIDER),
        weight: WFP_SUBLAYER_WEIGHT,
    }
}

#[test]
fn malformed_enumerations_are_refused_not_guessed() {
    use ReadProblem as P;
    let (_, store, _) = installed::<WfpBench>();
    let filters = store.port().enumerate(&WfpLayer::ALL).unwrap();
    let bindings = bind(vec![binding()]).unwrap();
    assert!(parse_filters(&filters, Some(&provisioned()), &bindings).is_ok());
    let owned = filters
        .iter()
        .position(|filter| filter.spec.sublayer == WFP_SUBLAYER && filter.spec.name.contains(':'))
        .unwrap();
    let isolation = filters
        .iter()
        .position(|filter| filter.spec.name.starts_with("yg1 isolate"))
        .unwrap();
    let at = |item: usize, problem: ReadProblem| ReadError::Refused { item, problem };
    type Edit = Box<dyn FnOnce(&mut Vec<WfpFilter>)>;
    let cases: Vec<(Edit, ReadError)> = vec![
        (
            Box::new(move |filters: &mut Vec<WfpFilter>| filters[owned].spec.weight = 4),
            at(owned, P::NotRendered),
        ),
        (
            Box::new(move |filters: &mut Vec<WfpFilter>| {
                filters[owned].spec.conditions.push(WfpCondition::Other {
                    field: guid(1),
                    value: id("value"),
                })
            }),
            at(owned, P::NotRendered),
        ),
        (
            Box::new(move |filters: &mut Vec<WfpFilter>| {
                filters[owned].spec.flags.persistent = false
            }),
            at(owned, P::NotRendered),
        ),
        (
            Box::new(move |filters: &mut Vec<WfpFilter>| {
                filters[owned].spec.flags.clear_action_right = true
            }),
            at(owned, P::NotRendered),
        ),
        (
            Box::new(move |filters: &mut Vec<WfpFilter>| filters[owned].spec.key = guid(0)),
            at(owned, P::NotRendered),
        ),
        (
            Box::new(move |filters: &mut Vec<WfpFilter>| {
                filters[owned].spec.action = WfpAction::Callout { callout: guid(1) }
            }),
            at(owned, P::NotRendered),
        ),
        (
            Box::new(move |filters: &mut Vec<WfpFilter>| {
                filters[owned].spec.conditions[1] = WfpCondition::RemoteAddress {
                    low: address("10.0.0.0"),
                    high: address("10.0.0.5"),
                }
            }),
            at(owned, P::NotRendered),
        ),
        (
            Box::new(move |filters: &mut Vec<WfpFilter>| {
                filters[owned].spec.conditions[0] = WfpCondition::ServiceSid {
                    sid: Sid::parse("S-1-5-80-9").unwrap(),
                }
            }),
            at(owned, P::NotRendered),
        ),
        (
            Box::new(move |filters: &mut Vec<WfpFilter>| {
                filters[owned].spec.name = "yg1 x".to_owned()
            }),
            at(owned, P::BadMarker),
        ),
        (
            Box::new(move |filters: &mut Vec<WfpFilter>| {
                filters[owned].spec.name = "rule".to_owned()
            }),
            at(owned, P::Unmarked),
        ),
        (
            Box::new(move |filters: &mut Vec<WfpFilter>| filters[owned].spec.provider = None),
            at(owned, P::WrongObject),
        ),
        (
            Box::new(move |filters: &mut Vec<WfpFilter>| {
                let mut copy = filters[owned].clone();
                copy.id = 1;
                filters.push(copy);
            }),
            at(filters.len(), P::DuplicateHandle),
        ),
        (
            Box::new(move |filters: &mut Vec<WfpFilter>| {
                let mut copy = filters[isolation].clone();
                copy.id = 1;
                filters.push(copy);
            }),
            at(filters.len(), P::DuplicateIsolation),
        ),
        (
            Box::new(move |filters: &mut Vec<WfpFilter>| {
                filters[isolation].spec.name = format!("yg1 isolate {}", id("stranger").to_hex())
            }),
            at(isolation, P::UnboundIdentity),
        ),
        (
            Box::new(move |filters: &mut Vec<WfpFilter>| filters[isolation].spec.weight = 0),
            at(isolation, P::NotRendered),
        ),
        (
            Box::new(|filters: &mut Vec<WfpFilter>| filters[0].id = FOREIGN_HANDLE_BIT | 5),
            at(0, P::ForeignIdOutOfRange),
        ),
    ];
    for (index, (edit, expected)) in cases.into_iter().enumerate() {
        assert_eq!(refusal(&filters, edit), expected, "case {index}");
    }
    // Owned filters with no owned sublayer, or a sublayer not as provisioned.
    let first_owned = filters
        .iter()
        .position(|filter| filter.spec.sublayer == WFP_SUBLAYER)
        .unwrap();
    assert_eq!(
        parse_filters(&filters, None, &bindings).unwrap_err(),
        at(first_owned, P::ObjectShape)
    );
    for sublayer in [
        WfpSublayer {
            weight: WFP_SUBLAYER_WEIGHT - 1,
            ..provisioned()
        },
        WfpSublayer {
            provider: Some(guid(1)),
            ..provisioned()
        },
        WfpSublayer {
            provider: None,
            ..provisioned()
        },
        WfpSublayer {
            key: guid(2),
            ..provisioned()
        },
    ] {
        assert_eq!(
            parse_filters(&filters, Some(&sublayer), &bindings).unwrap_err(),
            at(filters.len(), P::ObjectShape),
            "{sublayer:?}"
        );
    }
    // Missing any one of the four isolation filters, the broker is not isolated.
    for layer in WfpLayer::ALL {
        let mut missing = filters.clone();
        missing.retain(|filter| {
            !(filter.spec.name.starts_with("yg1 isolate") && filter.spec.layer == layer)
        });
        assert_eq!(missing.len(), filters.len() - 1);
        let listing = parse_filters(&missing, Some(&provisioned()), &bindings).unwrap();
        assert!(
            !listing.snapshot.isolated.contains(&broker().identity),
            "{layer:?}"
        );
    }
}

#[test]
fn the_owned_sublayers_weight_and_provider_are_read_back() {
    let mut store = WfpBench::store();
    assert!(store.read().is_ok());
    store
        .port_mut()
        .engine
        .sublayers
        .insert(WFP_SUBLAYER, (WFP_PROVIDER, 7));
    assert!(matches!(
        store.read(),
        Err(ReadError::Refused {
            problem: ReadProblem::ObjectShape,
            ..
        })
    ));
    store
        .port_mut()
        .engine
        .sublayers
        .insert(WFP_SUBLAYER, (guid(1), WFP_SUBLAYER_WEIGHT));
    let writes = WfpBench::writes(&store);
    assert_eq!(
        store.isolate(broker().identity),
        Err(StoreFailure::Unavailable)
    );
    assert_eq!(WfpBench::writes(&store), writes);
}

#[test]
fn a_foreign_inbound_filter_on_the_broker_blocks_the_install() {
    // Say a firewall rule another program made to let the broker accept connections.
    let mut store = WfpBench::store();
    let mut spec = foreign(
        "Accept for broker",
        Some(guid(7)),
        guid(8),
        vec![
            WfpCondition::ServiceSid { sid: sid() },
            WfpCondition::RemotePort {
                low: 8080,
                high: 8080,
            },
        ],
        WfpAction::Permit,
    );
    spec.layer = WfpLayer::AleAuthRecvAcceptV4;
    let id_on_broker = store.port_mut().engine.insert(spec);
    let handle = RuleHandle::new(FOREIGN_HANDLE_BIT | id_on_broker);
    let installer = Installer::new(perimeter());
    assert_eq!(
        installer
            .prepare(
                &store,
                &profile(PerimeterPlatform::Windows, broker(), old_rules()),
                broker()
            )
            .unwrap_err(),
        InstallRefusal::ForeignRuleOnBroker { handle }
    );
}

/// FWPM_CONDITION_ALE_USER_ID matches a service SID only when the service carries it in
/// its token: SID type none, another SID, or an unknown service is never isolated.
#[test]
fn a_service_without_its_sid_in_the_token_is_never_isolated() {
    // Installed and isolated, then the service is reconfigured with SID type none.
    let (installer, mut store, _) = installed::<WfpBench>();
    assert!(store
        .snapshot()
        .unwrap()
        .isolated
        .contains(&broker().identity));
    store.port_mut().services.insert(
        service().as_str().to_owned(),
        configured(ServiceSidType::None),
    );
    let snapshot = store.snapshot().unwrap();
    assert!(!snapshot.isolated.contains(&broker().identity));
    assert_eq!(owned(&snapshot), scoped(broker().identity, &old_rules()));
    assert_eq!(
        installer
            .prepare(
                &store,
                &profile(PerimeterPlatform::Windows, broker(), new_rules()),
                broker()
            )
            .unwrap_err(),
        InstallRefusal::ScopeNotIsolated
    );

    // A restricted SID type is in the token too.
    store.port_mut().services.insert(
        service().as_str().to_owned(),
        configured(ServiceSidType::Restricted),
    );
    assert!(store
        .snapshot()
        .unwrap()
        .isolated
        .contains(&broker().identity));

    // isolate refuses before writing.
    let refusals = [
        Some(configured(ServiceSidType::None)),
        Some(ServiceSidInfo {
            sid: Sid::parse("S-1-5-80-1-2-3-4-5").unwrap(),
            sid_type: ServiceSidType::Unrestricted,
        }),
        None,
    ];
    for answer in refusals {
        let mut port = FakeWfp::default();
        if let Some(answer) = answer.clone() {
            port.services.insert(service().as_str().to_owned(), answer);
        }
        let mut store = WfpStore::new(port, vec![binding()]).unwrap();
        assert_eq!(
            store.isolate(broker().identity),
            Err(StoreFailure::Rejected),
            "{answer:?}"
        );
        assert_eq!(WfpBench::writes(&store), 0);
    }

    // An unknown service makes the read fail rather than guess.
    let (_, mut store, _) = installed::<WfpBench>();
    store.port_mut().services.clear();
    assert_eq!(
        store.read(),
        Err(ReadError::Port {
            failure: StoreFailure::Rejected
        })
    );

    // An AppContainer's package SID is always in its token.
    let container = BrokerIdentity {
        kind: IdentityKind::AppContainer,
        identity: id("container broker"),
    };
    let binding = Binding {
        broker: container,
        selector: WfpSelector::PackageSid {
            sid: Sid::parse("S-1-15-2-1-2-3-4-5-6-7").unwrap(),
        },
    };
    let mut store = WfpStore::new(FakeWfp::default(), vec![binding]).unwrap();
    store.isolate(container.identity).unwrap();
    assert!(store
        .snapshot()
        .unwrap()
        .isolated
        .contains(&container.identity));
}

#[test]
fn sids_and_bindings_are_checked() {
    for text in ["S-1-5-80-1-2-3-4-5", "S-1-15-2-1-2-3-4-5-6-7", "S-1-5-18-0"] {
        assert_eq!(Sid::parse(text).unwrap().as_str(), text);
    }
    for text in [
        "",
        "S-1-5",
        "S-2-5-80-1",
        "s-1-5-80-1",
        "S-1-5-80-01",
        "S-1-5-80-4294967296",
        "S-1-281474976710656-1",
        "S-1-5-80-1-",
        "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16",
    ] {
        assert_eq!(Sid::parse(text), Err(BindingError::InvalidName), "{text:?}");
    }
    let store = |bindings| WfpStore::new(FakeWfp::default(), bindings).err();
    assert_eq!(
        store(vec![Binding {
            broker: broker(),
            selector: WfpSelector::ServiceSid {
                service: service(),
                sid: Sid::parse("S-1-15-2-1-2-3-4-5-6-7").unwrap()
            }
        }]),
        Some(BindingError::InvalidName)
    );
    // One SID under two identities overlaps, whatever the services are called.
    let other = BrokerIdentity {
        kind: IdentityKind::ServiceSid,
        identity: id("other broker"),
    };
    assert_eq!(
        store(vec![
            binding(),
            Binding {
                broker: other,
                selector: WfpSelector::ServiceSid {
                    service: ServiceName::new("OtherBroker").unwrap(),
                    sid: sid()
                }
            }
        ]),
        Some(BindingError::OverlappingSelector {
            identity: other.identity
        })
    );
    assert_eq!(
        ServiceName::new("Yougori.Broker_2-x").unwrap().as_str(),
        "Yougori.Broker_2-x"
    );
    for name in ["", "a b", "a/b", "a\\b", "\u{e9}", "x".repeat(257).as_str()] {
        assert_eq!(
            ServiceName::new(name),
            Err(BindingError::InvalidName),
            "{name:?}"
        );
    }
    assert_eq!(
        store(vec![Binding {
            broker: broker(),
            selector: WfpSelector::PackageSid {
                sid: Sid::parse("S-1-15-2-1-2-3-4-5-6-7").unwrap()
            }
        }]),
        Some(BindingError::KindMismatch {
            broker: IdentityKind::ServiceSid,
            selector: IdentityKind::AppContainer
        })
    );
}
