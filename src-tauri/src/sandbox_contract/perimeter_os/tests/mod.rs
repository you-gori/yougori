//! Tests of the platform rule stores over fake ports that keep state the way each
//! platform would.

use std::collections::BTreeSet;
use std::net::IpAddr;

use super::fakes::FakeJournal;
use super::*;
use crate::foundation::coordination::PerimeterId;
use crate::foundation::ids::{digest, Digest};
use crate::sandbox_contract::destinations::{
    DestinationPort, IpPrefix, PerimeterOptions, PerimeterPlatform, PerimeterProfile,
    PerimeterRule, PortSelector, RuleAction,
};
use crate::sandbox_contract::perimeter_install::{
    BrokerIdentity, ElevationGrant, InstallError, InstallReceipt, Installer, OwnerTag, RuleHandle,
    RuleStore, ScopedRule, StoreFailure, StoreSnapshot, TransactionId,
};

mod elevation;
mod nft;
mod pf;
mod scenarios;
mod wfp;

pub fn id(seed: &str) -> Digest {
    digest("test/perimeter-os", &[seed.as_bytes()])
}

pub fn perimeter() -> PerimeterId {
    PerimeterId::new(id("perimeter"))
}

pub fn prefix(address: &str, length: u8) -> IpPrefix {
    IpPrefix::new(address.parse().unwrap(), length).unwrap()
}

pub fn port(number: u16) -> DestinationPort {
    DestinationPort::new(number).unwrap()
}

pub fn allow(address: &str, length: u8, to: u16) -> PerimeterRule {
    PerimeterRule {
        action: RuleAction::Allow,
        prefix: prefix(address, length),
        ports: PortSelector::Only(port(to)),
    }
}

pub fn allow_all(address: &str, length: u8) -> PerimeterRule {
    PerimeterRule {
        action: RuleAction::Allow,
        prefix: prefix(address, length),
        ports: PortSelector::All,
    }
}

pub fn block(address: &str, length: u8) -> PerimeterRule {
    PerimeterRule {
        action: RuleAction::Block,
        prefix: prefix(address, length),
        ports: PortSelector::All,
    }
}

/// The perimeter before an update: IPv4 and IPv6, one port and all ports, hosts and
/// prefixes.
pub fn old_rules() -> Vec<PerimeterRule> {
    vec![
        allow("203.0.113.0", 24, 443),
        allow("198.51.100.7", 32, 443),
        allow_all("2001:db8::", 32),
        block("169.254.169.254", 32),
        block("10.0.0.0", 8),
    ]
}

/// The perimeter after it: 203.0.113.0/24 moves from allowed to blocked, 192.0.2.0/24 is
/// newly allowed, all of IPv6 is blocked, and two rules stay.
pub fn new_rules() -> Vec<PerimeterRule> {
    vec![
        allow("192.0.2.0", 24, 443),
        allow("198.51.100.7", 32, 443),
        block("203.0.113.0", 24),
        block("10.0.0.0", 8),
        block("::", 0),
    ]
}

pub fn profile(
    platform: PerimeterPlatform,
    broker: BrokerIdentity,
    rules: Vec<PerimeterRule>,
) -> PerimeterProfile {
    let options = PerimeterOptions::default();
    PerimeterProfile::declare(
        platform,
        options,
        platform.required_properties(options),
        None,
        broker.identity,
        rules,
    )
    .unwrap()
}

pub fn scoped(identity: Digest, rules: &[PerimeterRule]) -> BTreeSet<ScopedRule> {
    rules
        .iter()
        .map(|rule| ScopedRule {
            identity,
            rule: *rule,
        })
        .collect()
}

/// The rules the snapshot attributes to `perimeter()`.
pub fn owned(snapshot: &StoreSnapshot) -> BTreeSet<ScopedRule> {
    snapshot
        .entries
        .values()
        .filter(|entry| entry.tag.map(|tag| tag.perimeter) == Some(perimeter()))
        .map(|entry| entry.scoped().unwrap())
        .collect()
}

/// How many entries carry any tag at all.
pub fn tagged(snapshot: &StoreSnapshot) -> usize {
    snapshot
        .entries
        .values()
        .filter(|entry| entry.tag.is_some())
        .count()
}

// The error type is V16's own; these helpers only pass it through.
#[allow(clippy::result_large_err)]
pub fn install<S: RuleStore>(
    installer: &mut Installer,
    store: &mut S,
    journal: &mut FakeJournal,
    platform: PerimeterPlatform,
    broker: BrokerIdentity,
    rules: Vec<PerimeterRule>,
) -> Result<InstallReceipt, InstallError> {
    let prepared = installer
        .prepare(store, &profile(platform, broker, rules), broker)
        .unwrap();
    let grant = prepared.grant_request();
    installer.execute(&prepared, &grant, store, journal)
}

#[allow(clippy::result_large_err)]
pub fn teardown<S: RuleStore>(
    installer: &mut Installer,
    store: &mut S,
    journal: &mut FakeJournal,
) -> Result<InstallReceipt, InstallError> {
    let prepared = installer.prepare_teardown(store).unwrap();
    let grant = prepared.grant_request();
    installer.execute(&prepared, &grant, store, journal)
}

pub fn grid() -> Vec<(IpAddr, DestinationPort)> {
    let addresses = [
        "203.0.113.5",
        "198.51.100.7",
        "198.51.100.8",
        "192.0.2.9",
        "169.254.169.254",
        "10.1.2.3",
        "8.8.8.8",
        "2001:db8::1",
        "fd00::1",
    ];
    let mut points = Vec::new();
    for address in addresses {
        for number in [443, 80] {
            points.push((address.parse().unwrap(), port(number)));
        }
    }
    points
}

/// The grid points `identity` may reach under `snapshot`.
pub fn permitted(
    snapshot: &StoreSnapshot,
    identity: Digest,
) -> BTreeSet<(IpAddr, DestinationPort)> {
    grid()
        .into_iter()
        .filter(|(address, to)| snapshot.permits(identity, *address, *to) == Some(true))
        .collect()
}

/// The grid points `rules` permit: an allow covers the point and no block does.
pub fn expected(rules: &[PerimeterRule]) -> BTreeSet<(IpAddr, DestinationPort)> {
    let covers = |action: RuleAction, address: IpAddr, to: DestinationPort| {
        rules
            .iter()
            .any(|rule| rule.action == action && rule.covers(address, to))
    };
    grid()
        .into_iter()
        .filter(|(address, to)| {
            covers(RuleAction::Allow, *address, *to) && !covers(RuleAction::Block, *address, *to)
        })
        .collect()
}

/// A grant that may remove `handles` and add nothing, under transaction 9.
pub fn removal_grant(handles: impl IntoIterator<Item = RuleHandle>) -> ElevationGrant {
    ElevationGrant {
        tag: OwnerTag {
            perimeter: perimeter(),
            transaction: TransactionId::new(9),
        },
        plan: id("plan"),
        may_add: BTreeSet::new(),
        may_remove: handles.into_iter().collect(),
    }
}

#[test]
fn markers_round_trip_exactly_and_refuse_near_misses() {
    use super::common::{
        isolation_marker, owned_marker, read_marker, read_short_marker, short_owned_marker, Marker,
    };
    let tag = OwnerTag {
        perimeter: perimeter(),
        transaction: TransactionId::new(12),
    };
    let handle = RuleHandle::new(4242);
    let text = owned_marker(tag, handle);
    assert_eq!(
        text,
        format!("yg1 {}:12:4242", perimeter().digest().to_hex())
    );
    assert!(text.len() <= 128);
    assert_eq!(read_marker(&text), Marker::Owned { tag, handle });
    assert_eq!(
        read_marker(&isolation_marker(id("broker"))),
        Marker::Isolation {
            identity: Some(id("broker"))
        }
    );
    let short = short_owned_marker(tag.transaction, handle);
    assert_eq!(short, "yg1 12:4242");
    assert_eq!(
        read_short_marker(&short, perimeter()),
        Marker::Owned { tag, handle }
    );
    let hex = perimeter().digest().to_hex();
    for absent in ["", "ssh", "yg1", "yg2 x", "YG1 x"] {
        assert_eq!(read_marker(absent), Marker::Absent, "{absent:?}");
    }
    for malformed in [
        format!("yg1 {}:12:4242", hex.to_uppercase()),
        format!("yg1 {hex}:012:4242"),
        format!("yg1 {hex}:12:4242:1"),
        format!("yg1 {hex}:12:+4242"),
        format!("yg1 {hex}:12:{}", u64::MAX),
        format!("yg1  {hex}:12:4242"),
        format!("yg1 {hex}:12:4242 "),
        "yg1 isolate".to_owned(),
        format!("yg1 isolate {}", &hex[..63]),
    ] {
        assert_eq!(read_marker(&malformed), Marker::Malformed, "{malformed:?}");
    }
    for malformed in ["yg1 12", "yg1 12:", "yg1 x:1", "yg1 1:2:3", "yg1 isolate 1"] {
        assert_eq!(
            read_short_marker(malformed, perimeter()),
            Marker::Malformed,
            "{malformed:?}"
        );
    }
}

#[test]
fn handles_follow_the_tag_skip_taken_ones_and_never_look_foreign() {
    use super::common::allocate_handle;
    let tag = OwnerTag {
        perimeter: perimeter(),
        transaction: TransactionId::FIRST,
    };
    let first = allocate_handle(tag, &BTreeSet::new()).unwrap();
    assert_eq!(allocate_handle(tag, &BTreeSet::new()).unwrap(), first);
    let second = allocate_handle(tag, &BTreeSet::from([first])).unwrap();
    assert_ne!(second, first);
    let next_transaction = OwnerTag {
        transaction: TransactionId::new(2),
        ..tag
    };
    assert_ne!(
        allocate_handle(next_transaction, &BTreeSet::new()).unwrap(),
        first
    );
    let other_perimeter = OwnerTag {
        perimeter: PerimeterId::new(id("other perimeter")),
        ..tag
    };
    assert_ne!(
        allocate_handle(other_perimeter, &BTreeSet::new()).unwrap(),
        first
    );
    for handle in [first, second] {
        assert_eq!(handle.get() & FOREIGN_HANDLE_BIT, 0);
    }
}

#[test]
fn a_refused_listing_is_unavailable_to_the_installer() {
    let refused = ReadError::Refused {
        item: 3,
        problem: ReadProblem::NotRendered,
    };
    assert_eq!(refused.failure(), StoreFailure::Unavailable);
    let port = ReadError::Port {
        failure: StoreFailure::Rejected,
    };
    assert_eq!(port.failure(), StoreFailure::Rejected);
    assert!(refused.to_string().contains("item 3"));
}
