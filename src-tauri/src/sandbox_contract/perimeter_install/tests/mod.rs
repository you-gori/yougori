//! Tests of the transactional perimeter installer on the fake store.

use std::collections::BTreeSet;
use std::net::IpAddr;

use super::fakes::{FakeJournal, FakeRuleStore};
use super::*;
use crate::foundation::coordination::PerimeterId;
use crate::foundation::ids::{digest, Digest};
use crate::sandbox_contract::destinations::{
    DestinationPort, IpPrefix, PerimeterOptions, PerimeterPlatform, PerimeterProfile,
    PerimeterRule, PortSelector, RemoteEnforcement, RuleAction,
};

mod install;
mod plan;
mod records;
mod recovery;

pub fn id(seed: &str) -> Digest {
    digest("test/perimeter-install", &[seed.as_bytes()])
}

pub fn perimeter() -> PerimeterId {
    PerimeterId::new(id("perimeter"))
}

pub fn broker() -> BrokerIdentity {
    BrokerIdentity {
        kind: IdentityKind::ServiceSid,
        identity: id("broker"),
    }
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

pub fn block(address: &str, length: u8) -> PerimeterRule {
    PerimeterRule {
        action: RuleAction::Block,
        prefix: prefix(address, length),
        ports: PortSelector::All,
    }
}

/// The perimeter before an update.
pub fn old_rules() -> Vec<PerimeterRule> {
    vec![
        allow("203.0.113.0", 24, 443),
        allow("198.51.100.7", 32, 443),
        block("169.254.169.254", 32),
        block("10.0.0.0", 8),
    ]
}

/// The perimeter after it: 203.0.113.0/24 moves from allowed to blocked, 192.0.2.0/24 is
/// newly allowed, the metadata block goes, and the other two rules stay.
pub fn new_rules() -> Vec<PerimeterRule> {
    vec![
        allow("192.0.2.0", 24, 443),
        allow("198.51.100.7", 32, 443),
        block("203.0.113.0", 24),
        block("10.0.0.0", 8),
    ]
}

pub fn profile_on(platform: PerimeterPlatform, rules: Vec<PerimeterRule>) -> PerimeterProfile {
    let options = PerimeterOptions::default();
    let remote =
        (platform == PerimeterPlatform::Remote).then_some(RemoteEnforcement::HostOutsideGuest);
    PerimeterProfile::declare(
        platform,
        options,
        platform.required_properties(options),
        remote,
        broker().identity,
        rules,
    )
    .unwrap()
}

pub fn profile(rules: Vec<PerimeterRule>) -> PerimeterProfile {
    profile_on(PerimeterPlatform::Windows, rules)
}

/// A store that isolates the broker, with two rules other programs wrote: an opaque
/// machine-wide one and one on another identity.
pub fn store() -> FakeRuleStore {
    let mut store = FakeRuleStore::new();
    store.isolate(broker().identity);
    store.opaque_machine_rule("vpn client");
    store.insert_foreign(StoreEntry {
        tag: None,
        scope: RuleScope::Identity {
            identity: id("browser"),
        },
        body: RuleBody::Perimeter {
            rule: allow("203.0.113.0", 24, 443),
        },
    });
    store
}

pub fn scoped(rules: &[PerimeterRule]) -> BTreeSet<ScopedRule> {
    rules
        .iter()
        .map(|rule| ScopedRule {
            identity: broker().identity,
            rule: *rule,
        })
        .collect()
}

pub fn install(
    installer: &mut Installer,
    store: &mut FakeRuleStore,
    journal: &mut FakeJournal,
    rules: Vec<PerimeterRule>,
) -> Result<InstallReceipt, InstallError> {
    let prepared = installer.prepare(store, &profile(rules), broker()).unwrap();
    let grant = prepared.grant_request();
    installer.execute(&prepared, &grant, store, journal)
}

/// The rules in the store with this perimeter's tag, as scoped rules.
pub fn tagged(store: &FakeRuleStore) -> Vec<ScopedRule> {
    store
        .state
        .entries
        .values()
        .filter(|entry| entry.tag.map(|tag| tag.perimeter) == Some(perimeter()))
        .map(|entry| entry.scoped().unwrap())
        .collect()
}

pub fn tagged_set(store: &FakeRuleStore) -> BTreeSet<ScopedRule> {
    tagged(store).into_iter().collect()
}

/// Every entry without this perimeter's tag.
pub fn foreign(store: &FakeRuleStore) -> Vec<(RuleHandle, StoreEntry)> {
    store
        .state
        .entries
        .iter()
        .filter(|(_, entry)| entry.tag.map(|tag| tag.perimeter) != Some(perimeter()))
        .map(|(handle, entry)| (*handle, *entry))
        .collect()
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
    ];
    let mut points = Vec::new();
    for address in addresses {
        for number in [443, 80, 22] {
            points.push((address.parse().unwrap(), port(number)));
        }
    }
    points
}

/// The grid points the broker may reach under `snapshot`.
pub fn permitted(snapshot: &StoreSnapshot) -> BTreeSet<(IpAddr, DestinationPort)> {
    grid()
        .into_iter()
        .filter(|(address, to)| snapshot.permits(broker().identity, *address, *to) == Some(true))
        .collect()
}

/// The handles of this perimeter's rules, by rule.
pub fn handles(store: &FakeRuleStore) -> std::collections::BTreeMap<ScopedRule, RuleHandle> {
    store
        .state
        .entries
        .iter()
        .filter(|(_, entry)| entry.tag.map(|tag| tag.perimeter) == Some(perimeter()))
        .map(|(handle, entry)| (entry.scoped().unwrap(), *handle))
        .collect()
}
