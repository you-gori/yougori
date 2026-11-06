//! What the two perimeter read-back targets share (M10; VM §4.4, VM-W15; VM-W50): the
//! perimeter and broker identities, random valid rule sets and the grants that let a
//! store render them, and the checks that a snapshot read back holds exactly the rules a
//! store rendered and only entries a store can own.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::rng::SplitMix64;
use crate::foundation::coordination::PerimeterId;
use crate::foundation::ids::{digest, Digest};
use crate::sandbox_contract::destinations::{
    DestinationPort, IpPrefix, PerimeterRule, PortSelector, RuleAction,
};
use crate::sandbox_contract::perimeter_install::{
    ElevationGrant, OwnedRule, OwnerTag, RuleBody, RuleHandle, RuleScope, ScopedRule, StoreEntry,
    StoreSnapshot, TransactionId,
};
use crate::sandbox_contract::perimeter_os::FOREIGN_HANDLE_BIT;

/// Ports pf may print by name, and others.
const PORTS: [u16; 8] = [22, 53, 80, 123, 443, 1, 8_443, 65_535];

/// A digest naming one test identity.
pub(super) fn id(name: &str) -> Digest {
    digest(
        "yougori/test/protocol-fuzz/perimeter/v1",
        &[name.as_bytes()],
    )
}

/// The perimeter every rendered rule belongs to.
pub(super) fn perimeter() -> PerimeterId {
    PerimeterId::new(id("perimeter"))
}

/// The rule `action` for `address`/`length`, for one port or all.
pub(super) fn rule(
    action: RuleAction,
    address: &str,
    length: u8,
    port: Option<u16>,
) -> PerimeterRule {
    PerimeterRule {
        action,
        prefix: IpPrefix::new(address.parse().unwrap(), length).unwrap(),
        ports: port.map_or(PortSelector::All, |port| {
            PortSelector::Only(DestinationPort::new(port).unwrap())
        }),
    }
}

/// `rule` for `identity`, tagged with this perimeter and `transaction`.
pub(super) fn owned(identity: Digest, transaction: u64, rule: PerimeterRule) -> OwnedRule {
    OwnedRule {
        tag: OwnerTag {
            perimeter: perimeter(),
            transaction: TransactionId::new(transaction),
        },
        scoped: ScopedRule { identity, rule },
    }
}

/// A random valid perimeter rule: allow or block, IPv4 or IPv6, a whole family, a host or
/// a prefix, all ports or one.
pub(super) fn random_rule(rng: &mut SplitMix64) -> PerimeterRule {
    let action = if rng.one_in(2) {
        RuleAction::Allow
    } else {
        RuleAction::Block
    };
    let v6 = rng.one_in(3);
    let width: u8 = if v6 { 128 } else { 32 };
    let length = match rng.below(4) {
        0 => 0,
        1 => width,
        _ => u8::try_from(rng.between(1, usize::from(width))).unwrap(),
    };
    let bits = (u128::from(rng.next_u64()) << 64) | u128::from(rng.next_u64());
    let shift = u32::from(width - length);
    let network = if v6 {
        let mask = u128::MAX.checked_shl(shift).unwrap_or(0);
        IpAddr::V6(Ipv6Addr::from(bits & mask))
    } else {
        let mask = u32::MAX.checked_shl(shift).unwrap_or(0);
        IpAddr::V4(Ipv4Addr::from(u32::try_from(bits >> 96).unwrap() & mask))
    };
    let ports = if rng.one_in(3) {
        PortSelector::All
    } else {
        let port = if rng.one_in(2) {
            *rng.pick(&PORTS)
        } else {
            u16::try_from(rng.between(1, 65_535)).unwrap()
        };
        PortSelector::Only(DestinationPort::new(port).unwrap())
    };
    PerimeterRule {
        action,
        prefix: IpPrefix::new(network, length).unwrap(),
        ports,
    }
}

/// One operation of a rendering plan.
#[derive(Clone, Copy, Debug)]
pub(super) enum Step {
    /// Isolate the identity (nftables), or add its TCP and UDP deny (pf).
    Isolate(Digest),
    Add(OwnedRule),
}

/// A random plan over `identities`: an isolation of some of them and up to `most` random
/// rules of any of them, in random order; with `isolate_first`, the first step isolates
/// one of them.
pub(super) fn random_plan(
    rng: &mut SplitMix64,
    identities: &[Digest],
    most: usize,
    isolate_first: bool,
) -> Vec<Step> {
    let mut steps = Vec::new();
    let mut isolated = BTreeSet::new();
    if isolate_first {
        let identity = *rng.pick(identities);
        isolated.insert(identity);
        steps.push(Step::Isolate(identity));
    }
    let fixed = steps.len();
    for identity in identities {
        if rng.one_in(2) && isolated.insert(*identity) {
            steps.push(Step::Isolate(*identity));
        }
    }
    for _ in 0..rng.between(0, most) {
        let transaction = match rng.below(4) {
            0 => 1,
            1 => u64::MAX,
            _ => rng.next_u64(),
        };
        steps.push(Step::Add(owned(
            *rng.pick(identities),
            transaction,
            random_rule(rng),
        )));
    }
    for index in (fixed + 1..steps.len()).rev() {
        let other = rng.between(fixed, index);
        steps.swap(index, other);
    }
    steps
}

/// The grant that lets a store add exactly `rule`.
pub(super) fn grant_for(rule: &OwnedRule) -> ElevationGrant {
    ElevationGrant {
        tag: rule.tag,
        plan: id("plan"),
        may_add: BTreeSet::from([rule.scoped]),
        may_remove: BTreeSet::new(),
    }
}

/// Fails unless `snapshot` holds exactly the `added` rules, each under the handle the
/// store returned for it, with its tag, identity and rule.
pub(super) fn holds(
    snapshot: &StoreSnapshot,
    added: &[(RuleHandle, OwnedRule)],
) -> Result<(), String> {
    ensure!(
        snapshot.entries.len() == added.len(),
        "{} entries read back for {} rules rendered",
        snapshot.entries.len(),
        added.len()
    );
    for (handle, rule) in added {
        let expected = StoreEntry {
            tag: Some(rule.tag),
            scope: RuleScope::Identity {
                identity: rule.scoped.identity,
            },
            body: RuleBody::Perimeter {
                rule: rule.scoped.rule,
            },
        };
        let found = snapshot.entries.get(handle);
        ensure!(
            found == Some(&expected),
            "{handle} read back as {found:?}, rendered as {expected:?}"
        );
    }
    Ok(())
}

/// Fails unless every entry of an accepted `snapshot` is one a store can own: a handle
/// outside the foreign space, a tag, an identity in `bound` and a perimeter rule; and
/// every isolated identity is in `bound`.
pub(super) fn owned_limits(
    snapshot: &StoreSnapshot,
    bound: &BTreeSet<Digest>,
) -> Result<(), String> {
    for (handle, entry) in &snapshot.entries {
        ensure!(
            handle.get() & FOREIGN_HANDLE_BIT == 0,
            "{handle} lies in the foreign handle space"
        );
        ensure!(entry.tag.is_some(), "{handle} was read without a tag");
        ensure!(
            matches!(entry.scope, RuleScope::Identity { identity } if bound.contains(&identity)),
            "{handle} names {:?}, which the store does not bind",
            entry.scope
        );
        ensure!(
            matches!(entry.body, RuleBody::Perimeter { .. }),
            "{handle} was read with an opaque body"
        );
    }
    ensure!(
        snapshot.isolated.is_subset(bound),
        "identities {:?} the store does not bind were reported isolated",
        snapshot.isolated
    );
    Ok(())
}
