//! The host rule store as the installer sees it (VM §4.4: "Install/update rules
//! transactionally, verify their scope, preserve unrelated rules, and provide a
//! rollback"; VM-W15 acceptance: "no unrelated PC rule changes").
//!
//! A [`RuleStore`] is the platform's firewall (nftables, WFP/Windows Firewall, a macOS
//! enforcement API) reduced to what the installer needs: a full read, and an add and a
//! remove that the elevated side performs only under an [`ElevationGrant`]. Every rule
//! Yougori adds carries an [`OwnerTag`] naming its perimeter and transaction. A tag is
//! bookkeeping, not authority: anything with administrator rights can write one, so the
//! installer touches only rules its own journal recorded or its own pending transaction
//! tagged, and leaves every other rule, tagged or not, exactly as it found it.
//!
//! The evaluation model ([`StoreSnapshot::permits`]) is the one the platform adapter must
//! provide for the broker's identity: traffic of an isolated identity is permitted only by
//! that identity's own allow rules, an explicit block wins over a conflicting allow (VM
//! §4.4, Windows), and anything no rule permits is denied. Whether the kernel really
//! behaves so is a CORE-01 `PerimeterRuleEnforced` fact from a must-probe (V02
//! `MustProbe`), never something a store report establishes.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use super::plan::ElevationGrant;
use crate::foundation::coordination::PerimeterId;
use crate::foundation::ids::Digest;
use crate::sandbox_contract::destinations::{DestinationPort, PerimeterRule, RuleAction};

/// One installer transaction of one perimeter. Transactions only count up, so a tag from
/// an earlier or abandoned transaction is never mistaken for the current one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TransactionId(u64);

impl TransactionId {
    pub const FIRST: Self = Self(1);

    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    /// `None` at `u64::MAX`; a transaction number is never reused.
    pub fn next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }
}

impl fmt::Display for TransactionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The ownership mark on a rule Yougori added: which perimeter and which transaction. The
/// platform adapter keeps it in the rule's group, comment, table or anchor name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerTag {
    pub perimeter: PerimeterId,
    pub transaction: TransactionId,
}

/// The store's own name for one installed rule (an nftables handle, a firewall rule
/// name). Only the store assigns one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RuleHandle(u64);

impl RuleHandle {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for RuleHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rule {}", self.0)
    }
}

/// Whose traffic a rule applies to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RuleScope {
    /// One stable process or service identity, by digest (VM §4.4: "the actual process
    /// or service identity"; see [`BrokerIdentity`](super::BrokerIdentity)).
    Identity { identity: Digest },
    /// Every program on the machine. The installer never writes one (VM §4.4: "Avoid
    /// changing the whole PC's outbound defaults").
    Machine,
}

/// A rule body and the identity it constrains: what the installer compares, independent
/// of handles and tags.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedRule {
    pub identity: Digest,
    pub rule: PerimeterRule,
}

/// What the installer asks the store to add: always identity-scoped and tagged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedRule {
    pub tag: OwnerTag,
    pub scoped: ScopedRule,
}

/// A rule body as the store reports it. A rule some other program wrote need not be
/// expressible as a [`PerimeterRule`]; it is then known only by a digest of its
/// platform form.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RuleBody {
    Perimeter { rule: PerimeterRule },
    Opaque { digest: Digest },
}

/// One rule as the store reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreEntry {
    /// The tag the store read back, if the rule carries one.
    pub tag: Option<OwnerTag>,
    pub scope: RuleScope,
    pub body: RuleBody,
}

impl StoreEntry {
    /// The entry as Yougori's own rule shape, when it is identity-scoped with a
    /// perimeter body.
    pub fn scoped(&self) -> Option<ScopedRule> {
        match (self.scope, self.body) {
            (RuleScope::Identity { identity }, RuleBody::Perimeter { rule }) => {
                Some(ScopedRule { identity, rule })
            }
            _ => None,
        }
    }

    /// Whether the entry applies to exactly `identity`'s traffic.
    pub fn constrains(&self, identity: Digest) -> bool {
        self.scope == RuleScope::Identity { identity }
    }
}

/// A full read of the store.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreSnapshot {
    pub entries: BTreeMap<RuleHandle, StoreEntry>,
    /// Identities whose traffic only their own rules can permit, with default deny for
    /// the rest (a dedicated network namespace, a WFP sublayer). Machine-wide and other
    /// identities' rules do not apply to them.
    pub isolated: BTreeSet<Digest>,
}

impl StoreSnapshot {
    /// Whether `identity`'s traffic to `address:port` is permitted under the evaluation
    /// model above: an isolated identity needs one of its own allow rules covering the
    /// destination and none of its own block rules covering it. A non-isolated identity
    /// is never judged permitted or denied here, so this returns `None`.
    pub fn permits(
        &self,
        identity: Digest,
        address: IpAddr,
        port: DestinationPort,
    ) -> Option<bool> {
        if !self.isolated.contains(&identity) {
            return None;
        }
        let mut allowed = false;
        for entry in self
            .entries
            .values()
            .filter(|entry| entry.constrains(identity))
        {
            let RuleBody::Perimeter { rule } = entry.body else {
                // An opaque rule on the identity cannot be judged; deny.
                return Some(false);
            };
            if rule.covers(address, port) {
                match rule.action {
                    RuleAction::Block => return Some(false),
                    RuleAction::Allow => allowed = true,
                }
            }
        }
        Some(allowed)
    }

    /// The entry under `handle`, if the store still has one.
    pub fn entry(&self, handle: RuleHandle) -> Option<&StoreEntry> {
        self.entries.get(&handle)
    }
}

/// Why the store could not do what was asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum StoreFailure {
    /// The store could not be read or written at all.
    Unavailable,
    /// The elevated side refused an operation its grant does not cover.
    NotGranted,
    /// No rule has this handle.
    UnknownHandle { handle: RuleHandle },
    /// The platform rejected the rule.
    Rejected,
}

impl fmt::Display for StoreFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => f.write_str("the rule store is unavailable"),
            Self::NotGranted => {
                f.write_str("the elevated side refused an operation outside its grant")
            }
            Self::UnknownHandle { handle } => write!(f, "the rule store has no {handle}"),
            Self::Rejected => f.write_str("the platform rejected the rule"),
        }
    }
}

impl std::error::Error for StoreFailure {}

/// The platform firewall as the installer uses it. A read needs no elevation; an add or a
/// remove is performed by the elevated side only when `grant` covers it (VM §4.4: "Use
/// elevation only for the concrete operations that require it").
pub trait RuleStore {
    fn snapshot(&self) -> Result<StoreSnapshot, StoreFailure>;

    fn add(&mut self, grant: &ElevationGrant, rule: &OwnedRule)
        -> Result<RuleHandle, StoreFailure>;

    /// Removes the rule under `handle`.
    fn remove(&mut self, grant: &ElevationGrant, handle: RuleHandle) -> Result<(), StoreFailure>;
}
