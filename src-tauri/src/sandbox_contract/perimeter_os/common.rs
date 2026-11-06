//! What the three platform stores share (VM §4.4: "Install/update rules transactionally,
//! verify their scope, preserve unrelated rules, and provide a rollback"; VM-W15): the
//! marker on every rule this product writes, how a store chooses a new rule's handle, how
//! a broker identity is bound to the platform's name for it, the command port, and why a
//! listing is refused.
//!
//! A marker is bookkeeping, not authority (V16 `OwnerTag`): a store believes one only on a
//! rule inside the object this product owns (an nftables table, a WFP sublayer, a pf
//! anchor), and there only when the rule is exactly what the store renders for it.
//! Anything else in the owned object refuses the whole read; nothing is guessed.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::foundation::coordination::PerimeterId;
use crate::foundation::ids::{Digest, DigestBuilder};
use crate::sandbox_contract::destinations::PerimeterRule;
use crate::sandbox_contract::perimeter_install::{
    BrokerIdentity, IdentityKind, OwnerTag, RuleBody, RuleHandle, RuleScope, StoreEntry,
    StoreFailure, TransactionId,
};

/// The word every marker this product writes starts with, followed by one space.
pub const MARKER_VERSION: &str = "yg1";

/// Handles with this bit set name rules outside the owned object (WFP filters of other
/// sublayers). A store never gives one to a rule it adds and never removes one.
pub const FOREIGN_HANDLE_BIT: u64 = 1 << 63;

/// Domain of the digest a store derives a new rule's handle from.
pub const HANDLE_DOMAIN: &str = "yougori/sandbox/perimeter-os/handle/v1";

/// How many handles of one transaction a store tries before it refuses an add.
const HANDLE_ATTEMPTS: u64 = 1 << 16;

/// What a marker read back says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Marker {
    /// Not a marker of this product at all.
    Absent,
    /// It starts like one but is not exactly one this product writes.
    Malformed,
    /// A perimeter rule: its owner tag and the handle the store gave it.
    Owned { tag: OwnerTag, handle: RuleHandle },
    /// The default deny that isolates one identity, named where the platform has room.
    Isolation { identity: Option<Digest> },
}

/// The full marker of an owned rule, `yg1 <perimeter>:<transaction>:<handle>`: the
/// perimeter as 64 lowercase hexadecimal digits, the numbers in decimal.
pub(super) fn owned_marker(tag: OwnerTag, handle: RuleHandle) -> String {
    format!(
        "{MARKER_VERSION} {}:{}:{}",
        tag.perimeter.digest().to_hex(),
        tag.transaction.get(),
        handle.get()
    )
}

/// The full marker of an isolation rule, `yg1 isolate <identity>`.
pub(super) fn isolation_marker(identity: Digest) -> String {
    format!("{MARKER_VERSION} isolate {}", identity.to_hex())
}

/// The short marker of an owned rule, `yg1 <transaction>:<handle>`, for a platform whose
/// owned object already names the perimeter.
pub(super) fn short_owned_marker(transaction: TransactionId, handle: RuleHandle) -> String {
    format!("{MARKER_VERSION} {}:{}", transaction.get(), handle.get())
}

/// The short marker of an isolation rule, `yg1 isolate`.
pub(super) fn short_isolation_marker() -> String {
    format!("{MARKER_VERSION} isolate")
}

/// Reads a full marker.
pub(super) fn read_marker(text: &str) -> Marker {
    let Some(rest) = strip_version(text) else {
        return Marker::Absent;
    };
    if let Some(identity) = rest.strip_prefix("isolate ") {
        return match digest_hex(identity) {
            Some(identity) => Marker::Isolation {
                identity: Some(identity),
            },
            None => Marker::Malformed,
        };
    }
    let mut parts = rest.split(':');
    let (Some(perimeter), Some(transaction), Some(handle), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Marker::Malformed;
    };
    match (
        digest_hex(perimeter),
        decimal(transaction),
        own_handle(handle),
    ) {
        (Some(perimeter), Some(transaction), Some(handle)) => Marker::Owned {
            tag: OwnerTag {
                perimeter: PerimeterId::new(perimeter),
                transaction: TransactionId::new(transaction),
            },
            handle,
        },
        _ => Marker::Malformed,
    }
}

/// Reads a short marker of `perimeter`'s owned object.
pub(super) fn read_short_marker(text: &str, perimeter: PerimeterId) -> Marker {
    let Some(rest) = strip_version(text) else {
        return Marker::Absent;
    };
    if rest == "isolate" {
        return Marker::Isolation { identity: None };
    }
    let Some((transaction, handle)) = rest.split_once(':') else {
        return Marker::Malformed;
    };
    match (decimal(transaction), own_handle(handle)) {
        (Some(transaction), Some(handle)) => Marker::Owned {
            tag: OwnerTag {
                perimeter,
                transaction: TransactionId::new(transaction),
            },
            handle,
        },
        _ => Marker::Malformed,
    }
}

fn strip_version(text: &str) -> Option<&str> {
    text.strip_prefix(MARKER_VERSION)?.strip_prefix(' ')
}

/// Decimal digits without sign or leading zeros.
pub(super) fn decimal(text: &str) -> Option<u64> {
    let canonical = !text.is_empty()
        && text.bytes().all(|byte| byte.is_ascii_digit())
        && (text.len() == 1 || !text.starts_with('0'));
    if !canonical {
        return None;
    }
    text.parse().ok()
}

fn own_handle(text: &str) -> Option<RuleHandle> {
    let value = decimal(text)?;
    (value & FOREIGN_HANDLE_BIT == 0).then_some(RuleHandle::new(value))
}

/// Exactly 64 lowercase hexadecimal digits, the canonical text of a digest.
fn digest_hex(text: &str) -> Option<Digest> {
    let canonical = text.len() == 64
        && text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));
    if !canonical {
        return None;
    }
    Digest::from_hex(text).ok()
}

/// The handle a store gives the next rule of `tag`: the first of a sequence derived from
/// the tag that no rule in `taken` holds. Another transaction's sequence is another, so a
/// handle a journal still records for a rule of an earlier transaction is not handed out
/// again (barring a 63-bit digest collision, which V16's survey refuses as an altered
/// rule).
pub(super) fn allocate_handle(
    tag: OwnerTag,
    taken: &BTreeSet<RuleHandle>,
) -> Result<RuleHandle, StoreFailure> {
    (0..HANDLE_ATTEMPTS)
        .map(|sequence| derive_handle(tag, sequence))
        .find(|handle| !taken.contains(handle))
        .ok_or(StoreFailure::Rejected)
}

fn derive_handle(tag: OwnerTag, sequence: u64) -> RuleHandle {
    let digest = DigestBuilder::new(HANDLE_DOMAIN)
        .digest(&tag.perimeter.digest())
        .u64(tag.transaction.get())
        .u64(sequence)
        .finish();
    let [a, b, c, d, e, f, g, h, ..] = *digest.as_bytes();
    RuleHandle::new(u64::from_be_bytes([a, b, c, d, e, f, g, h]) & !FOREIGN_HANDLE_BIT)
}

/// The store entry of a rule this product wrote and read back exactly.
pub(super) fn owned_entry(tag: OwnerTag, identity: Digest, rule: PerimeterRule) -> StoreEntry {
    StoreEntry {
        tag: Some(tag),
        scope: RuleScope::Identity { identity },
        body: RuleBody::Perimeter { rule },
    }
}

/// One path component of a platform object name: 1 to `max` bytes of ASCII letters,
/// digits, `.`, `_`, `-`, `@` and `:`, never `.` or `..`.
pub(super) fn name_component(text: &str, max: usize) -> bool {
    !text.is_empty()
        && text.len() <= max
        && text != "."
        && text != ".."
        && text.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'@' | b':')
        })
}

/// One broker identity bound to the platform's name for it, which every rule for that
/// identity matches on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding<S> {
    pub broker: BrokerIdentity,
    pub selector: S,
}

/// The platform's name for a broker identity: a uid, a cgroup, a service SID.
pub trait Selector: Clone + PartialEq + fmt::Debug {
    /// The V16 [`IdentityKind`] this name stands for.
    fn kind(&self) -> IdentityKind;

    /// Refuses a name that cannot single out one dedicated broker identity.
    fn check(&self) -> Result<(), BindingError>;

    /// Whether one socket could match both names: the same uid, nested cgroups, the same
    /// SID. Equal names always overlap. Rules of two overlapping identities would
    /// constrain each other's traffic, so a store binds at most one of them.
    fn overlaps(&self, other: &Self) -> bool;
}

/// Checks `bindings` and keys them by identity: each selector must name its broker's kind,
/// no identity may appear twice and no two selectors may overlap.
pub(super) fn bind<S: Selector>(
    bindings: Vec<Binding<S>>,
) -> Result<BTreeMap<Digest, Binding<S>>, BindingError> {
    let mut bound: BTreeMap<Digest, Binding<S>> = BTreeMap::new();
    for binding in bindings {
        binding.selector.check()?;
        let selector = binding.selector.kind();
        if binding.broker.kind != selector {
            return Err(BindingError::KindMismatch {
                broker: binding.broker.kind,
                selector,
            });
        }
        let identity = binding.broker.identity;
        if bound
            .values()
            .any(|other| other.selector.overlaps(&binding.selector))
        {
            return Err(BindingError::OverlappingSelector { identity });
        }
        if bound.insert(identity, binding).is_some() {
            return Err(BindingError::DuplicateIdentity { identity });
        }
    }
    Ok(bound)
}

/// Why a store refused its identity bindings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingError {
    /// The selector names another identity kind than the broker's, including the kinds
    /// V16 never accepts (a user account, a process ID).
    KindMismatch {
        broker: IdentityKind,
        selector: IdentityKind,
    },
    /// Two bindings name one broker identity.
    DuplicateIdentity { identity: Digest },
    /// The platform name of this identity could match a socket another binding's name
    /// matches too (the same uid, nested cgroups, the same SID).
    OverlappingSelector { identity: Digest },
    /// The identity has no binding in this store.
    Unbound { identity: Digest },
    /// Root or the invalid uid cannot be an account only the broker runs as.
    PrivilegedAccount { uid: u32 },
    /// A cgroup path, namespace name, SID or anchor name is not in the accepted form.
    InvalidName,
    /// A network-namespace binding must be its store's only one: every rule in that
    /// namespace's table is the broker's.
    NamespaceNotAlone,
}

impl fmt::Display for BindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KindMismatch { broker, selector } => write!(
                f,
                "the broker is identified by a {broker}, but the platform name is a {selector}"
            ),
            Self::DuplicateIdentity { identity } => {
                write!(f, "broker identity {identity} is bound twice")
            }
            Self::OverlappingSelector { identity } => write!(
                f,
                "the platform name of broker identity {identity} overlaps another binding's"
            ),
            Self::Unbound { identity } => {
                write!(f, "broker identity {identity} has no binding in this store")
            }
            Self::PrivilegedAccount { uid } => {
                write!(f, "uid {uid} cannot be an account only the broker runs as")
            }
            Self::InvalidName => f.write_str("the platform name is not in the accepted form"),
            Self::NamespaceNotAlone => {
                f.write_str("a network-namespace binding must be the store's only binding")
            }
        }
    }
}

impl std::error::Error for BindingError {}

/// One command line a store wants run: the program and its arguments, and what goes to
/// its standard input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invocation {
    pub argv: Vec<String>,
    pub input: Option<String>,
}

/// Runs a platform's firewall command line for a store (nftables, pf). Nothing in this
/// module implements it for a real machine: the real port is the elevated helper, which
/// is outside this module and must check every write against its grant itself.
pub trait CommandPort {
    /// Runs a command that changes nothing and returns its standard output. A command
    /// that ran and failed is [`StoreFailure::Rejected`].
    fn read(&self, invocation: &Invocation) -> Result<String, StoreFailure>;

    /// Has the elevated side run a command that changes rules; `Ok` once the platform
    /// committed all of it, an error when it committed none of it.
    fn write(&mut self, invocation: &Invocation) -> Result<(), StoreFailure>;
}

/// What is wrong with a platform listing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadProblem {
    /// Not the document, record or line the platform prints.
    Malformed,
    /// The item names another table, family, chain, provider or anchor than the owned one.
    WrongObject,
    /// The owned object is missing, repeated, or not shaped the way the store provisions
    /// it.
    ObjectShape,
    /// A rule in the owned object carries no marker of this product.
    Unmarked,
    /// The marker is not exactly one this product writes.
    BadMarker,
    /// The rule is not the exact rendering of a bound identity and a perimeter rule.
    NotRendered,
    /// The rule names an identity the store does not bind.
    UnboundIdentity,
    /// Another rule already carries this rule's handle.
    DuplicateHandle,
    /// The identity is isolated twice.
    DuplicateIsolation,
    /// A foreign filter's id does not fit the foreign handle space.
    ForeignIdOutOfRange,
    /// The item is listed before the object that holds it.
    OutOfOrder,
}

impl fmt::Display for ReadProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "it is not what the platform prints",
            Self::WrongObject => "it names another object than the owned one",
            Self::ObjectShape => "the owned object is missing, repeated or not as provisioned",
            Self::Unmarked => "a rule in the owned object carries no marker of this product",
            Self::BadMarker => "the marker is not one this product writes",
            Self::NotRendered => "the rule is not exactly what this product renders",
            Self::UnboundIdentity => "the rule names an identity the store does not bind",
            Self::DuplicateHandle => "two rules carry one handle",
            Self::DuplicateIsolation => "an identity is isolated twice",
            Self::ForeignIdOutOfRange => "a foreign filter id is too large",
            Self::OutOfOrder => "an item is listed before the object that holds it",
        })
    }
}

/// Why a store could not read its platform. The first problem refuses the whole read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadError {
    /// The port could not run the read.
    Port { failure: StoreFailure },
    /// The listing was refused at `item`: an array element, an enumerated filter or a
    /// line, counted from 0.
    Refused { item: usize, problem: ReadProblem },
}

impl ReadError {
    /// The [`StoreFailure`] the installer sees: a refused listing is
    /// [`StoreFailure::Unavailable`], since the store cannot say what it holds.
    pub const fn failure(&self) -> StoreFailure {
        match self {
            Self::Port { failure } => *failure,
            Self::Refused { .. } => StoreFailure::Unavailable,
        }
    }
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Port { failure } => write!(f, "{failure}"),
            Self::Refused { item, problem } => {
                write!(
                    f,
                    "the platform listing was refused at item {item}: {problem}"
                )
            }
        }
    }
}

impl std::error::Error for ReadError {}

/// A refusal at `item`.
pub(super) const fn refused(item: usize, problem: ReadProblem) -> ReadError {
    ReadError::Refused { item, problem }
}
