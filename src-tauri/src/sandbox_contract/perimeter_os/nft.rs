//! Linux nftables (VM §4.4, Linux: "dedicated identities/net namespaces or equivalent
//! isolation, with narrowly scoped nftables rules"; VM-W15).
//!
//! Rendered. Every rule lives in chain [`NFT_CHAIN`] of table `inet` [`NFT_TABLE`], which
//! this product owns: a filter chain on the output hook at priority [`NFT_PRIORITY`] with
//! policy accept, so no other program's traffic is touched. A rule matches its broker the
//! way the [`IdentityKind`] says ([`NftSelector`]): `meta skuid` for a dedicated account,
//! `meta skuid` and `socket cgroupv2` for a cgroup, and nothing for a network namespace,
//! whose own table only the broker's traffic passes. Then come the destination
//! (`ip`/`ip6 daddr`, or `meta nfproto` for a whole family), the port (`meta l4proto {
//! tcp, udp }` and `th dport`) and the verdict. The comment carries the owner tag and the
//! store's handle (`yg1 <perimeter>:<transaction>:<handle>`); the handle is the store's,
//! not the kernel's, which the store looks up only to delete.
//!
//! Order carries V16's evaluation model: an identity's block rules are inserted at the
//! head of the chain, its allow rules just before its isolation rule (`yg1 isolate
//! <identity>`: the uid match, or nothing in a namespace, and `drop`), which comes last,
//! so an explicit block wins and anything unmatched is dropped. nftables makes a drop
//! final across base chains, so no rule in another table can permit what this chain
//! drops. The output hook sees every packet the broker sends, ICMP from a datagram socket
//! and data on connections it accepted included.
//!
//! Cgroups. nftables resolves a `socket cgroupv2` path to the cgroup's id when it loads
//! the rule, so a broker restart that recreates its cgroup leaves the rule matching a
//! cgroup that no longer exists. A cgroup binding therefore also names an account only
//! the broker runs as ([`NftSelector::Cgroup`]), its rules match both, and its isolation
//! rule matches the account alone: after such a restart the broker's allows stop matching
//! and the isolation rule drops everything, until the perimeter is installed again. We
//! expect `nft` to list the stale rule with a numeric cgroup id instead of the path, which
//! this parser refuses; that is a guess a real machine must confirm, and fails closed
//! either way.
//!
//! Parsed. [`NftStore::read`] runs `nft -j list table inet yougori` and accepts only what
//! this module renders: the metainfo, then the table, then the one chain as provisioned,
//! then rules each carrying a well-formed marker whose statements are exactly the
//! rendering of a bound identity and a perimeter rule. Anything else, an item listed
//! before the object that holds it included, refuses the whole read. An identity counts
//! as isolated only while its rules sit in the order above. Rules of other tables are
//! never listed (only table names are, by [`NftStore::isolate`]), so a look-alike with a
//! forged comment there is never read, reported or removed; that is also why the
//! installer's check that unrelated rules are unchanged covers only the owned table on
//! Linux.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use super::common::{
    allocate_handle, bind, isolation_marker, name_component, owned_entry, owned_marker,
    read_marker, refused, Binding, BindingError, CommandPort, Invocation, Marker, ReadError,
    ReadProblem, Selector,
};
use super::elevation::{ElevatedMechanism, ElevationScope};
use crate::foundation::ids::Digest;
use crate::sandbox_contract::destinations::{
    DestinationPort, IpPrefix, PerimeterPlatform, PerimeterRule, PortSelector, RuleAction,
};
use crate::sandbox_contract::perimeter_install::{
    ElevationGrant, IdentityKind, OwnedRule, RuleHandle, RuleStore, StoreFailure, StoreSnapshot,
};

/// The family of the owned table: one table for IPv4 and IPv6.
pub const NFT_FAMILY: &str = "inet";
/// The owned table.
pub const NFT_TABLE: &str = "yougori";
/// The owned chain.
pub const NFT_CHAIN: &str = "perimeter";
/// The owned chain's priority on the output hook (filter).
pub const NFT_PRIORITY: i64 = 0;

/// Longest cgroup path, in components, a binding accepts.
const MAX_CGROUP_LEVEL: usize = 16;

/// A cgroup v2 path below the root, such as `system.slice/yougori-broker.service`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CgroupPath(String);

impl CgroupPath {
    /// Accepts 1 to 16 `/`-separated components of letters, digits, `.`, `_`, `-`, `@`
    /// and `:`, with no empty, `.` or `..` component.
    pub fn new(path: &str) -> Result<Self, BindingError> {
        let components: Vec<&str> = path.split('/').collect();
        let valid = components.len() <= MAX_CGROUP_LEVEL
            && components
                .iter()
                .all(|component| name_component(component, 255));
        if valid {
            Ok(Self(path.to_owned()))
        } else {
            Err(BindingError::InvalidName)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The depth `socket cgroupv2 level` names: the number of components.
    pub fn level(&self) -> u64 {
        u64::try_from(self.0.split('/').count()).unwrap_or(u64::MAX)
    }

    /// Whether `other` is this cgroup or below it, at a component boundary.
    pub fn contains(&self, other: &Self) -> bool {
        other
            .0
            .strip_prefix(&self.0)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
    }
}

impl TryFrom<String> for CgroupPath {
    type Error = BindingError;

    fn try_from(path: String) -> Result<Self, Self::Error> {
        Self::new(&path)
    }
}

impl From<CgroupPath> for String {
    fn from(path: CgroupPath) -> Self {
        path.0
    }
}

/// A named network namespace (`ip netns`), such as `yougori-broker`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct NamespaceName(String);

impl NamespaceName {
    /// Accepts 1 to 64 letters, digits, `.`, `_`, `-`, `@` and `:`, never `.` or `..`.
    pub fn new(name: &str) -> Result<Self, BindingError> {
        if name_component(name, 64) {
            Ok(Self(name.to_owned()))
        } else {
            Err(BindingError::InvalidName)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for NamespaceName {
    type Error = BindingError;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        Self::new(&name)
    }
}

impl From<NamespaceName> for String {
    fn from(name: NamespaceName) -> Self {
        name.0
    }
}

/// How an nftables rule names its broker identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NftSelector {
    /// `meta skuid <uid>`: an account only the broker runs as
    /// ([`IdentityKind::DedicatedAccount`]).
    SocketUid { uid: u32 },
    /// `meta skuid <uid>` and `socket cgroupv2 level <depth> "<path>"`: a cgroup only the
    /// broker runs in, as an account only the broker runs as, which alone isolates it
    /// across restarts ([`IdentityKind::Cgroup`]; see the module docs).
    Cgroup { path: CgroupPath, uid: u32 },
    /// The table lives in the broker's own network namespace and its rules match no
    /// identity ([`IdentityKind::NetworkNamespace`]).
    Namespace { name: NamespaceName },
}

impl Selector for NftSelector {
    fn kind(&self) -> IdentityKind {
        match self {
            Self::SocketUid { .. } => IdentityKind::DedicatedAccount,
            Self::Cgroup { .. } => IdentityKind::Cgroup,
            Self::Namespace { .. } => IdentityKind::NetworkNamespace,
        }
    }

    fn check(&self) -> Result<(), BindingError> {
        match self.uid() {
            Some(uid) if uid == 0 || uid == u32::MAX => {
                Err(BindingError::PrivilegedAccount { uid })
            }
            _ => Ok(()),
        }
    }

    fn overlaps(&self, other: &Self) -> bool {
        let same_uid = self.uid().is_some() && self.uid() == other.uid();
        let nested = match (self, other) {
            (Self::Cgroup { path, .. }, Self::Cgroup { path: other, .. }) => {
                path.contains(other) || other.contains(path)
            }
            _ => false,
        };
        // A namespace binding is its store's only one (`NamespaceNotAlone`).
        same_uid || nested || self == other
    }
}

impl NftSelector {
    /// The account the rules match, which a namespace binding has none of.
    pub const fn uid(&self) -> Option<u32> {
        match self {
            Self::SocketUid { uid } | Self::Cgroup { uid, .. } => Some(*uid),
            Self::Namespace { .. } => None,
        }
    }
}

fn matches(left: Value, right: Value) -> Value {
    json!({"match": {"op": "==", "left": left, "right": right}})
}

fn uid_statement(uid: u32) -> Value {
    matches(json!({"meta": {"key": "skuid"}}), json!(uid))
}

/// The statements a perimeter rule of `selector`'s identity starts with; none for a
/// namespace.
fn identity_statements(selector: &NftSelector) -> Vec<Value> {
    match selector {
        NftSelector::SocketUid { uid } => vec![uid_statement(*uid)],
        NftSelector::Cgroup { path, uid } => vec![
            uid_statement(*uid),
            matches(
                json!({"socket": {"key": "cgroupv2", "level": path.level()}}),
                json!(path.as_str()),
            ),
        ],
        NftSelector::Namespace { .. } => Vec::new(),
    }
}

fn address_statement(prefix: &IpPrefix) -> Value {
    let (protocol, family, width) = match prefix.network() {
        IpAddr::V4(_) => ("ip", "ipv4", 32),
        IpAddr::V6(_) => ("ip6", "ipv6", 128),
    };
    if prefix.length() == 0 {
        return matches(json!({"meta": {"key": "nfproto"}}), json!(family));
    }
    let address = prefix.network().to_string();
    let right = if prefix.length() == width {
        json!(address)
    } else {
        json!({"prefix": {"addr": address, "len": prefix.length()}})
    };
    matches(
        json!({"payload": {"protocol": protocol, "field": "daddr"}}),
        right,
    )
}

fn verdict(action: RuleAction) -> Value {
    match action {
        RuleAction::Allow => json!({"accept": null}),
        RuleAction::Block => json!({"drop": null}),
    }
}

/// The statements of `rule` for `selector`, as `nft -j` lists them: the identity match,
/// the destination, the ports and the verdict.
pub fn rule_statements(selector: &NftSelector, rule: &PerimeterRule) -> Vec<Value> {
    let mut statements = identity_statements(selector);
    statements.push(address_statement(&rule.prefix));
    if let PortSelector::Only(port) = rule.ports {
        statements.push(matches(
            json!({"meta": {"key": "l4proto"}}),
            json!({"set": ["tcp", "udp"]}),
        ));
        statements.push(matches(
            json!({"payload": {"protocol": "th", "field": "dport"}}),
            json!(port.get()),
        ));
    }
    statements.push(verdict(rule.action));
    statements
}

/// The statements of `selector`'s isolation rule: the uid match (none in a namespace)
/// and `drop`. A cgroup binding's isolation matches its account alone, which survives a
/// restart that recreates the cgroup.
pub fn isolation_statements(selector: &NftSelector) -> Vec<Value> {
    let mut statements: Vec<Value> = selector.uid().map(uid_statement).into_iter().collect();
    statements.push(verdict(RuleAction::Block));
    statements
}

/// The left and right side of a `match` statement.
fn match_sides(statement: &Value) -> Option<(&Value, &Value)> {
    let inner = statement.get("match")?;
    Some((inner.get("left")?, inner.get("right")?))
}

fn decode_address(statement: &Value) -> Option<IpPrefix> {
    let (left, right) = match_sides(statement)?;
    if left.get("meta").and_then(|meta| meta.get("key")) == Some(&json!("nfproto")) {
        let network: IpAddr = match right.as_str()? {
            "ipv4" => Ipv4Addr::UNSPECIFIED.into(),
            "ipv6" => Ipv6Addr::UNSPECIFIED.into(),
            _ => return None,
        };
        return IpPrefix::new(network, 0).ok();
    }
    if let Some(address) = right.as_str() {
        return Some(IpPrefix::host(address.parse().ok()?));
    }
    let prefix = right.get("prefix")?;
    let network: IpAddr = prefix.get("addr")?.as_str()?.parse().ok()?;
    let length = u8::try_from(prefix.get("len")?.as_u64()?).ok()?;
    IpPrefix::new(network, length).ok()
}

/// Recovers a perimeter rule from the statements after the identity match. The caller
/// re-renders it and compares, so this may be lenient about everything it does not read.
fn decode_body(statements: &[Value]) -> Option<PerimeterRule> {
    let (address, rest) = statements.split_first()?;
    let (last, middle) = rest.split_last()?;
    let action = if *last == verdict(RuleAction::Allow) {
        RuleAction::Allow
    } else if *last == verdict(RuleAction::Block) {
        RuleAction::Block
    } else {
        return None;
    };
    let ports = match middle {
        [] => PortSelector::All,
        [_, port] => {
            let (_, right) = match_sides(port)?;
            let number = u16::try_from(right.as_u64()?).ok()?;
            PortSelector::Only(DestinationPort::new(number).ok()?)
        }
        _ => return None,
    };
    Some(PerimeterRule {
        action,
        prefix: decode_address(address)?,
        ports,
    })
}

/// The bound identity and perimeter rule whose rendering `statements` is exactly.
fn decode_rule(
    bindings: &BTreeMap<Digest, Binding<NftSelector>>,
    statements: &[Value],
) -> Option<(Digest, PerimeterRule)> {
    bindings.values().find_map(|binding| {
        let head = identity_statements(&binding.selector);
        let rule = decode_body(statements.strip_prefix(head.as_slice())?)?;
        (rule_statements(&binding.selector, &rule).as_slice() == statements)
            .then_some((binding.broker.identity, rule))
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    nftables: Vec<Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Item {
    Metainfo(Metainfo),
    Table(TableItem),
    Chain(ChainItem),
    Rule(RuleItem),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Metainfo {
    #[serde(rename = "version")]
    _version: String,
    #[serde(rename = "release_name")]
    _release_name: String,
    json_schema_version: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TableItem {
    family: String,
    name: String,
    #[serde(rename = "handle")]
    _handle: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChainItem {
    family: String,
    table: String,
    name: String,
    #[serde(rename = "handle")]
    _handle: u64,
    #[serde(rename = "type")]
    kind: Option<String>,
    hook: Option<String>,
    prio: Option<i64>,
    policy: Option<String>,
}

/// One element of `nft -j list tables` after the metainfo.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TablesEntry {
    table: NamedTable,
}

/// A table as `nft -j list tables` names it; other programs' tables may carry fields
/// this module does not read.
#[derive(Deserialize)]
struct NamedTable {
    family: String,
    name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleItem {
    family: String,
    table: String,
    chain: String,
    handle: u64,
    comment: Option<String>,
    expr: Vec<Value>,
}

/// Where a rule of one identity sits in the chain.
#[derive(Clone, Copy)]
enum Placement {
    Rule(RuleAction),
    Isolation,
}

/// The owned table as read back.
#[derive(Debug, Default)]
pub(super) struct Listing {
    pub(super) snapshot: StoreSnapshot,
    /// The kernel handle of each owned rule, which `delete rule` names.
    pub(super) kernel: BTreeMap<RuleHandle, u64>,
    /// The kernel handle of each identity's isolation rule.
    pub(super) isolation: BTreeMap<Digest, u64>,
}

/// The identities whose rules sit in the order the evaluation model needs: blocks, then
/// allows, then the isolation rule last.
fn isolated(order: &[(Digest, Placement)]) -> BTreeSet<Digest> {
    let identities: BTreeSet<Digest> = order
        .iter()
        .filter(|(_, placement)| matches!(placement, Placement::Isolation))
        .map(|(identity, _)| *identity)
        .collect();
    identities
        .into_iter()
        .filter(|identity| {
            let mut stage = 0_u8;
            order
                .iter()
                .filter(|(other, _)| other == identity)
                .all(|(_, placement)| {
                    let next = match placement {
                        Placement::Rule(RuleAction::Block) => 0,
                        Placement::Rule(RuleAction::Allow) => 1,
                        Placement::Isolation => 2,
                    };
                    let in_order = stage < 2 && next >= stage;
                    stage = next;
                    in_order
                })
        })
        .collect()
}

/// Parses `nft -j list table inet yougori` output, accepting only what this module
/// renders for `bindings`.
pub(super) fn parse_listing(
    text: &str,
    bindings: &BTreeMap<Digest, Binding<NftSelector>>,
) -> Result<Listing, ReadError> {
    use ReadProblem as P;
    let envelope: Envelope = serde_json::from_str(text).map_err(|_| refused(0, P::Malformed))?;
    let count = envelope.nftables.len();
    let mut listing = Listing::default();
    let (mut table, mut chain) = (false, false);
    let mut kernel_handles = BTreeSet::new();
    let mut order = Vec::new();
    for (index, value) in envelope.nftables.into_iter().enumerate() {
        let item: Item = serde_json::from_value(value).map_err(|_| refused(index, P::Malformed))?;
        match item {
            Item::Metainfo(meta) => {
                if index != 0 || meta.json_schema_version != 1 {
                    return Err(refused(index, P::Malformed));
                }
            }
            _ if index == 0 => return Err(refused(index, P::Malformed)),
            Item::Table(item) => {
                if item.family != NFT_FAMILY || item.name != NFT_TABLE {
                    return Err(refused(index, P::WrongObject));
                }
                if std::mem::replace(&mut table, true) {
                    return Err(refused(index, P::ObjectShape));
                }
            }
            Item::Chain(item) => {
                if item.family != NFT_FAMILY || item.table != NFT_TABLE {
                    return Err(refused(index, P::WrongObject));
                }
                if !table {
                    return Err(refused(index, P::OutOfOrder));
                }
                let provisioned = item.name == NFT_CHAIN
                    && item.kind.as_deref() == Some("filter")
                    && item.hook.as_deref() == Some("output")
                    && item.prio == Some(NFT_PRIORITY)
                    && item.policy.as_deref() == Some("accept");
                if !provisioned || std::mem::replace(&mut chain, true) {
                    return Err(refused(index, P::ObjectShape));
                }
            }
            Item::Rule(item) => {
                if item.family != NFT_FAMILY || item.table != NFT_TABLE || item.chain != NFT_CHAIN {
                    return Err(refused(index, P::WrongObject));
                }
                if !table || !chain {
                    return Err(refused(index, P::OutOfOrder));
                }
                if !kernel_handles.insert(item.handle) {
                    return Err(refused(index, P::Malformed));
                }
                match item.comment.as_deref().map_or(Marker::Absent, read_marker) {
                    Marker::Absent => return Err(refused(index, P::Unmarked)),
                    Marker::Malformed | Marker::Isolation { identity: None } => {
                        return Err(refused(index, P::BadMarker))
                    }
                    Marker::Owned { tag, handle } => {
                        let (identity, rule) = decode_rule(bindings, &item.expr)
                            .ok_or(refused(index, P::NotRendered))?;
                        if listing.kernel.insert(handle, item.handle).is_some() {
                            return Err(refused(index, P::DuplicateHandle));
                        }
                        listing
                            .snapshot
                            .entries
                            .insert(handle, owned_entry(tag, identity, rule));
                        order.push((identity, Placement::Rule(rule.action)));
                    }
                    Marker::Isolation {
                        identity: Some(identity),
                    } => {
                        let binding = bindings
                            .get(&identity)
                            .ok_or(refused(index, P::UnboundIdentity))?;
                        if item.expr != isolation_statements(&binding.selector) {
                            return Err(refused(index, P::NotRendered));
                        }
                        if listing.isolation.insert(identity, item.handle).is_some() {
                            return Err(refused(index, P::DuplicateIsolation));
                        }
                        order.push((identity, Placement::Isolation));
                    }
                }
            }
        }
    }
    if !table || !chain {
        return Err(refused(count, P::ObjectShape));
    }
    listing.snapshot.isolated = isolated(&order);
    Ok(listing)
}

/// Whether `nft -j list tables` output names the owned table.
pub(super) fn lists_owned_table(text: &str) -> Result<bool, ReadError> {
    use ReadProblem as P;
    let envelope: Envelope = serde_json::from_str(text).map_err(|_| refused(0, P::Malformed))?;
    let mut items = envelope.nftables.into_iter().enumerate();
    match items.next() {
        Some((_, value)) => match serde_json::from_value(value) {
            Ok(Item::Metainfo(meta)) if meta.json_schema_version == 1 => {}
            _ => return Err(refused(0, P::Malformed)),
        },
        None => return Err(refused(0, P::Malformed)),
    }
    let mut owned = false;
    for (index, value) in items {
        let entry: TablesEntry =
            serde_json::from_value(value).map_err(|_| refused(index, P::Malformed))?;
        owned |= entry.table.family == NFT_FAMILY && entry.table.name == NFT_TABLE;
    }
    Ok(owned)
}

/// The nftables rule store: the owned table read and changed through a [`CommandPort`].
pub struct NftStore<P> {
    port: P,
    bindings: BTreeMap<Digest, Binding<NftSelector>>,
    namespace: Option<NamespaceName>,
}

impl<P: CommandPort> NftStore<P> {
    /// A store serving `bindings`. A namespace binding must be the only one; its commands
    /// run in that namespace.
    pub fn new(port: P, bindings: Vec<Binding<NftSelector>>) -> Result<Self, BindingError> {
        let bindings = bind(bindings)?;
        let namespaces: Vec<NamespaceName> = bindings
            .values()
            .filter_map(|binding| match &binding.selector {
                NftSelector::Namespace { name } => Some(name.clone()),
                _ => None,
            })
            .collect();
        let namespace = match namespaces.as_slice() {
            [] => None,
            [name] if bindings.len() == 1 => Some(name.clone()),
            _ => return Err(BindingError::NamespaceNotAlone),
        };
        Ok(Self {
            port,
            bindings,
            namespace,
        })
    }

    pub fn port(&self) -> &P {
        &self.port
    }

    pub fn port_mut(&mut self) -> &mut P {
        &mut self.port
    }

    fn argv(&self, arguments: &[&str]) -> Vec<String> {
        let mut argv: Vec<String> = Vec::new();
        if let Some(namespace) = &self.namespace {
            argv.extend(["ip", "netns", "exec", namespace.as_str()].map(str::to_owned));
        }
        argv.push("nft".to_owned());
        argv.extend(arguments.iter().map(|argument| (*argument).to_owned()));
        argv
    }

    /// The read: `nft -j list table inet yougori`.
    pub fn list_invocation(&self) -> Invocation {
        Invocation {
            argv: self.argv(&["-j", "list", "table", NFT_FAMILY, NFT_TABLE]),
            input: None,
        }
    }

    /// The read that proves the owned table absent: `nft -j list tables`, which names every
    /// table and lists no rules.
    pub fn tables_invocation(&self) -> Invocation {
        Invocation {
            argv: self.argv(&["-j", "list", "tables"]),
            input: None,
        }
    }

    /// A write: `nft -j -f -` with `commands` as one batch, which nftables commits
    /// atomically.
    pub fn batch_invocation(&self, commands: Vec<Value>) -> Invocation {
        Invocation {
            argv: self.argv(&["-j", "-f", "-"]),
            input: Some(json!({ "nftables": commands }).to_string()),
        }
    }

    fn listing(&self) -> Result<Listing, ReadError> {
        let text = self
            .port
            .read(&self.list_invocation())
            .map_err(|failure| ReadError::Port { failure })?;
        parse_listing(&text, &self.bindings)
    }

    /// Reads the owned table, with the reason when it is refused.
    pub fn read(&self) -> Result<StoreSnapshot, ReadError> {
        self.listing().map(|listing| listing.snapshot)
    }

    /// Provisions the owned table and chain when absent and appends `identity`'s
    /// isolation rule unless it has one. An elevated operation of its own
    /// ([`NftStore::isolation_scope`]). It writes only over a listing the store accepts,
    /// or when `nft list tables` proves the owned table absent; any other failed or
    /// refused read refuses without writing.
    pub fn isolate(&mut self, identity: Digest) -> Result<(), StoreFailure> {
        let statements = isolation_statements(
            &self
                .bindings
                .get(&identity)
                .ok_or(StoreFailure::Rejected)?
                .selector,
        );
        match self.listing() {
            Ok(listing) if listing.isolation.contains_key(&identity) => return Ok(()),
            Ok(_) => {}
            // `nft list table` fails when the table does not exist, and for other reasons.
            Err(ReadError::Port {
                failure: StoreFailure::Rejected,
            }) => {
                let text = self.port.read(&self.tables_invocation())?;
                if lists_owned_table(&text).map_err(|error| error.failure())? {
                    return Err(StoreFailure::Rejected);
                }
            }
            Err(error) => return Err(error.failure()),
        }
        let invocation = self.batch_invocation(vec![
            json!({"add": {"table": {"family": NFT_FAMILY, "name": NFT_TABLE}}}),
            json!({"add": {"chain": {
                "family": NFT_FAMILY, "table": NFT_TABLE, "name": NFT_CHAIN,
                "type": "filter", "hook": "output", "prio": NFT_PRIORITY, "policy": "accept"
            }}}),
            json!({"add": {"rule": {
                "family": NFT_FAMILY, "table": NFT_TABLE, "chain": NFT_CHAIN,
                "expr": statements, "comment": isolation_marker(identity)
            }}}),
        ]);
        self.port.write(&invocation)
    }

    fn mechanism(&self) -> ElevatedMechanism {
        ElevatedMechanism::Nftables {
            reads: vec![self.list_invocation().argv, self.tables_invocation().argv],
            write: self.argv(&["-j", "-f", "-"]),
            family: NFT_FAMILY.to_owned(),
            table: NFT_TABLE.to_owned(),
            chain: NFT_CHAIN.to_owned(),
        }
    }

    /// The exact elevation `grant` needs here; an identity it adds rules for that this
    /// store does not bind refuses the scope.
    pub fn elevation_scope(&self, grant: &ElevationGrant) -> Result<ElevationScope, BindingError> {
        ElevationScope::for_grant(
            PerimeterPlatform::Linux,
            self.mechanism(),
            grant,
            &self.bindings,
        )
    }

    /// The exact elevation isolating `identity` needs here.
    pub fn isolation_scope(&self, identity: Digest) -> Result<ElevationScope, BindingError> {
        ElevationScope::for_isolation(
            PerimeterPlatform::Linux,
            self.mechanism(),
            identity,
            &self.bindings,
        )
    }
}

impl<P: CommandPort> RuleStore for NftStore<P> {
    fn snapshot(&self) -> Result<StoreSnapshot, StoreFailure> {
        self.read().map_err(|error| error.failure())
    }

    /// Inserts the rule: a block at the head of the chain, an allow just before its
    /// identity's isolation rule (appended when there is none).
    fn add(
        &mut self,
        grant: &ElevationGrant,
        rule: &OwnedRule,
    ) -> Result<RuleHandle, StoreFailure> {
        if !grant.permits_add(rule) {
            return Err(StoreFailure::NotGranted);
        }
        let statements = rule_statements(
            &self
                .bindings
                .get(&rule.scoped.identity)
                .ok_or(StoreFailure::Rejected)?
                .selector,
            &rule.scoped.rule,
        );
        let listing = self.listing().map_err(|error| error.failure())?;
        let taken: BTreeSet<RuleHandle> = listing.kernel.keys().copied().collect();
        let handle = allocate_handle(rule.tag, &taken)?;
        let mut body = Map::new();
        body.insert("family".to_owned(), json!(NFT_FAMILY));
        body.insert("table".to_owned(), json!(NFT_TABLE));
        body.insert("chain".to_owned(), json!(NFT_CHAIN));
        body.insert("expr".to_owned(), Value::Array(statements));
        body.insert("comment".to_owned(), json!(owned_marker(rule.tag, handle)));
        let verb = match (
            rule.scoped.rule.action,
            listing.isolation.get(&rule.scoped.identity),
        ) {
            (RuleAction::Block, _) => "insert",
            (RuleAction::Allow, Some(position)) => {
                body.insert("handle".to_owned(), json!(position));
                "insert"
            }
            (RuleAction::Allow, None) => "add",
        };
        let mut command = Map::new();
        command.insert(verb.to_owned(), json!({ "rule": body }));
        let invocation = self.batch_invocation(vec![Value::Object(command)]);
        self.port.write(&invocation)?;
        Ok(handle)
    }

    /// Deletes the owned rule under `handle` by its kernel handle, in the owned chain
    /// only.
    fn remove(&mut self, grant: &ElevationGrant, handle: RuleHandle) -> Result<(), StoreFailure> {
        let listing = self.listing().map_err(|error| error.failure())?;
        let (Some(entry), Some(kernel)) =
            (listing.snapshot.entry(handle), listing.kernel.get(&handle))
        else {
            return Err(StoreFailure::UnknownHandle { handle });
        };
        if !grant.permits_remove(handle, entry) {
            return Err(StoreFailure::NotGranted);
        }
        let invocation = self.batch_invocation(vec![json!({"delete": {"rule": {
            "family": NFT_FAMILY, "table": NFT_TABLE, "chain": NFT_CHAIN, "handle": kernel
        }}})]);
        self.port.write(&invocation)
    }
}
