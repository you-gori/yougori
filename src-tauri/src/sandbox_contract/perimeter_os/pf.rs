//! macOS pf (VM §4.4, macOS: "verify the exact supported sandbox/network enforcement
//! APIs and identities. A pf user rule cannot distinguish every same-user process
//! automatically"; VM-W15; VM-P27).
//!
//! Not isolation. pf matches `user` only on TCP and UDP sockets, and an unprivileged
//! macOS process can send ICMP through a datagram socket, which no `user` rule matches;
//! dropping all ICMP would change unrelated traffic on the PC. So the TCP and UDP default
//! deny this store can add ([`PfStore::add_tcp_udp_deny`]) does not isolate the broker,
//! a snapshot never reports any identity isolated, and V16 refuses to install a perimeter
//! over this store (`ScopeNotIsolated`). macOS needs another mechanism that sees every
//! flow of the signed broker, for example a Network Extension content filter; which one,
//! and how it reports its rules, is open. The rendering, parsing and changes below remain
//! for the TCP and UDP part such a mechanism may keep.
//!
//! Rendered. A store owns one anchor per perimeter ([`PfAnchor::for_perimeter`]:
//! `yougori/<the perimeter digest in base32>`), since pf's 63-byte label has no room for
//! the perimeter. The anchor's whole rule set is rendered as text and loaded with `pfctl
//! -a <anchor> -f -`, which replaces it atomically; pf has no per-rule add or remove.
//! Each perimeter rule becomes two `quick` rules, for TCP and UDP, matching `user =
//! <uid>` and labelled `yg1 <transaction>:<handle>`. Block rules come first, then pass
//! rules, then each identity's TCP and UDP deny (`block drop out quick proto tcp|udp all
//! user = <uid> label "yg1 isolate"`).
//!
//! Identity. V16 accepts only a signing identity on macOS, which pf cannot match: a
//! [`PfSelector`] binds it to the uid of an account only the signed broker daemon runs
//! as. That only the signed broker runs as that account, and that no `pass quick` for
//! the same uid earlier in the main ruleset or in another anchor decides first, are
//! outside what a pf listing shows.
//!
//! Printed form. The store renders each line as `pfctl -sr` prints it, so the listing can
//! be compared exactly. Known from pfctl's printer (`print_rule`, `print_fromto`,
//! `print_addr`, `print_ugid` and `print_port` in the OpenBSD and FreeBSD
//! `pfctl_parser.c` macOS's pfctl derives from): `from any to any` without ports prints
//! as `all`; a block without a return policy prints `block drop`; `user = <uid>` prints
//! the number; an address with a full mask prints without `/len` and an all-zero one as
//! `any`; a TCP pass prints `flags S/SA keep state` and a UDP pass `keep state`, after
//! the user and before the label. Ports print as the service name `getservbyport` finds,
//! else the number. The store writes numbers, which pf.conf accepts, and the parser
//! accepts a port as its number or as the name [`PF_SERVICE_NAMES`] gives it and as no
//! other name; anything else refuses the read.
//!
//! Needs a real Mac: that macOS's own pfctl prints exactly these forms (Apple's pf has
//! changes of its own); which names its `/etc/services` gives for these ports, assumed
//! here to be IANA's; whether a numeric-output option exists; and the IPv6 text form
//! (`inet_ntop` prints an IPv4-compatible address such as `::102:304` as `::1.2.3.4`,
//! which the parser refuses). Every one of these fails closed. Enabling pf, referencing
//! the anchor from the main ruleset (`anchor "yougori/*"`) and killing the states of
//! connections a removed allow no longer permits are machine-wide changes outside this
//! module.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use super::common::{
    allocate_handle, bind, decimal, owned_entry, read_short_marker, refused,
    short_isolation_marker, short_owned_marker, Binding, BindingError, CommandPort, Invocation,
    Marker, ReadError, ReadProblem, Selector,
};
use super::elevation::{ElevatedMechanism, ElevationScope};
use crate::foundation::coordination::PerimeterId;
use crate::foundation::ids::Digest;
use crate::sandbox_contract::destinations::{
    DestinationPort, IpPrefix, PerimeterPlatform, PerimeterRule, PortSelector, RuleAction,
};
use crate::sandbox_contract::perimeter_install::{
    ElevationGrant, IdentityKind, OwnedRule, OwnerTag, RuleHandle, RuleStore, StoreFailure,
    StoreSnapshot, TransactionId,
};

/// The parent of every anchor this product owns.
pub const PF_ANCHOR_ROOT: &str = "yougori";
/// The longest label pf keeps (PF_RULE_LABEL_SIZE less the terminating NUL).
pub const PF_LABEL_MAX: usize = 63;
/// The service names a listing may print for a port, TCP and UDP alike: IANA's, assumed
/// to be macOS's `/etc/services` (a guess a real Mac must confirm).
pub const PF_SERVICE_NAMES: [(u16, &str); 5] = [
    (22, "ssh"),
    (53, "domain"),
    (80, "http"),
    (123, "ntp"),
    (443, "https"),
];

/// The lowercase RFC 4648 base32 text of `bytes`, without padding.
fn base32(bytes: &[u8]) -> String {
    fn digit(value: u32) -> char {
        let value = u8::try_from(value & 31).unwrap_or(0);
        if value < 26 {
            char::from(b'a' + value)
        } else {
            char::from(b'2' + (value - 26))
        }
    }
    let mut text = String::new();
    let (mut buffer, mut bits) = (0_u32, 0_u32);
    for byte in bytes {
        buffer = ((buffer << 8) | u32::from(*byte)) & 0xffff;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            text.push(digit(buffer >> bits));
        }
    }
    if bits > 0 {
        text.push(digit(buffer << (5 - bits)));
    }
    text
}

/// The anchor that holds one perimeter's rules.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PfAnchor(String);

impl PfAnchor {
    /// `yougori/<perimeter>`, the perimeter digest as 52 base32 characters (an anchor
    /// name component holds at most 63).
    pub fn for_perimeter(perimeter: PerimeterId) -> Self {
        Self(format!(
            "{PF_ANCHOR_ROOT}/{}",
            base32(perimeter.digest().as_bytes())
        ))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// How a pf rule names its broker identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PfSelector {
    /// `user = <uid>`: the account only the signed broker daemon runs as
    /// ([`IdentityKind::SigningIdentity`]; see the module docs for what pf cannot check).
    User { uid: u32 },
}

impl PfSelector {
    pub const fn uid(&self) -> u32 {
        match self {
            Self::User { uid } => *uid,
        }
    }
}

impl Selector for PfSelector {
    fn kind(&self) -> IdentityKind {
        IdentityKind::SigningIdentity
    }

    fn check(&self) -> Result<(), BindingError> {
        let uid = self.uid();
        if uid == 0 || uid == u32::MAX {
            return Err(BindingError::PrivilegedAccount { uid });
        }
        Ok(())
    }

    fn overlaps(&self, other: &Self) -> bool {
        self.uid() == other.uid()
    }
}

fn family(prefix: &IpPrefix) -> (&'static str, u8) {
    match prefix.network() {
        IpAddr::V4(_) => ("inet", 32),
        IpAddr::V6(_) => ("inet6", 128),
    }
}

/// The source, destination and port as pfctl prints them: `all`, or `from any to <dst>`
/// and ` port = <number>`.
fn from_to(prefix: &IpPrefix, ports: PortSelector) -> String {
    let (_, width) = family(prefix);
    let to = if prefix.length() == 0 {
        "any".to_owned()
    } else if prefix.length() == width {
        prefix.network().to_string()
    } else {
        prefix.to_string()
    };
    match ports {
        PortSelector::All if prefix.length() == 0 => "all".to_owned(),
        PortSelector::All => format!("from any to {to}"),
        PortSelector::Only(port) => format!("from any to {to} port = {port}"),
    }
}

/// The TCP and UDP lines of `rule` for `uid`, labelled `label`, as pfctl prints them.
pub fn rule_lines(uid: u32, rule: &PerimeterRule, label: &str) -> [String; 2] {
    let (af, _) = family(&rule.prefix);
    let from_to = from_to(&rule.prefix, rule.ports);
    match rule.action {
        RuleAction::Block => ["tcp", "udp"].map(|protocol| {
            format!(
                "block drop out quick {af} proto {protocol} {from_to} user = {uid} label \
                 \"{label}\""
            )
        }),
        RuleAction::Allow => [
            format!(
                "pass out quick {af} proto tcp {from_to} user = {uid} flags S/SA keep state \
                 label \"{label}\""
            ),
            format!(
                "pass out quick {af} proto udp {from_to} user = {uid} keep state label \
                 \"{label}\""
            ),
        ],
    }
}

/// The TCP and UDP deny lines for `uid`, as pfctl prints them. They do not cover ICMP.
pub fn deny_lines(uid: u32) -> [String; 2] {
    let label = short_isolation_marker();
    ["tcp", "udp"].map(|protocol| {
        format!("block drop out quick proto {protocol} all user = {uid} label \"{label}\"")
    })
}

/// One owned rule of the anchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PfRule {
    transaction: TransactionId,
    identity: Digest,
    uid: u32,
    rule: PerimeterRule,
}

/// An anchor's rules: the owned rules by handle and the identities with a TCP and UDP
/// deny, with their uids.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct AnchorRules {
    rules: BTreeMap<RuleHandle, PfRule>,
    denied: BTreeMap<Digest, u32>,
}

/// The canonical text of `anchor`: blocks, then passes, each by handle, then the denies
/// by identity; every line ends with a newline.
fn render(anchor: &AnchorRules) -> String {
    let mut lines: Vec<String> = Vec::new();
    for action in [RuleAction::Block, RuleAction::Allow] {
        for (handle, owned) in &anchor.rules {
            if owned.rule.action == action {
                let label = short_owned_marker(owned.transaction, *handle);
                lines.extend(rule_lines(owned.uid, &owned.rule, &label));
            }
        }
    }
    for uid in anchor.denied.values() {
        lines.extend(deny_lines(*uid));
    }
    lines.iter().map(|line| format!("{line}\n")).collect()
}

/// The text before ` label "` and the label, when the line ends with a quoted label.
fn split_label(line: &str) -> Option<(&str, &str)> {
    let (body, label) = line.rsplit_once(" label \"")?;
    let label = label.strip_suffix('"')?;
    (!label.contains('"')).then_some((body, label))
}

/// `line` with a port pfctl printed as a name in [`PF_SERVICE_NAMES`] replaced by its
/// number; any other text is left for the comparison to refuse.
fn numeric_ports(line: &str) -> String {
    let tokens: Vec<&str> = line.split(' ').collect();
    tokens
        .iter()
        .enumerate()
        .map(|(at, token)| {
            let after_port = at.checked_sub(2).and_then(|start| tokens.get(start..at))
                == Some(&["port", "="][..]);
            let number = PF_SERVICE_NAMES
                .iter()
                .find(|(_, name)| name == token)
                .map(|(number, _)| number.to_string());
            match number {
                Some(number) if after_port => number,
                _ => (*token).to_owned(),
            }
        })
        .collect::<Vec<String>>()
        .join(" ")
}

fn user_of(tokens: &[&str]) -> Option<u32> {
    let at = tokens.iter().position(|token| *token == "user")?;
    match tokens.get(at + 1..at + 3)? {
        ["=", uid] => u32::try_from(decimal(uid)?).ok(),
        _ => None,
    }
}

/// Recovers a perimeter rule from a line's tokens. The caller re-renders the whole anchor
/// and compares, so this may be lenient about everything it does not read.
fn decode_rule(tokens: &[&str]) -> Option<PerimeterRule> {
    let action = match *tokens.first()? {
        "block" => RuleAction::Block,
        "pass" => RuleAction::Allow,
        _ => return None,
    };
    let unspecified: IpAddr = match *tokens
        .iter()
        .find(|token| matches!(**token, "inet" | "inet6"))?
    {
        "inet" => Ipv4Addr::UNSPECIFIED.into(),
        _ => Ipv6Addr::UNSPECIFIED.into(),
    };
    let any = || IpPrefix::new(unspecified, 0).ok();
    let Some(to) = tokens.iter().position(|token| *token == "to") else {
        tokens.contains(&"all").then_some(())?;
        return Some(PerimeterRule {
            action,
            prefix: any()?,
            ports: PortSelector::All,
        });
    };
    let prefix = match *tokens.get(to + 1)? {
        "any" => any()?,
        text => match text.split_once('/') {
            Some((address, length)) => {
                IpPrefix::new(address.parse().ok()?, u8::try_from(decimal(length)?).ok()?).ok()?
            }
            None => IpPrefix::host(text.parse().ok()?),
        },
    };
    let ports = match tokens.get(to + 2..to + 5) {
        Some(["port", "=", number]) => {
            PortSelector::Only(DestinationPort::new(u16::try_from(decimal(number)?).ok()?).ok()?)
        }
        _ => PortSelector::All,
    };
    Some(PerimeterRule {
        action,
        prefix,
        ports,
    })
}

/// Parses `pfctl -a <anchor> -sr` output for `perimeter`'s anchor, accepting only the
/// canonical rendering of what it decodes, up to ports printed as the names in
/// [`PF_SERVICE_NAMES`].
pub(super) fn parse_anchor(
    text: &str,
    perimeter: PerimeterId,
    bindings: &BTreeMap<Digest, Binding<PfSelector>>,
) -> Result<AnchorRules, ReadError> {
    use ReadProblem as P;
    let lines: Vec<String> = if text.is_empty() {
        Vec::new()
    } else {
        text.strip_suffix('\n')
            .ok_or(refused(0, P::Malformed))?
            .split('\n')
            .map(numeric_ports)
            .collect()
    };
    let identity_of = |uid: u32| {
        bindings
            .values()
            .find(|binding| binding.selector.uid() == uid)
            .map(|binding| binding.broker.identity)
    };
    let mut anchor = AnchorRules::default();
    for (index, line) in lines.iter().enumerate() {
        let (body, label) = split_label(line).ok_or(refused(index, P::Malformed))?;
        let tokens: Vec<&str> = body.split(' ').collect();
        let uid = user_of(&tokens).ok_or(refused(index, P::Malformed))?;
        match read_short_marker(label, perimeter) {
            Marker::Absent => return Err(refused(index, P::Unmarked)),
            Marker::Malformed => return Err(refused(index, P::BadMarker)),
            Marker::Isolation { .. } => {
                let identity = identity_of(uid).ok_or(refused(index, P::UnboundIdentity))?;
                anchor.denied.insert(identity, uid);
            }
            Marker::Owned { tag, handle } => {
                let identity = identity_of(uid).ok_or(refused(index, P::UnboundIdentity))?;
                let rule = decode_rule(&tokens).ok_or(refused(index, P::NotRendered))?;
                let owned = PfRule {
                    transaction: tag.transaction,
                    identity,
                    uid,
                    rule,
                };
                if anchor
                    .rules
                    .insert(handle, owned)
                    .is_some_and(|previous| previous != owned)
                {
                    return Err(refused(index, P::DuplicateHandle));
                }
            }
        }
    }
    let canonical = render(&anchor);
    let rendered: Vec<&str> = canonical.lines().collect();
    if rendered != lines {
        let item = rendered
            .iter()
            .zip(&lines)
            .position(|(expected, found)| expected != found)
            .unwrap_or(rendered.len().min(lines.len()));
        return Err(refused(item, P::NotRendered));
    }
    Ok(anchor)
}

/// The pf rule store: one perimeter's anchor read and replaced through a
/// [`CommandPort`].
pub struct PfStore<P> {
    port: P,
    perimeter: PerimeterId,
    anchor: PfAnchor,
    bindings: BTreeMap<Digest, Binding<PfSelector>>,
}

impl<P: CommandPort> PfStore<P> {
    /// A store of `perimeter`'s anchor serving `bindings`.
    pub fn new(
        port: P,
        perimeter: PerimeterId,
        bindings: Vec<Binding<PfSelector>>,
    ) -> Result<Self, BindingError> {
        Ok(Self {
            port,
            perimeter,
            anchor: PfAnchor::for_perimeter(perimeter),
            bindings: bind(bindings)?,
        })
    }

    pub fn anchor(&self) -> &PfAnchor {
        &self.anchor
    }

    pub fn port(&self) -> &P {
        &self.port
    }

    pub fn port_mut(&mut self) -> &mut P {
        &mut self.port
    }

    /// The read: `pfctl -a <anchor> -sr`.
    pub fn list_invocation(&self) -> Invocation {
        Invocation {
            argv: ["pfctl", "-a", self.anchor.as_str(), "-sr"]
                .map(str::to_owned)
                .to_vec(),
            input: None,
        }
    }

    /// A write: `pfctl -a <anchor> -f -` with the anchor's whole rule set as input.
    pub fn load_invocation(&self, rules: String) -> Invocation {
        Invocation {
            argv: ["pfctl", "-a", self.anchor.as_str(), "-f", "-"]
                .map(str::to_owned)
                .to_vec(),
            input: Some(rules),
        }
    }

    fn anchor_rules(&self) -> Result<AnchorRules, ReadError> {
        let text = self
            .port
            .read(&self.list_invocation())
            .map_err(|failure| ReadError::Port { failure })?;
        parse_anchor(&text, self.perimeter, &self.bindings)
    }

    fn tag(&self, transaction: TransactionId) -> OwnerTag {
        OwnerTag {
            perimeter: self.perimeter,
            transaction,
        }
    }

    /// The anchor's rules as V16 sees them. No identity is isolated: the deny lets ICMP
    /// through (see the module docs).
    fn snapshot_of(&self, anchor: &AnchorRules) -> StoreSnapshot {
        StoreSnapshot {
            entries: anchor
                .rules
                .iter()
                .map(|(handle, owned)| {
                    (
                        *handle,
                        owned_entry(self.tag(owned.transaction), owned.identity, owned.rule),
                    )
                })
                .collect(),
            isolated: BTreeSet::new(),
        }
    }

    /// Reads the anchor, with the reason when it is refused.
    pub fn read(&self) -> Result<StoreSnapshot, ReadError> {
        self.anchor_rules().map(|anchor| self.snapshot_of(&anchor))
    }

    /// Whether the anchor holds `identity`'s TCP and UDP deny.
    pub fn denies_tcp_udp(&self, identity: Digest) -> Result<bool, ReadError> {
        self.anchor_rules()
            .map(|anchor| anchor.denied.contains_key(&identity))
    }

    fn load(&mut self, anchor: &AnchorRules) -> Result<(), StoreFailure> {
        let invocation = self.load_invocation(render(anchor));
        self.port.write(&invocation)
    }

    /// Adds `identity`'s TCP and UDP deny to the anchor unless it has it. It does not
    /// isolate the identity (see the module docs). An elevated operation of its own
    /// ([`PfStore::tcp_udp_deny_scope`]).
    pub fn add_tcp_udp_deny(&mut self, identity: Digest) -> Result<(), StoreFailure> {
        let uid = self
            .bindings
            .get(&identity)
            .ok_or(StoreFailure::Rejected)?
            .selector
            .uid();
        let mut anchor = self.anchor_rules().map_err(|error| error.failure())?;
        if anchor.denied.contains_key(&identity) {
            return Ok(());
        }
        anchor.denied.insert(identity, uid);
        self.load(&anchor)
    }

    fn mechanism(&self) -> ElevatedMechanism {
        ElevatedMechanism::Pf {
            read: self.list_invocation().argv,
            write: self.load_invocation(String::new()).argv,
            anchor: self.anchor.as_str().to_owned(),
        }
    }

    /// The exact elevation `grant` needs here; an identity it adds rules for that this
    /// store does not bind refuses the scope.
    pub fn elevation_scope(&self, grant: &ElevationGrant) -> Result<ElevationScope, BindingError> {
        ElevationScope::for_grant(
            PerimeterPlatform::MacOs,
            self.mechanism(),
            grant,
            &self.bindings,
        )
    }

    /// The exact elevation adding `identity`'s TCP and UDP deny needs here.
    pub fn tcp_udp_deny_scope(&self, identity: Digest) -> Result<ElevationScope, BindingError> {
        ElevationScope::for_isolation(
            PerimeterPlatform::MacOs,
            self.mechanism(),
            identity,
            &self.bindings,
        )
    }
}

impl<P: CommandPort> RuleStore for PfStore<P> {
    fn snapshot(&self) -> Result<StoreSnapshot, StoreFailure> {
        self.read().map_err(|error| error.failure())
    }

    /// Loads the anchor with the rule added. Only rules of this store's perimeter fit its
    /// anchor.
    fn add(
        &mut self,
        grant: &ElevationGrant,
        rule: &OwnedRule,
    ) -> Result<RuleHandle, StoreFailure> {
        if !grant.permits_add(rule) {
            return Err(StoreFailure::NotGranted);
        }
        if rule.tag.perimeter != self.perimeter {
            return Err(StoreFailure::Rejected);
        }
        let uid = self
            .bindings
            .get(&rule.scoped.identity)
            .ok_or(StoreFailure::Rejected)?
            .selector
            .uid();
        let mut anchor = self.anchor_rules().map_err(|error| error.failure())?;
        let taken: BTreeSet<RuleHandle> = anchor.rules.keys().copied().collect();
        let handle = allocate_handle(rule.tag, &taken)?;
        anchor.rules.insert(
            handle,
            PfRule {
                transaction: rule.tag.transaction,
                identity: rule.scoped.identity,
                uid,
                rule: rule.scoped.rule,
            },
        );
        self.load(&anchor)?;
        Ok(handle)
    }

    /// Loads the anchor without the rule under `handle`.
    fn remove(&mut self, grant: &ElevationGrant, handle: RuleHandle) -> Result<(), StoreFailure> {
        let mut anchor = self.anchor_rules().map_err(|error| error.failure())?;
        let Some(owned) = anchor.rules.get(&handle).copied() else {
            return Err(StoreFailure::UnknownHandle { handle });
        };
        let entry = owned_entry(self.tag(owned.transaction), owned.identity, owned.rule);
        if !grant.permits_remove(handle, &entry) {
            return Err(StoreFailure::NotGranted);
        }
        anchor.rules.remove(&handle);
        self.load(&anchor)
    }
}
