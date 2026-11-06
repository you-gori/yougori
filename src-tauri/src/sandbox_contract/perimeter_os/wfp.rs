//! Windows Filtering Platform (VM §4.4, Windows: "validate WFP/Firewall scope against the
//! actual process or service identity ... Explicit block rules take precedence over
//! conflicting allow rules ... Avoid changing the whole PC's outbound defaults"; VM-W15).
//!
//! Rendered. Each rule is one typed filter specification ([`WfpFilterSpec`]) under
//! provider [`WFP_PROVIDER`] in sublayer [`WFP_SUBLAYER`] (weight
//! [`WFP_SUBLAYER_WEIGHT`]), at the ALE connect layer of the destination's family: the
//! broker identity condition ([`WfpSelector`]: the service SID through
//! FWPM_CONDITION_ALE_USER_ID, or the AppContainer package SID through
//! FWPM_CONDITION_ALE_PACKAGE_ID), the remote address range and, for one port, the remote
//! port range, and permit or block. Weight carries V16's evaluation model inside the
//! sublayer: blocks ([`WFP_BLOCK_WEIGHT`]) above permits ([`WFP_PERMIT_WEIGHT`]) above
//! each identity's isolation filters ([`WFP_ISOLATION_WEIGHT`]: the identity condition
//! alone and block), so an explicit block wins and anything unmatched is blocked; WFP
//! makes a block final across sublayers. Filters are persistent and none clears the
//! action right, so no permit here overrides another sublayer's block. The filter name
//! carries the owner tag and the store's handle (`yg1 <perimeter>:<transaction>:<handle>`)
//! and the filter key is derived from them; a delete names that key.
//!
//! Isolation. The ALE connect layers authorize only connections the broker opens (and the
//! first datagram to each remote endpoint, ICMP included); a connection it accepts is
//! authorized at the receive/accept layers instead and then carries data both ways. So an
//! identity's isolation filters block at all four layers of [`WfpLayer::ALL`], connect
//! and receive/accept, IPv4 and IPv6, and an identity counts as isolated only with all
//! four present: the broker accepts no inbound connection or unsolicited datagram, local
//! (loopback) ones included, and a broker that must serve local clients needs a channel
//! these layers do not filter. The ALE listen layers are not used: a listen carries no
//! traffic, and every connection it could lead to is refused at receive/accept.
//!
//! Service SIDs. FWPM_CONDITION_ALE_USER_ID matches a service SID only when the Service
//! Control Manager adds it to the service's token, which it does for SID type
//! unrestricted or restricted and not for none (`sc qsidtype`). A service binding
//! therefore names the service ([`WfpSelector::ServiceSid`]), and the store asks the port
//! for its configured SID and type ([`WfpPort::service_sid`]): an identity whose service
//! does not carry exactly the bound SID in its token is never reported isolated, and
//! [`WfpStore::isolate`] refuses it before writing. An AppContainer's package SID is
//! always in its token.
//!
//! Parsed. [`WfpStore::read`] reads the owned sublayer, which must be under the owned
//! provider at [`WFP_SUBLAYER_WEIGHT`], and enumerates every filter at the four layers. A
//! filter in the owned sublayer must be exactly what this module renders, under the owned
//! provider; anything else there refuses the read. Every other filter is reported as a
//! foreign entry under [`FOREIGN_HANDLE_BIT`] | its filter id: no tag whatever its name
//! says, so a look-alike is never owned and never removed; an opaque body (the digest of
//! its specification), never guessed as a perimeter rule; and the broker's scope only
//! when one of its conditions is exactly a bound identity's, which V16 then refuses.
//!
//! The `fwpuclnt` and service-configuration calls, the conversion between FWPM
//! structures and these specifications, and whether another sublayer of equal weight or
//! a callout changes the arbitration are outside this module: the port's and the
//! must-probes'.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use super::common::{
    allocate_handle, bind, decimal, isolation_marker, owned_entry, owned_marker, read_marker,
    refused, Binding, BindingError, Marker, ReadError, ReadProblem, Selector, FOREIGN_HANDLE_BIT,
};
use super::elevation::{ElevatedMechanism, ElevationScope, WfpCall};
use crate::foundation::ids::{Digest, DigestBuilder};
use crate::sandbox_contract::destinations::{
    DestinationPort, IpPrefix, PerimeterPlatform, PerimeterRule, PortSelector, RuleAction,
};
use crate::sandbox_contract::perimeter_install::{
    ElevationGrant, IdentityKind, OwnedRule, OwnerTag, RuleBody, RuleHandle, RuleScope, RuleStore,
    StoreEntry, StoreFailure, StoreSnapshot,
};

/// A WFP GUID (a provider, sublayer, filter or callout key), as its 16 bytes in RFC 9562
/// order.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WfpGuid([u8; 16]);

impl WfpGuid {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// A name-based GUID: the first 16 bytes of `builder`'s digest, marked as an RFC 9562
    /// version 8 GUID.
    fn derive(builder: DigestBuilder) -> Self {
        let [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, ..] = *builder.finish().as_bytes();
        Self([
            a,
            b,
            c,
            d,
            e,
            f,
            (g & 0x0f) | 0x80,
            h,
            (i & 0x3f) | 0x80,
            j,
            k,
            l,
            m,
            n,
            o,
            p,
        ])
    }
}

impl fmt::Display for WfpGuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g, h, i, j, k, l, m, n, o, p, q] = self.0;
        write!(
            f,
            "{{{a:02x}{b:02x}{c:02x}{d:02x}-{e:02x}{g:02x}-{h:02x}{i:02x}-{j:02x}{k:02x}-\
             {l:02x}{m:02x}{n:02x}{o:02x}{p:02x}{q:02x}}}"
        )
    }
}

impl fmt::Debug for WfpGuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WfpGuid({self})")
    }
}

/// The provider this product owns.
pub const WFP_PROVIDER: WfpGuid = WfpGuid([
    0x79, 0x67, 0x31, 0x70, 0x2d, 0x70, 0x8e, 0x72, 0x9d, 0x69, 0x6d, 0x65, 0x74, 0x65, 0x72, 0x01,
]);
/// The sublayer this product owns.
pub const WFP_SUBLAYER: WfpGuid = WfpGuid([
    0x79, 0x67, 0x31, 0x70, 0x2d, 0x70, 0x8e, 0x72, 0x9d, 0x69, 0x6d, 0x65, 0x74, 0x65, 0x72, 0x02,
]);
/// The owned provider's display name.
pub const WFP_PROVIDER_NAME: &str = "Yougori perimeter";
/// The owned sublayer's display name.
pub const WFP_SUBLAYER_NAME: &str = "Yougori perimeter";
/// The owned sublayer's weight: the highest, so no sublayer evaluated before it can
/// override its blocks.
pub const WFP_SUBLAYER_WEIGHT: u16 = u16::MAX;
/// The weight of a block filter in the owned sublayer.
pub const WFP_BLOCK_WEIGHT: u64 = 3;
/// The weight of a permit filter in the owned sublayer.
pub const WFP_PERMIT_WEIGHT: u64 = 2;
/// The weight of an isolation filter in the owned sublayer.
pub const WFP_ISOLATION_WEIGHT: u64 = 1;
/// Domain of an owned filter's key.
pub const FILTER_KEY_DOMAIN: &str = "yougori/sandbox/perimeter-os/wfp-filter-key/v1";
/// Domain of an isolation filter's key.
pub const ISOLATION_KEY_DOMAIN: &str = "yougori/sandbox/perimeter-os/wfp-isolation-key/v1";
/// Domain of the opaque body of a foreign filter.
pub const FOREIGN_FILTER_DOMAIN: &str = "yougori/sandbox/perimeter-os/wfp-foreign-filter/v1";

/// A filtering layer the store uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WfpLayer {
    /// FWPM_LAYER_ALE_AUTH_CONNECT_V4: outbound connection authorization, IPv4.
    AleAuthConnectV4,
    /// FWPM_LAYER_ALE_AUTH_CONNECT_V6: outbound connection authorization, IPv6.
    AleAuthConnectV6,
    /// FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4: inbound connection authorization, IPv4.
    AleAuthRecvAcceptV4,
    /// FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6: inbound connection authorization, IPv6.
    AleAuthRecvAcceptV6,
}

impl WfpLayer {
    /// Every layer the store enumerates and isolates an identity at.
    pub const ALL: [Self; 4] = [
        Self::AleAuthConnectV4,
        Self::AleAuthConnectV6,
        Self::AleAuthRecvAcceptV4,
        Self::AleAuthRecvAcceptV6,
    ];

    /// The connect layer a perimeter rule to a destination of `address`'s family is
    /// rendered at.
    pub const fn of(address: IpAddr) -> Self {
        match address {
            IpAddr::V4(_) => Self::AleAuthConnectV4,
            IpAddr::V6(_) => Self::AleAuthConnectV6,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::AleAuthConnectV4 => "ale-auth-connect-v4",
            Self::AleAuthConnectV6 => "ale-auth-connect-v6",
            Self::AleAuthRecvAcceptV4 => "ale-auth-recv-accept-v4",
            Self::AleAuthRecvAcceptV6 => "ale-auth-recv-accept-v6",
        }
    }
}

/// A Windows security identifier in its canonical string form.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Sid(String);

impl Sid {
    /// Accepts `S-1-<authority>-<subauthority>...`: decimal without leading zeros, an
    /// authority below 2^48 and 1 to 15 subauthorities that fit 32 bits.
    pub fn parse(text: &str) -> Result<Self, BindingError> {
        let mut parts = text.split('-');
        let header = parts.next() == Some("S") && parts.next() == Some("1");
        let authority = parts
            .next()
            .and_then(decimal)
            .is_some_and(|value| value < 1 << 48);
        let subauthorities: Vec<Option<u64>> = parts.map(decimal).collect();
        let valid = header
            && authority
            && (1..=15).contains(&subauthorities.len())
            && subauthorities
                .iter()
                .all(|value| value.is_some_and(|value| value <= u64::from(u32::MAX)));
        if valid {
            Ok(Self(text.to_owned()))
        } else {
            Err(BindingError::InvalidName)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Sid {
    type Error = BindingError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::parse(&text)
    }
}

impl From<Sid> for String {
    fn from(sid: Sid) -> Self {
        sid.0
    }
}

/// A Windows service name, such as `YougoriBroker`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ServiceName(String);

impl ServiceName {
    /// Accepts 1 to 256 ASCII letters, digits, `.`, `_` and `-` (the Service Control
    /// Manager allows 256 characters and no slashes).
    pub fn new(name: &str) -> Result<Self, BindingError> {
        let valid = !name.is_empty()
            && name.len() <= 256
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
        if valid {
            Ok(Self(name.to_owned()))
        } else {
            Err(BindingError::InvalidName)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ServiceName {
    type Error = BindingError;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        Self::new(&name)
    }
}

impl From<ServiceName> for String {
    fn from(name: ServiceName) -> Self {
        name.0
    }
}

/// How the Service Control Manager adds a service's SID to its token
/// (SERVICE_SID_INFO.dwServiceSidType).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceSidType {
    /// SERVICE_SID_TYPE_NONE: not at all.
    None,
    /// SERVICE_SID_TYPE_UNRESTRICTED: as a group.
    Unrestricted,
    /// SERVICE_SID_TYPE_RESTRICTED: as a group and in the restricting SIDs.
    Restricted,
}

impl ServiceSidType {
    /// Whether the service SID is in the service's token, which matching it through
    /// FWPM_CONDITION_ALE_USER_ID needs.
    pub const fn in_token(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// A service's SID and SID type as the Service Control Manager reports them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSidInfo {
    pub sid: Sid,
    pub sid_type: ServiceSidType,
}

/// How a WFP filter names its broker identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum WfpSelector {
    /// The broker service and its SID, `S-1-5-80-...` ([`IdentityKind::ServiceSid`]). The
    /// service must carry the SID in its token (see the module docs).
    ServiceSid { service: ServiceName, sid: Sid },
    /// The broker's AppContainer package SID, `S-1-15-2-...`
    /// ([`IdentityKind::AppContainer`]).
    PackageSid { sid: Sid },
}

impl WfpSelector {
    pub const fn sid(&self) -> &Sid {
        match self {
            Self::ServiceSid { sid, .. } | Self::PackageSid { sid } => sid,
        }
    }
}

impl Selector for WfpSelector {
    fn kind(&self) -> IdentityKind {
        match self {
            Self::ServiceSid { .. } => IdentityKind::ServiceSid,
            Self::PackageSid { .. } => IdentityKind::AppContainer,
        }
    }

    fn check(&self) -> Result<(), BindingError> {
        let prefix = match self {
            Self::ServiceSid { .. } => "S-1-5-80-",
            Self::PackageSid { .. } => "S-1-15-2-",
        };
        if self.sid().as_str().starts_with(prefix) {
            Ok(())
        } else {
            Err(BindingError::InvalidName)
        }
    }

    fn overlaps(&self, other: &Self) -> bool {
        self.sid() == other.sid()
    }
}

/// One filter condition (all of a filter's conditions must match).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum WfpCondition {
    /// FWPM_CONDITION_ALE_USER_ID, FWP_MATCH_EQUAL, with a security descriptor that grants
    /// only this service SID.
    ServiceSid { sid: Sid },
    /// FWPM_CONDITION_ALE_PACKAGE_ID, FWP_MATCH_EQUAL.
    PackageSid { sid: Sid },
    /// FWPM_CONDITION_IP_REMOTE_ADDRESS, FWP_MATCH_RANGE, both ends included.
    RemoteAddress { low: IpAddr, high: IpAddr },
    /// FWPM_CONDITION_IP_REMOTE_PORT, FWP_MATCH_RANGE, both ends included.
    RemotePort { low: u16, high: u16 },
    /// Any other condition, by its field key and a digest of its match type and value;
    /// only foreign filters carry one.
    Other { field: WfpGuid, value: Digest },
}

/// What a filter does when its conditions match.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum WfpAction {
    /// FWP_ACTION_PERMIT.
    Permit,
    /// FWP_ACTION_BLOCK.
    Block,
    /// A callout decides; only foreign filters carry one.
    Callout { callout: WfpGuid },
}

/// The filter flags the store reads and writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WfpFlags {
    /// FWPM_FILTER_FLAG_PERSISTENT: the filter survives a restart of the filtering engine.
    pub persistent: bool,
    /// FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT: a hard permit that lower sublayers cannot
    /// override.
    pub clear_action_right: bool,
}

impl WfpFlags {
    /// The flags of every filter this product adds.
    pub const OWNED: Self = Self {
        persistent: true,
        clear_action_right: false,
    };
}

/// One filter as the store renders it and the port reports it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WfpFilterSpec {
    /// The filter key, which a delete names.
    pub key: WfpGuid,
    /// The display name, which carries the marker.
    pub name: String,
    pub provider: Option<WfpGuid>,
    pub sublayer: WfpGuid,
    pub layer: WfpLayer,
    /// An FWP_UINT64 weight inside the sublayer.
    pub weight: u64,
    pub conditions: Vec<WfpCondition>,
    pub action: WfpAction,
    pub flags: WfpFlags,
}

/// An enumerated filter: the engine's runtime id and the specification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WfpFilter {
    pub id: u64,
    pub spec: WfpFilterSpec,
}

/// A sublayer as the engine reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WfpSublayer {
    pub key: WfpGuid,
    pub provider: Option<WfpGuid>,
    pub weight: u16,
}

/// One change inside a WFP transaction. Providers, sublayers and filters this product
/// adds are persistent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum WfpChange {
    /// `FwpmProviderAdd0`, unless the same provider exists.
    AddProvider { key: WfpGuid, name: String },
    /// `FwpmSubLayerAdd0`, unless the same sublayer exists.
    AddSublayer {
        key: WfpGuid,
        provider: WfpGuid,
        name: String,
        weight: u16,
    },
    /// `FwpmFilterAdd0`.
    AddFilter { spec: WfpFilterSpec },
    /// `FwpmFilterDeleteByKey0`.
    DeleteFilter { key: WfpGuid },
}

/// The filtering engine and the service configuration as the store uses them. Nothing in
/// this module implements it for a real machine: the real port makes the `fwpuclnt` and
/// `advapi32` calls, writes through the elevated helper.
pub trait WfpPort {
    /// Enumerates every filter at `layers`, of every provider and sublayer
    /// (`FwpmFilterEnum0`).
    fn enumerate(&self, layers: &[WfpLayer]) -> Result<Vec<WfpFilter>, StoreFailure>;

    /// The sublayer under `key` (`FwpmSubLayerGetByKey0`); `None` when there is none.
    fn sublayer(&self, key: WfpGuid) -> Result<Option<WfpSublayer>, StoreFailure>;

    /// The SID and SID type of `service` (`LookupAccountNameW` of `NT SERVICE\<service>`
    /// and `QueryServiceConfig2W` with SERVICE_CONFIG_SERVICE_SID_INFO, which needs no
    /// elevation).
    fn service_sid(&self, service: &ServiceName) -> Result<ServiceSidInfo, StoreFailure>;

    /// Applies `changes` in one transaction (`FwpmTransactionBegin0` to
    /// `FwpmTransactionCommit0`): all of them or none.
    fn apply(&mut self, changes: &[WfpChange]) -> Result<(), StoreFailure>;
}

fn identity_condition(selector: &WfpSelector) -> WfpCondition {
    match selector {
        WfpSelector::ServiceSid { sid, .. } => WfpCondition::ServiceSid { sid: sid.clone() },
        WfpSelector::PackageSid { sid } => WfpCondition::PackageSid { sid: sid.clone() },
    }
}

/// The first and last address `prefix` covers.
fn address_range(prefix: &IpPrefix) -> (IpAddr, IpAddr) {
    let length = u32::from(prefix.length());
    match prefix.network() {
        IpAddr::V4(network) => {
            let host = u32::MAX.checked_shr(length).unwrap_or(0);
            (
                IpAddr::V4(network),
                IpAddr::V4((u32::from(network) | host).into()),
            )
        }
        IpAddr::V6(network) => {
            let host = u128::MAX.checked_shr(length).unwrap_or(0);
            (
                IpAddr::V6(network),
                IpAddr::V6((u128::from(network) | host).into()),
            )
        }
    }
}

/// The prefix whose range is exactly `low..=high`, when there is one.
fn prefix_of_range(low: IpAddr, high: IpAddr) -> Option<IpPrefix> {
    let (low_bits, high_bits, width) = match (low, high) {
        (IpAddr::V4(low), IpAddr::V4(high)) => (
            u128::from(u32::from(low)),
            u128::from(u32::from(high)),
            32_u32,
        ),
        (IpAddr::V6(low), IpAddr::V6(high)) => (u128::from(low), u128::from(high), 128),
        _ => return None,
    };
    let host = low_bits ^ high_bits;
    let length = u8::try_from(width.checked_sub(host.count_ones())?).ok()?;
    let prefix = IpPrefix::new(low, length).ok()?;
    (address_range(&prefix) == (low, high)).then_some(prefix)
}

fn filter_key(tag: OwnerTag, handle: RuleHandle) -> WfpGuid {
    WfpGuid::derive(
        DigestBuilder::new(FILTER_KEY_DOMAIN)
            .digest(&tag.perimeter.digest())
            .u64(handle.get()),
    )
}

fn isolation_key(identity: Digest, layer: WfpLayer) -> WfpGuid {
    WfpGuid::derive(
        DigestBuilder::new(ISOLATION_KEY_DOMAIN)
            .digest(&identity)
            .str(layer.name()),
    )
}

/// The filter of `rule` for `selector`, under `tag` and the store's `handle`.
pub fn rule_filter(
    tag: OwnerTag,
    handle: RuleHandle,
    selector: &WfpSelector,
    rule: &PerimeterRule,
) -> WfpFilterSpec {
    let (low, high) = address_range(&rule.prefix);
    let mut conditions = vec![
        identity_condition(selector),
        WfpCondition::RemoteAddress { low, high },
    ];
    if let PortSelector::Only(port) = rule.ports {
        conditions.push(WfpCondition::RemotePort {
            low: port.get(),
            high: port.get(),
        });
    }
    let (action, weight) = match rule.action {
        RuleAction::Allow => (WfpAction::Permit, WFP_PERMIT_WEIGHT),
        RuleAction::Block => (WfpAction::Block, WFP_BLOCK_WEIGHT),
    };
    WfpFilterSpec {
        key: filter_key(tag, handle),
        name: owned_marker(tag, handle),
        provider: Some(WFP_PROVIDER),
        sublayer: WFP_SUBLAYER,
        layer: WfpLayer::of(rule.prefix.network()),
        weight,
        conditions,
        action,
        flags: WfpFlags::OWNED,
    }
}

/// The isolation filter of `identity` (bound to `selector`) at `layer`: the identity
/// condition alone, block, at the lowest weight of the owned sublayer.
pub fn isolation_filter(
    identity: Digest,
    selector: &WfpSelector,
    layer: WfpLayer,
) -> WfpFilterSpec {
    WfpFilterSpec {
        key: isolation_key(identity, layer),
        name: isolation_marker(identity),
        provider: Some(WFP_PROVIDER),
        sublayer: WFP_SUBLAYER,
        layer,
        weight: WFP_ISOLATION_WEIGHT,
        conditions: vec![identity_condition(selector)],
        action: WfpAction::Block,
        flags: WfpFlags::OWNED,
    }
}

/// The bound identity and perimeter rule whose rendering under `tag` and `handle` is
/// exactly `spec`.
fn decode_rule(
    bindings: &BTreeMap<Digest, Binding<WfpSelector>>,
    tag: OwnerTag,
    handle: RuleHandle,
    spec: &WfpFilterSpec,
) -> Option<(Digest, PerimeterRule)> {
    let [identity, WfpCondition::RemoteAddress { low, high }, rest @ ..] =
        spec.conditions.as_slice()
    else {
        return None;
    };
    let binding = bindings
        .values()
        .find(|binding| identity_condition(&binding.selector) == *identity)?;
    let ports = match rest {
        [] => PortSelector::All,
        [WfpCondition::RemotePort { low, high }] if low == high => {
            PortSelector::Only(DestinationPort::new(*low).ok()?)
        }
        _ => return None,
    };
    let action = match spec.action {
        WfpAction::Permit => RuleAction::Allow,
        WfpAction::Block => RuleAction::Block,
        WfpAction::Callout { .. } => return None,
    };
    let rule = PerimeterRule {
        action,
        prefix: prefix_of_range(*low, *high)?,
        ports,
    };
    (rule_filter(tag, handle, &binding.selector, &rule) == *spec)
        .then_some((binding.broker.identity, rule))
}

/// A filter outside the owned sublayer: no tag, an opaque body, and the broker's scope
/// only when a condition is exactly a bound identity's.
fn foreign_entry(
    spec: &WfpFilterSpec,
    bindings: &BTreeMap<Digest, Binding<WfpSelector>>,
) -> Result<StoreEntry, serde_json::Error> {
    let scope = spec
        .conditions
        .iter()
        .find_map(|condition| {
            bindings
                .values()
                .find(|binding| identity_condition(&binding.selector) == *condition)
        })
        .map_or(RuleScope::Machine, |binding| RuleScope::Identity {
            identity: binding.broker.identity,
        });
    let canonical = serde_json::to_vec(spec)?;
    Ok(StoreEntry {
        tag: None,
        scope,
        body: RuleBody::Opaque {
            digest: DigestBuilder::new(FOREIGN_FILTER_DOMAIN)
                .bytes(&canonical)
                .finish(),
        },
    })
}

/// The filters at the store's layers as read back.
#[derive(Debug, Default)]
pub(super) struct Listing {
    pub(super) snapshot: StoreSnapshot,
    /// The key of each owned filter, which a delete names.
    pub(super) keys: BTreeMap<RuleHandle, WfpGuid>,
    /// The isolation filters present, by identity and layer.
    pub(super) isolation: BTreeSet<(Digest, WfpLayer)>,
}

/// Parses an enumeration and the owned sublayer as the engine reports it, accepting in
/// the owned sublayer only what this module renders for `bindings`. A sublayer that is
/// not the one this module provisions is refused at item `filters.len()`.
pub(super) fn parse_filters(
    filters: &[WfpFilter],
    sublayer: Option<&WfpSublayer>,
    bindings: &BTreeMap<Digest, Binding<WfpSelector>>,
) -> Result<Listing, ReadError> {
    use ReadProblem as P;
    if let Some(sublayer) = sublayer {
        let provisioned = sublayer.key == WFP_SUBLAYER
            && sublayer.provider == Some(WFP_PROVIDER)
            && sublayer.weight == WFP_SUBLAYER_WEIGHT;
        if !provisioned {
            return Err(refused(filters.len(), P::ObjectShape));
        }
    }
    let mut listing = Listing::default();
    for (index, filter) in filters.iter().enumerate() {
        let spec = &filter.spec;
        if spec.sublayer != WFP_SUBLAYER {
            if filter.id & FOREIGN_HANDLE_BIT != 0 {
                return Err(refused(index, P::ForeignIdOutOfRange));
            }
            let handle = RuleHandle::new(FOREIGN_HANDLE_BIT | filter.id);
            let entry = foreign_entry(spec, bindings).map_err(|_| refused(index, P::Malformed))?;
            if listing.snapshot.entries.insert(handle, entry).is_some() {
                return Err(refused(index, P::DuplicateHandle));
            }
            continue;
        }
        if sublayer.is_none() {
            return Err(refused(index, P::ObjectShape));
        }
        if spec.provider != Some(WFP_PROVIDER) {
            return Err(refused(index, P::WrongObject));
        }
        match read_marker(&spec.name) {
            Marker::Absent => return Err(refused(index, P::Unmarked)),
            Marker::Malformed | Marker::Isolation { identity: None } => {
                return Err(refused(index, P::BadMarker))
            }
            Marker::Owned { tag, handle } => {
                let (identity, rule) = decode_rule(bindings, tag, handle, spec)
                    .ok_or(refused(index, P::NotRendered))?;
                if listing.keys.insert(handle, spec.key).is_some() {
                    return Err(refused(index, P::DuplicateHandle));
                }
                listing
                    .snapshot
                    .entries
                    .insert(handle, owned_entry(tag, identity, rule));
            }
            Marker::Isolation {
                identity: Some(identity),
            } => {
                let binding = bindings
                    .get(&identity)
                    .ok_or(refused(index, P::UnboundIdentity))?;
                if isolation_filter(identity, &binding.selector, spec.layer) != *spec {
                    return Err(refused(index, P::NotRendered));
                }
                if !listing.isolation.insert((identity, spec.layer)) {
                    return Err(refused(index, P::DuplicateIsolation));
                }
            }
        }
    }
    listing.snapshot.isolated = bindings
        .keys()
        .filter(|identity| {
            WfpLayer::ALL
                .iter()
                .all(|layer| listing.isolation.contains(&(**identity, *layer)))
        })
        .copied()
        .collect();
    Ok(listing)
}

/// The WFP rule store: the owned sublayer read and changed through a [`WfpPort`].
pub struct WfpStore<P> {
    port: P,
    bindings: BTreeMap<Digest, Binding<WfpSelector>>,
}

impl<P: WfpPort> WfpStore<P> {
    /// A store serving `bindings`.
    pub fn new(port: P, bindings: Vec<Binding<WfpSelector>>) -> Result<Self, BindingError> {
        Ok(Self {
            port,
            bindings: bind(bindings)?,
        })
    }

    pub fn port(&self) -> &P {
        &self.port
    }

    pub fn port_mut(&mut self) -> &mut P {
        &mut self.port
    }

    /// Whether the filters' identity condition for `identity` matches its broker's token:
    /// a service must carry exactly the bound SID (see the module docs).
    fn in_token(&self, identity: Digest) -> Result<bool, StoreFailure> {
        match &self
            .bindings
            .get(&identity)
            .ok_or(StoreFailure::Rejected)?
            .selector
        {
            WfpSelector::ServiceSid { service, sid } => {
                let info = self.port.service_sid(service)?;
                Ok(info.sid_type.in_token() && info.sid == *sid)
            }
            WfpSelector::PackageSid { .. } => Ok(true),
        }
    }

    fn listing(&self) -> Result<Listing, ReadError> {
        let port = |failure| ReadError::Port { failure };
        let filters = self.port.enumerate(&WfpLayer::ALL).map_err(port)?;
        let sublayer = self.port.sublayer(WFP_SUBLAYER).map_err(port)?;
        let mut listing = parse_filters(&filters, sublayer.as_ref(), &self.bindings)?;
        let mut unmatched = Vec::new();
        for identity in &listing.snapshot.isolated {
            if !self.in_token(*identity).map_err(port)? {
                unmatched.push(*identity);
            }
        }
        for identity in unmatched {
            listing.snapshot.isolated.remove(&identity);
        }
        Ok(listing)
    }

    /// Reads the owned sublayer and the filters at the store's layers, with the reason
    /// when they are refused.
    pub fn read(&self) -> Result<StoreSnapshot, ReadError> {
        self.listing().map(|listing| listing.snapshot)
    }

    /// Provisions the owned provider and sublayer when absent and adds `identity`'s
    /// isolation filters it lacks, in one transaction. An elevated operation of its own
    /// ([`WfpStore::isolation_scope`]). A service whose token would not carry the bound
    /// SID is refused before anything is written.
    pub fn isolate(&mut self, identity: Digest) -> Result<(), StoreFailure> {
        let selector = self
            .bindings
            .get(&identity)
            .ok_or(StoreFailure::Rejected)?
            .selector
            .clone();
        if !self.in_token(identity)? {
            return Err(StoreFailure::Rejected);
        }
        let listing = self.listing().map_err(|error| error.failure())?;
        let missing: Vec<WfpChange> = WfpLayer::ALL
            .iter()
            .filter(|layer| !listing.isolation.contains(&(identity, **layer)))
            .map(|layer| WfpChange::AddFilter {
                spec: isolation_filter(identity, &selector, *layer),
            })
            .collect();
        if missing.is_empty() {
            return Ok(());
        }
        let mut changes = vec![
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
        changes.extend(missing);
        self.port.apply(&changes)
    }

    fn mechanism(provision: bool) -> ElevatedMechanism {
        let mut calls = vec![
            WfpCall::FwpmEngineOpen0,
            WfpCall::FwpmFilterEnum0,
            WfpCall::FwpmSubLayerGetByKey0,
            WfpCall::FwpmTransactionBegin0,
        ];
        if provision {
            calls.extend([WfpCall::FwpmProviderAdd0, WfpCall::FwpmSubLayerAdd0]);
        }
        calls.push(WfpCall::FwpmFilterAdd0);
        if !provision {
            calls.push(WfpCall::FwpmFilterDeleteByKey0);
        }
        calls.push(WfpCall::FwpmTransactionCommit0);
        ElevatedMechanism::Wfp {
            calls,
            provider: WFP_PROVIDER,
            sublayer: WFP_SUBLAYER,
            layers: WfpLayer::ALL.to_vec(),
        }
    }

    /// The exact elevation `grant` needs here; an identity it adds rules for that this
    /// store does not bind refuses the scope.
    pub fn elevation_scope(&self, grant: &ElevationGrant) -> Result<ElevationScope, BindingError> {
        ElevationScope::for_grant(
            PerimeterPlatform::Windows,
            Self::mechanism(false),
            grant,
            &self.bindings,
        )
    }

    /// The exact elevation isolating `identity` needs here.
    pub fn isolation_scope(&self, identity: Digest) -> Result<ElevationScope, BindingError> {
        ElevationScope::for_isolation(
            PerimeterPlatform::Windows,
            Self::mechanism(true),
            identity,
            &self.bindings,
        )
    }
}

impl<P: WfpPort> RuleStore for WfpStore<P> {
    fn snapshot(&self) -> Result<StoreSnapshot, StoreFailure> {
        self.read().map_err(|error| error.failure())
    }

    fn add(
        &mut self,
        grant: &ElevationGrant,
        rule: &OwnedRule,
    ) -> Result<RuleHandle, StoreFailure> {
        if !grant.permits_add(rule) {
            return Err(StoreFailure::NotGranted);
        }
        let selector = self
            .bindings
            .get(&rule.scoped.identity)
            .ok_or(StoreFailure::Rejected)?
            .selector
            .clone();
        let listing = self.listing().map_err(|error| error.failure())?;
        let taken: BTreeSet<RuleHandle> = listing.keys.keys().copied().collect();
        let handle = allocate_handle(rule.tag, &taken)?;
        let spec = rule_filter(rule.tag, handle, &selector, &rule.scoped.rule);
        self.port.apply(&[WfpChange::AddFilter { spec }])?;
        Ok(handle)
    }

    /// Deletes the owned filter under `handle` by its key. A foreign handle is never
    /// removed, whatever the grant says.
    fn remove(&mut self, grant: &ElevationGrant, handle: RuleHandle) -> Result<(), StoreFailure> {
        if handle.get() & FOREIGN_HANDLE_BIT != 0 {
            return Err(StoreFailure::NotGranted);
        }
        let listing = self.listing().map_err(|error| error.failure())?;
        let (Some(entry), Some(key)) = (listing.snapshot.entry(handle), listing.keys.get(&handle))
        else {
            return Err(StoreFailure::UnknownHandle { handle });
        };
        if !grant.permits_remove(handle, entry) {
            return Err(StoreFailure::NotGranted);
        }
        let change = WfpChange::DeleteFilter { key: *key };
        self.port.apply(&[change])
    }
}
