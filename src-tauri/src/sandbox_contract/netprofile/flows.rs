//! Flow-model vocabulary: flows, NAT mappings, DNS answers, refusals and revocations
//! (VM-W59 NAT, reconnects and published responses; VM-W08; VM-P08, VM-P09, VM-P36).
//!
//! A flow is the host's connection-tracking entry for one guest connection or one
//! admitted inbound session. NAT never rewrites a destination: a mapping changes only
//! the source, to the host's egress address and a port from the sandbox's own block, so
//! no mapping can land on a host or other-sandbox address. [`NatTable`] refuses one that
//! would.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;

use crate::foundation::ids::{ExecutionId, MonotonicTime, PolicyEpoch};
use crate::sandbox_contract::destinations::{
    AddressFamily, AddressRefused, Authority, AuthorizationRefusal, BudgetExhausted, CanonicalName,
    ConnectionRefusal, DestinationRefusal, GuestProtocol, GuestQueryType, IngressError,
    IngressSession, NameError, PublicationId, ReleaseError, ResolverId, RouteId, SandboxEndpoint,
    ServiceIdentity, SettleError,
};

/// A flow's transport, as the host sees it in the packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Transport {
    Tcp,
    Udp,
    Icmp,
    /// Any other IP protocol number, as a raw socket can send.
    Other(u8),
}

/// The 5-tuple of a guest flow as the host observes it on the sandbox's NIC. Ports are 0
/// for ICMP and other protocols.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlowKey {
    pub transport: Transport,
    pub source: IpAddr,
    pub source_port: u16,
    pub destination: IpAddr,
    pub destination_port: u16,
}

impl FlowKey {
    /// The address family of the destination.
    pub const fn family(&self) -> AddressFamily {
        match self.destination {
            IpAddr::V4(_) => AddressFamily::Ipv4,
            IpAddr::V6(_) => AddressFamily::Ipv6,
        }
    }

    /// The V02 view of the protocol and destination port.
    pub const fn guest_protocol(&self) -> GuestProtocol {
        match self.transport {
            Transport::Tcp => GuestProtocol::Tcp {
                port: self.destination_port,
            },
            Transport::Udp => GuestProtocol::Udp {
                port: self.destination_port,
            },
            Transport::Icmp => GuestProtocol::Icmp,
            Transport::Other(number) => GuestProtocol::Other(number),
        }
    }
}

/// A flow's handle, unique on one host and rising from 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlowId(pub(crate) u64);

impl FlowId {
    /// The number of the flow.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for FlowId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "flow-{}", self.0)
    }
}

/// Which host proxy listener a local flow reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProxyListener {
    HttpConnect,
    Socks5,
}

/// What a flow is and under which authority it was admitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FlowKind {
    /// To the host DNS listener; nothing leaves the host for it.
    LocalDns,
    /// To a host proxy listener; the proxy's own outbound connection is a separate
    /// [`FlowKind::Proxied`] flow.
    LocalProxy { listener: ProxyListener },
    /// To an address the guest learned from a host DNS answer for `name`.
    Named { route: RouteId, name: CanonicalName },
    /// To an exact endpoint grant's address.
    Endpoint { route: RouteId },
    /// The host proxy's outbound connection for a guest request.
    Proxied {
        route: RouteId,
        authority: Authority,
        address: IpAddr,
    },
    /// To another sandbox, with grants at both ends (VM §4.7).
    SandboxLink {
        callee: SandboxEndpoint,
        service: ServiceIdentity,
    },
    /// An admitted inbound session of a publication (VM §4.7).
    Inbound {
        publication: PublicationId,
        session: IngressSession,
    },
}

impl FlowKind {
    /// The egress route the flow is charged to, if any.
    pub fn route(&self) -> Option<&RouteId> {
        match self {
            Self::Named { route, .. } | Self::Endpoint { route } | Self::Proxied { route, .. } => {
                Some(route)
            }
            _ => None,
        }
    }
}

/// One NAT translation of an outbound guest flow (VM-W59 NAT). The destination is the
/// original one: NAT never rewrites it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NatMapping {
    pub transport: Transport,
    /// The guest's address and port.
    pub inside: (IpAddr, u16),
    /// The host egress address and the port from the sandbox's block.
    pub outside: (IpAddr, u16),
    pub destination: (IpAddr, u16),
}

/// The host's connection-tracking entry for one flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowRecord {
    pub id: FlowId,
    pub sandbox: ExecutionId,
    /// The guest 5-tuple; `None` for proxied and inbound flows, which the guest did not
    /// address.
    pub key: Option<FlowKey>,
    pub kind: FlowKind,
    pub nat: Option<NatMapping>,
    /// The policy epoch the flow is authorized under; raised when a profile change keeps
    /// it.
    pub epoch: PolicyEpoch,
    pub opened_at: MonotonicTime,
}

/// A newly admitted flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowAdmission {
    pub flow: FlowId,
    pub kind: FlowKind,
    pub nat: Option<NatMapping>,
}

/// Why a flow ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CloseReason {
    /// The guest or the peer closed it.
    Closed,
    /// Its egress grant is gone from the profile.
    GrantRevoked {
        route: RouteId,
    },
    /// Its egress grant changed, so it would need authorizing again.
    GrantChanged {
        route: RouteId,
    },
    LinkRevoked,
    PublicationWithdrawn,
    /// The address no longer passes the address rules, for example because the host
    /// now owns it.
    AddressNowRefused(AddressRefused),
}

/// One flow a revocation closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClosedFlow {
    pub flow: FlowId,
    pub sandbox: ExecutionId,
    pub kind: FlowKind,
    pub reason: CloseReason,
}

/// Every flow a change closed (VM-W13: revocation closes existing sessions). The caller
/// tears each one down; the model already refuses their packets.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Revocation {
    pub closed: Vec<ClosedFlow>,
}

impl Revocation {
    /// The ids of the closed flows.
    pub fn flow_ids(&self) -> BTreeSet<FlowId> {
        self.closed.iter().map(|closed| closed.flow).collect()
    }
}

/// The host DNS listener's answer to one guest query (VM §4.2; VM-W08).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsAnswer {
    /// Validated addresses of a granted name. `external` is false for an endpoint
    /// grant's name, which is answered locally.
    Addresses {
        route: RouteId,
        addresses: Vec<IpAddr>,
        valid_until: MonotonicTime,
        external: bool,
    },
    /// An empty answer: AAAA for a grant without IPv6, or for a sandbox without an IPv6
    /// address; never an IPv4 address in disguise (line 1940). No query was sent.
    NoData,
    /// The name is not granted; answered locally as nonexistent. No query was sent.
    NameNotAuthorized,
    /// The query name does not parse under the V02 parser. No query was sent.
    Malformed(NameError),
    /// The query type is not served. No query was sent.
    Unsupported(GuestQueryType),
    /// The answer was refused after authorization: by the broker (resolver failure,
    /// budget, an address that fails validation) or because an address lies outside the
    /// grant's perimeter prefixes.
    Refused(FlowRefusal),
}

/// Route usage in the flow model: name queries from the V02 broker, the rest from the
/// flow model's own V02 budget book.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RouteUsageView {
    pub dns_queries: u64,
    pub connections: u64,
    pub bytes_out: u64,
    pub bytes_in: u64,
}

/// Why a NAT mapping was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NatError {
    /// The destination is a host or sandbox address; a mapping never targets one.
    DestinationNotExternal {
        address: IpAddr,
    },
    /// The egress address is a sandbox address.
    EgressIsSandboxAddress {
        address: IpAddr,
    },
    NoEgressForFamily,
    Exhausted,
}

impl fmt::Display for NatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DestinationNotExternal { address } => write!(
                f,
                "{address} is a host or sandbox address; NAT never maps onto one"
            ),
            Self::EgressIsSandboxAddress { address } => {
                write!(f, "the egress address {address} is a sandbox address")
            }
            Self::NoEgressForFamily => f.write_str("there is no egress address for this family"),
            Self::Exhausted => f.write_str("the sandbox's NAT port block is full"),
        }
    }
}

impl std::error::Error for NatError {}

/// Where an address belongs, for a NAT mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NatScope {
    External,
    /// The host's own address, loopback included.
    Host,
    /// An address of the sandbox pool.
    Sandbox,
}

/// The NAT table of one host (VM-W59 NAT). Each mapping takes the lowest free port of
/// the sandbox's own block on the egress address, so the same sequence of flows gives
/// the same mappings and two sandboxes never share an outside port.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NatTable {
    in_use: BTreeMap<(IpAddr, u16), (ExecutionId, FlowId)>,
}

impl NatTable {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Maps `key` for `sandbox` to `egress` with a port from `block` (first port, size).
    /// `scope_of` says where an address belongs; a host or sandbox destination is
    /// refused, as is a sandbox address as the egress.
    pub fn map(
        &mut self,
        sandbox: &ExecutionId,
        flow: FlowId,
        key: &FlowKey,
        egress: Option<IpAddr>,
        block: (u16, u16),
        scope_of: impl Fn(IpAddr) -> NatScope,
    ) -> Result<NatMapping, NatError> {
        if scope_of(key.destination) != NatScope::External {
            return Err(NatError::DestinationNotExternal {
                address: key.destination,
            });
        }
        let egress = egress.ok_or(NatError::NoEgressForFamily)?;
        if scope_of(egress) == NatScope::Sandbox {
            return Err(NatError::EgressIsSandboxAddress { address: egress });
        }
        let (first, size) = block;
        let port = (0..size)
            .filter_map(|offset| first.checked_add(offset))
            .find(|port| !self.in_use.contains_key(&(egress, *port)))
            .ok_or(NatError::Exhausted)?;
        self.in_use.insert((egress, port), (sandbox.clone(), flow));
        Ok(NatMapping {
            transport: key.transport,
            inside: (key.source, key.source_port),
            outside: (egress, port),
            destination: (key.destination, key.destination_port),
        })
    }

    /// Frees a mapping's outside port.
    pub fn release(&mut self, mapping: &NatMapping) {
        self.in_use.remove(&mapping.outside);
    }

    /// The sandbox and flow holding an outside address and port.
    pub fn holder(&self, outside: (IpAddr, u16)) -> Option<&(ExecutionId, FlowId)> {
        self.in_use.get(&outside)
    }

    /// Number of mappings held.
    pub fn len(&self) -> usize {
        self.in_use.len()
    }

    /// True when no mapping is held.
    pub fn is_empty(&self) -> bool {
        self.in_use.is_empty()
    }
}

/// Why the flow model refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FlowRefusal {
    UnknownSandbox {
        execution: ExecutionId,
    },
    /// The packet's source is not the sandbox's own address for that family (a guest
    /// root spoofing another address).
    SpoofedSource {
        source: IpAddr,
    },
    /// Source and destination are of different families.
    FamilyMismatch,
    /// An IPv6 flow from a sandbox without an IPv6 address.
    NoIpv6Identity,
    /// Port 0 on TCP or UDP.
    InvalidPort,
    /// The 5-tuple already has an open flow.
    AlreadyEstablished {
        flow: FlowId,
    },
    /// No open flow has this 5-tuple, or the flow was closed: a reconnect must be
    /// opened, and is authorized again.
    NotEstablished,
    /// An inbound packet that matches no flow's NAT mapping.
    UnsolicitedInbound,
    /// A host service other than the DNS and proxy listeners.
    HostService {
        address: IpAddr,
        port: u16,
    },
    /// The sandbox addressed itself through the host.
    OwnAddress,
    /// A pool address no sandbox holds.
    UnassignedSandboxAddress {
        address: IpAddr,
    },
    /// V02's address rules refused the destination.
    Address(AddressRefused),
    /// V02's destination policy refused the destination.
    Authorization(AuthorizationRefusal),
    /// The V02 broker refused (resolution, validation, staleness).
    Destination(DestinationRefusal),
    /// The address is not inside the grant's perimeter prefixes.
    OutsidePerimeterPrefixes {
        route: RouteId,
        address: IpAddr,
    },
    /// The host answer that bound this address has expired; query again.
    BindingExpired {
        address: IpAddr,
    },
    /// The destination is granted, but not for this transport.
    TransportNotGranted {
        transport: Transport,
    },
    Connection(ConnectionRefusal),
    Ingress(IngressError),
    ConcurrentFlowLimit {
        limit: u32,
    },
    NewFlowRate {
        limit: u32,
        interval_seconds: u64,
    },
    Nat(NatError),
    Budget(BudgetExhausted),
    Release(ReleaseError),
    Settle(SettleError),
    /// The proxy request's authority does not parse under the V02 parser.
    Name(NameError),
    /// The grant's resolver is not among the resolvers the host supplied.
    ResolverUnavailable {
        resolver: ResolverId,
    },
    /// The operation does not apply to this kind of flow.
    WrongFlowKind,
    /// The host now owns this sandbox's own address; no flow leaves from it.
    IdentityHostOwned {
        address: IpAddr,
    },
    /// Flow ids would pass `u64::MAX`; ids are never reused.
    FlowIdsExhausted,
}

impl fmt::Display for FlowRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownSandbox { execution } => write!(f, "{execution} is not admitted"),
            Self::SpoofedSource { source } => {
                write!(f, "{source} is not this sandbox's address")
            }
            Self::FamilyMismatch => f.write_str("source and destination families differ"),
            Self::NoIpv6Identity => f.write_str("this sandbox has no IPv6 address"),
            Self::InvalidPort => f.write_str("port 0 is not a destination"),
            Self::AlreadyEstablished { flow } => write!(f, "{flow} already carries this 5-tuple"),
            Self::NotEstablished => {
                f.write_str("no open flow carries this 5-tuple; open it to be authorized")
            }
            Self::UnsolicitedInbound => f.write_str("no flow expects this inbound packet"),
            Self::HostService { address, port } => {
                write!(
                    f,
                    "{address} port {port} is a host service the sandbox may not reach"
                )
            }
            Self::OwnAddress => f.write_str("a sandbox does not reach itself through the host"),
            Self::UnassignedSandboxAddress { address } => {
                write!(f, "no sandbox holds {address}")
            }
            Self::Address(refused) => fmt::Display::fmt(refused, f),
            Self::Authorization(refusal) => fmt::Display::fmt(refusal, f),
            Self::Destination(refusal) => fmt::Display::fmt(refusal, f),
            Self::OutsidePerimeterPrefixes { route, address } => write!(
                f,
                "{address} is outside the perimeter prefixes of route {route}"
            ),
            Self::BindingExpired { address } => {
                write!(f, "the answer that gave {address} expired; query again")
            }
            Self::TransportNotGranted { transport } => {
                write!(f, "the destination is not granted for {transport:?}")
            }
            Self::Connection(refusal) => fmt::Display::fmt(refusal, f),
            Self::Ingress(error) => fmt::Display::fmt(error, f),
            Self::ConcurrentFlowLimit { limit } => {
                write!(f, "at most {limit} flows may be open at once")
            }
            Self::NewFlowRate {
                limit,
                interval_seconds,
            } => write!(f, "at most {limit} new flows per {interval_seconds} s"),
            Self::Nat(error) => fmt::Display::fmt(error, f),
            Self::Budget(exhausted) => fmt::Display::fmt(exhausted, f),
            Self::Release(error) => fmt::Display::fmt(error, f),
            Self::Settle(error) => fmt::Display::fmt(error, f),
            Self::Name(error) => fmt::Display::fmt(error, f),
            Self::ResolverUnavailable { resolver } => {
                write!(f, "resolver {resolver} is not available to the host")
            }
            Self::WrongFlowKind => f.write_str("that does not apply to this flow"),
            Self::IdentityHostOwned { address } => {
                write!(f, "the host owns {address}, this sandbox's own address")
            }
            Self::FlowIdsExhausted => f.write_str("no flow id is left"),
        }
    }
}

impl std::error::Error for FlowRefusal {}

impl From<AuthorizationRefusal> for FlowRefusal {
    fn from(refusal: AuthorizationRefusal) -> Self {
        Self::Authorization(refusal)
    }
}

impl From<DestinationRefusal> for FlowRefusal {
    /// The broker's authorization refusals are policy refusals, reported as such.
    fn from(refusal: DestinationRefusal) -> Self {
        match refusal {
            DestinationRefusal::Authorization(refusal) => Self::Authorization(refusal),
            other => Self::Destination(other),
        }
    }
}

impl From<BudgetExhausted> for FlowRefusal {
    fn from(exhausted: BudgetExhausted) -> Self {
        Self::Budget(exhausted)
    }
}

impl From<ReleaseError> for FlowRefusal {
    fn from(error: ReleaseError) -> Self {
        Self::Release(error)
    }
}
