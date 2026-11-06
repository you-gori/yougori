//! Network modes and optional synthetic addressing (VM §4.1).
//!
//! Strict action mode has no host-facing NIC and carries only typed operations; declared
//! transport mode carries explicit connections and publications and reports its broader
//! authority; offline mode carries neither; a user-owned general VM keeps a minimal NIC
//! under its own perimeter profile and never receives the strict mode's claims.

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::address::{
    classify, AddressClass, HostAddressState, IpPrefix, METADATA_IPV4, METADATA_IPV6,
};
use super::name::{CanonicalName, NameError};
use crate::foundation::ids::Digest;

strict_tagged_enum! {
    /// The network mode of a sandbox (VM §4.1).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum NetworkMode (tag = "mode", wire = NetworkModeWire, wire_name = "NetworkModeWire") {
        /// No virtual NIC connected to the host network; the workload requests approved
        /// operations over the bounded channel and the host validates each one.
        StrictAction,
        /// A hardware VM with explicitly authorized connections or service publication.
        DeclaredTransport,
        /// Neither operations nor transport.
        Offline,
        /// A user-owned general-purpose VM with a minimal NIC under its own declared
        /// perimeter profile: the digest of its network profile
        /// (`sandbox_contract::netprofile`, VM-W59), from which the `PerimeterProfile`
        /// rules the independent perimeter enforces are compiled.
        UserOwnedGeneralVm {
            perimeter_profile: Digest,
        },
    }
}

/// A property a mode may claim (VM §4.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ModeClaim {
    /// No virtual NIC is connected to the host network.
    NoHostFacingNic,
    /// Only typed operations leave the sandbox.
    TypedOperationsOnly,
    /// The host validates every operation independently of guest code.
    HostValidatesEveryOperation,
    /// Bypassing the proxy fails because there is no NIC to bypass through.
    BypassFailsWithoutNic,
    /// Nothing leaves or enters over the network.
    NoNetworkExposure,
    /// Only explicitly authorized connections and publications exist.
    ExplicitConnectionsOnly,
}

/// What kind of network authority is requested of a mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RouteClass {
    /// A typed operation route (TLS terminated at the executor).
    Operation,
    /// A pass-through transport route.
    Transport,
    /// An inbound service publication (VM §4.7).
    Publication,
    /// A connection to another sandbox (VM §4.7).
    SandboxConnection,
}

/// Why a mode refused a claim or a route class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModeRefusal {
    ClaimNotHeld {
        mode: NetworkMode,
        claim: ModeClaim,
    },
    RouteClassNotPermitted {
        mode: NetworkMode,
        class: RouteClass,
    },
}

impl fmt::Display for ModeRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClaimNotHeld { mode, claim } => {
                write!(f, "{} cannot claim {claim:?}", mode.label())
            }
            Self::RouteClassNotPermitted { mode, class } => {
                write!(f, "{} does not permit {class:?} routes", mode.label())
            }
        }
    }
}

impl std::error::Error for ModeRefusal {}

impl NetworkMode {
    /// A short user-facing label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::StrictAction => "strict action mode",
            Self::DeclaredTransport => "declared transport mode",
            Self::Offline => "offline mode",
            Self::UserOwnedGeneralVm { .. } => "user-owned general VM (not a strict sandbox)",
        }
    }

    /// The claims this mode may make. A user-owned general VM makes none (line 1936).
    pub const fn claims(self) -> &'static [ModeClaim] {
        match self {
            Self::StrictAction => &[
                ModeClaim::NoHostFacingNic,
                ModeClaim::TypedOperationsOnly,
                ModeClaim::HostValidatesEveryOperation,
                ModeClaim::BypassFailsWithoutNic,
            ],
            Self::DeclaredTransport => &[ModeClaim::ExplicitConnectionsOnly],
            Self::Offline => &[ModeClaim::NoHostFacingNic, ModeClaim::NoNetworkExposure],
            Self::UserOwnedGeneralVm { .. } => &[],
        }
    }

    /// Refuses a claim the mode does not hold.
    pub fn require_claim(self, claim: ModeClaim) -> Result<(), ModeRefusal> {
        if self.claims().contains(&claim) {
            Ok(())
        } else {
            Err(ModeRefusal::ClaimNotHeld { mode: self, claim })
        }
    }

    /// True when a virtual NIC reaches the host network.
    pub const fn has_host_facing_nic(self) -> bool {
        matches!(
            self,
            Self::DeclaredTransport | Self::UserOwnedGeneralVm { .. }
        )
    }

    /// The broader authority the mode must report, if any (line 1934).
    pub const fn broader_authority(self) -> Option<&'static str> {
        match self {
            Self::DeclaredTransport | Self::UserOwnedGeneralVm { .. } => Some(
                "encrypted transport can conceal the application's methods and payloads from \
                 the broker",
            ),
            Self::StrictAction | Self::Offline => None,
        }
    }

    /// Refuses a route class the mode does not carry: strict action mode carries only
    /// typed operations, offline mode nothing.
    pub fn permits(self, class: RouteClass) -> Result<(), ModeRefusal> {
        let permitted = match self {
            Self::StrictAction => matches!(class, RouteClass::Operation),
            Self::DeclaredTransport | Self::UserOwnedGeneralVm { .. } => true,
            Self::Offline => false,
        };
        if permitted {
            Ok(())
        } else {
            Err(ModeRefusal::RouteClassNotPermitted { mode: self, class })
        }
    }
}

/// An address family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

/// Where a rejected synthetic candidate collided (VM §4.1, line 1940).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CollisionSource {
    /// An address or prefix the host owns, such as an overlay VPN in CGNAT space.
    HostOwned,
    /// A prefix the caller reserved, such as an exact endpoint grant or a host route.
    Reserved(IpPrefix),
    /// A known metadata endpoint lies inside the candidate.
    Metadata(IpAddr),
}

/// A synthetic candidate that was skipped, and why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SkippedCandidate {
    pub prefix: IpPrefix,
    pub source: CollisionSource,
}

/// Why synthetic addressing refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyntheticError {
    /// Every candidate collided; nothing is chosen rather than a colliding range.
    NoUsableCandidate {
        family: AddressFamily,
        skipped: Vec<SkippedCandidate>,
    },
    /// A candidate of the wrong family, too small, or in public space (it would shadow
    /// real destinations); IPv6 candidates must be unique-local.
    UnsuitableCandidate { prefix: IpPrefix },
    /// The plan has no free address left.
    Exhausted { family: AddressFamily },
    /// IPv6 was requested for a name but the plan has no IPv6 range.
    NoIpv6Range,
    /// A real resolved address falls inside the synthetic range and could not be told
    /// apart from a synthetic one.
    Collision { address: IpAddr, prefix: IpPrefix },
}

impl fmt::Display for SyntheticError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoUsableCandidate { family, skipped } => write!(
                f,
                "every {family:?} synthetic candidate collides ({} skipped); choose another range",
                skipped.len()
            ),
            Self::UnsuitableCandidate { prefix } => {
                write!(f, "{prefix} cannot be a synthetic range")
            }
            Self::Exhausted { family } => write!(f, "the {family:?} synthetic range is full"),
            Self::NoIpv6Range => f.write_str("the synthetic plan has no IPv6 range"),
            Self::Collision { address, prefix } => write!(
                f,
                "the real address {address} lies in the synthetic range {prefix}"
            ),
        }
    }
}

impl std::error::Error for SyntheticError {}

/// The synthetic addresses given to one authorized name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SyntheticAssignment {
    pub ipv4: Ipv4Addr,
    /// Present only when the name's grant permits IPv6.
    pub ipv6: Option<Ipv6Addr>,
}

/// A guest DNS query type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GuestQueryType {
    A,
    Aaaa,
    Https,
    Svcb,
    Mx,
    Txt,
    Srv,
    Ptr,
    Any,
    Other(u16),
}

/// The local answer to a guest DNS query. No answer involves external DNS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyntheticAnswer {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    /// AAAA for a name without an IPv6 grant: an empty answer (NODATA), never an IPv4
    /// address in disguise (line 1940).
    NoIpv6Grant,
    /// The name is not authorized; answered locally as nonexistent.
    NameNotAuthorized,
    /// The query name does not parse under the destination parser.
    MalformedName(NameError),
    /// The query type is not implemented (NOTIMP), explicitly rather than by a guess.
    Unsupported(GuestQueryType),
}

/// A guest packet's protocol, as the compatibility layer sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GuestProtocol {
    Tcp { port: u16 },
    Udp { port: u16 },
    Icmp,
    Other(u8),
}

/// Why the compatibility layer refused a guest packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProtocolRefusal {
    /// The destination is outside the synthetic ranges; without a host-facing NIC there
    /// is no other way out (line 1938).
    NotSynthetic,
    /// A synthetic address no name was assigned.
    UnassignedAddress,
    /// QUIC/HTTP/3 over UDP 443 is refused so clients fall back to TCP.
    Quic,
    /// Other UDP, ICMP and other protocols are refused explicitly.
    UnsupportedProtocol,
}

/// What the compatibility layer does with a guest packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProtocolHandling {
    /// A TCP stream to an assigned synthetic address, mediated by the broker under the
    /// authorized name.
    MediatedByBroker {
        name: CanonicalName,
        port: u16,
    },
    /// A DNS query to the synthetic resolver, answered locally.
    LocalSyntheticDns,
    Refused(ProtocolRefusal),
}

/// Optional synthetic addressing for strict-mode guest compatibility (VM §4.1, lines
/// 1938–1940), with explicit collision handling: a candidate range that overlaps a
/// host-owned or reserved prefix is skipped and recorded, and a real address inside the
/// chosen range is refused. CGNAT space is not assumed unrouted.
///
/// The first address after the network address is the synthetic resolver; names get
/// addresses from the one after it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyntheticAddressPlan {
    ipv4: IpPrefix,
    ipv6: Option<IpPrefix>,
    skipped: Vec<SkippedCandidate>,
    assignments: BTreeMap<CanonicalName, SyntheticAssignment>,
    by_address: BTreeMap<IpAddr, CanonicalName>,
    next_ipv4: u32,
    next_ipv6: u128,
}

fn choose_candidate(
    family: AddressFamily,
    candidates: &[IpPrefix],
    host: &HostAddressState,
    reserved: &[IpPrefix],
    skipped: &mut Vec<SkippedCandidate>,
) -> Result<Option<IpPrefix>, SyntheticError> {
    for candidate in candidates {
        let suitable = match (family, candidate.network()) {
            (AddressFamily::Ipv4, IpAddr::V4(_)) => {
                candidate.length() <= 30
                    && !matches!(
                        classify(
                            candidate.network(),
                            &HostAddressState::new(host.generation(), [])
                        )
                        .class,
                        AddressClass::Public
                    )
            }
            (AddressFamily::Ipv6, IpAddr::V6(network)) => {
                candidate.length() <= 120 && (network.segments()[0] & 0xfe00) == 0xfc00
            }
            _ => false,
        };
        if !suitable {
            return Err(SyntheticError::UnsuitableCandidate { prefix: *candidate });
        }
        if host.overlaps(candidate) {
            skipped.push(SkippedCandidate {
                prefix: *candidate,
                source: CollisionSource::HostOwned,
            });
            continue;
        }
        let metadata = METADATA_IPV4
            .iter()
            .map(|address| IpAddr::V4(*address))
            .chain(METADATA_IPV6.iter().map(|address| IpAddr::V6(*address)))
            .find(|address| candidate.contains(*address));
        if let Some(address) = metadata {
            skipped.push(SkippedCandidate {
                prefix: *candidate,
                source: CollisionSource::Metadata(address),
            });
            continue;
        }
        if let Some(reserved) = reserved
            .iter()
            .find(|reserved| reserved.overlaps(candidate))
        {
            skipped.push(SkippedCandidate {
                prefix: *candidate,
                source: CollisionSource::Reserved(*reserved),
            });
            continue;
        }
        return Ok(Some(*candidate));
    }
    Ok(None)
}

impl SyntheticAddressPlan {
    /// Chooses the first IPv4 candidate, and the first IPv6 candidate if any are given,
    /// that overlaps no host-owned and no reserved prefix. With no IPv6 candidates the
    /// plan answers no AAAA query with an address.
    pub fn choose(
        ipv4_candidates: &[IpPrefix],
        ipv6_candidates: &[IpPrefix],
        host: &HostAddressState,
        reserved: &[IpPrefix],
    ) -> Result<Self, SyntheticError> {
        let mut skipped = Vec::new();
        let ipv4 = choose_candidate(
            AddressFamily::Ipv4,
            ipv4_candidates,
            host,
            reserved,
            &mut skipped,
        )?
        .ok_or_else(|| SyntheticError::NoUsableCandidate {
            family: AddressFamily::Ipv4,
            skipped: skipped.clone(),
        })?;
        let ipv6 = if ipv6_candidates.is_empty() {
            None
        } else {
            Some(
                choose_candidate(
                    AddressFamily::Ipv6,
                    ipv6_candidates,
                    host,
                    reserved,
                    &mut skipped,
                )?
                .ok_or_else(|| SyntheticError::NoUsableCandidate {
                    family: AddressFamily::Ipv6,
                    skipped: skipped.clone(),
                })?,
            )
        };
        Ok(Self {
            ipv4,
            ipv6,
            skipped,
            assignments: BTreeMap::new(),
            by_address: BTreeMap::new(),
            next_ipv4: 2,
            next_ipv6: 2,
        })
    }

    pub const fn ipv4_range(&self) -> IpPrefix {
        self.ipv4
    }

    pub const fn ipv6_range(&self) -> Option<IpPrefix> {
        self.ipv6
    }

    /// The candidates skipped because they collided.
    pub fn skipped(&self) -> &[SkippedCandidate] {
        &self.skipped
    }

    /// The synthetic resolver's IPv4 address.
    pub fn resolver_ipv4(&self) -> Ipv4Addr {
        ipv4_at(self.ipv4, 1)
    }

    /// Assigns synthetic addresses to an authorized name; the same name keeps its
    /// addresses. IPv6 is assigned only when `ipv6_granted` and the plan has an IPv6 range.
    pub fn assign(
        &mut self,
        name: &CanonicalName,
        ipv6_granted: bool,
    ) -> Result<SyntheticAssignment, SyntheticError> {
        if let Some(existing) = self.assignments.get(name) {
            if ipv6_granted && existing.ipv6.is_none() {
                return Err(SyntheticError::NoIpv6Range);
            }
            return Ok(*existing);
        }
        if ipv6_granted && self.ipv6.is_none() {
            return Err(SyntheticError::NoIpv6Range);
        }
        let ipv4_size = 1u64 << (32 - u32::from(self.ipv4.length()));
        if u64::from(self.next_ipv4) + 1 >= ipv4_size {
            return Err(SyntheticError::Exhausted {
                family: AddressFamily::Ipv4,
            });
        }
        let ipv4 = ipv4_at(self.ipv4, self.next_ipv4);
        let ipv6 = match (ipv6_granted, self.ipv6) {
            (true, Some(range)) => {
                let host_bits = 128 - u32::from(range.length());
                if host_bits < 128 && self.next_ipv6 >= (1u128 << host_bits) {
                    return Err(SyntheticError::Exhausted {
                        family: AddressFamily::Ipv6,
                    });
                }
                Some(ipv6_at(range, self.next_ipv6))
            }
            _ => None,
        };
        self.next_ipv4 = self.next_ipv4.saturating_add(1);
        if ipv6.is_some() {
            self.next_ipv6 = self.next_ipv6.saturating_add(1);
        }
        let assignment = SyntheticAssignment { ipv4, ipv6 };
        self.assignments.insert(name.clone(), assignment);
        self.by_address.insert(IpAddr::V4(ipv4), name.clone());
        if let Some(ipv6) = ipv6 {
            self.by_address.insert(IpAddr::V6(ipv6), name.clone());
        }
        Ok(assignment)
    }

    /// Answers a guest DNS query locally. Unassigned names are nonexistent, AAAA without
    /// an IPv6 grant is empty, and other query types are explicitly unsupported.
    pub fn answer(&self, query_name: &str, query_type: GuestQueryType) -> SyntheticAnswer {
        let name = match CanonicalName::parse(query_name) {
            Ok(name) => name,
            Err(error) => return SyntheticAnswer::MalformedName(error),
        };
        let Some(assignment) = self.assignments.get(&name) else {
            return SyntheticAnswer::NameNotAuthorized;
        };
        match query_type {
            GuestQueryType::A => SyntheticAnswer::Ipv4(assignment.ipv4),
            GuestQueryType::Aaaa => match assignment.ipv6 {
                Some(ipv6) => SyntheticAnswer::Ipv6(ipv6),
                None => SyntheticAnswer::NoIpv6Grant,
            },
            other => SyntheticAnswer::Unsupported(other),
        }
    }

    /// Refuses a real resolved address that falls inside a synthetic range.
    pub fn check_real_address(&self, address: IpAddr) -> Result<(), SyntheticError> {
        for range in std::iter::once(self.ipv4).chain(self.ipv6) {
            if range.contains(address) {
                return Err(SyntheticError::Collision {
                    address,
                    prefix: range,
                });
            }
        }
        Ok(())
    }

    /// Decides what happens to a guest packet. Only TCP to an assigned address and DNS to
    /// the synthetic resolver proceed; everything else is refused explicitly.
    pub fn handle(&self, destination: IpAddr, protocol: GuestProtocol) -> ProtocolHandling {
        let synthetic = self.ipv4.contains(destination)
            || self.ipv6.is_some_and(|range| range.contains(destination));
        if !synthetic {
            return ProtocolHandling::Refused(ProtocolRefusal::NotSynthetic);
        }
        match protocol {
            GuestProtocol::Udp { port: 53 } if destination == IpAddr::V4(self.resolver_ipv4()) => {
                ProtocolHandling::LocalSyntheticDns
            }
            GuestProtocol::Udp { port: 443 } => ProtocolHandling::Refused(ProtocolRefusal::Quic),
            GuestProtocol::Tcp { port } => match self.by_address.get(&destination) {
                Some(name) => ProtocolHandling::MediatedByBroker {
                    name: name.clone(),
                    port,
                },
                None => ProtocolHandling::Refused(ProtocolRefusal::UnassignedAddress),
            },
            GuestProtocol::Udp { .. } | GuestProtocol::Icmp | GuestProtocol::Other(_) => {
                ProtocolHandling::Refused(ProtocolRefusal::UnsupportedProtocol)
            }
        }
    }
}

fn ipv4_at(range: IpPrefix, offset: u32) -> Ipv4Addr {
    match range.network() {
        IpAddr::V4(network) => Ipv4Addr::from(u32::from(network).wrapping_add(offset)),
        IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
    }
}

fn ipv6_at(range: IpPrefix, offset: u128) -> Ipv6Addr {
    match range.network() {
        IpAddr::V6(network) => Ipv6Addr::from(u128::from(network).wrapping_add(offset)),
        IpAddr::V4(_) => Ipv6Addr::UNSPECIFIED,
    }
}
