//! Classification of every resolved or granted address (VM §4.2 step 4; VM-P08): private,
//! loopback, link-local, metadata, multicast, broadcast, unspecified, IPv4 embedded in
//! IPv6, shared CGNAT space, documentation and benchmarking ranges, other reserved space
//! and the addresses the host itself owns.
//!
//! Classification is an allow-list: only global unicast space outside every special range
//! is [`AddressClass::Public`], so a range missing from the lists below is refused as
//! reserved rather than allowed.

use std::collections::BTreeSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

/// What an address is, for destination policy (VM §4.2 step 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressClass {
    /// Global unicast outside every special range.
    Public,
    /// `0.0.0.0/8` ("this network") or `::`.
    Unspecified,
    /// `127.0.0.0/8` or `::1`.
    Loopback,
    /// RFC 1918 space or IPv6 unique-local `fc00::/7`.
    Private,
    /// `100.64.0.0/10`, shared address space that real networks (carrier NAT, overlay
    /// VPNs) route (VM §4.1, line 1940).
    SharedCgnat,
    /// `169.254.0.0/16` or `fe80::/10`.
    LinkLocal,
    /// A cloud instance metadata or platform service endpoint; see
    /// [`METADATA_IPV4`] and [`METADATA_IPV6`].
    Metadata,
    /// `224.0.0.0/4` or `ff00::/8`.
    Multicast,
    /// `255.255.255.255`.
    Broadcast,
    /// `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`, `3fff::/20`.
    Documentation,
    /// `198.18.0.0/15` or `2001:2::/48`.
    Benchmarking,
    /// Other special-purpose or unallocated space, including `240.0.0.0/4`,
    /// `192.0.0.0/24`, `192.88.99.0/24`, `100::/64`, `2001::/23`, `fec0::/10` and all
    /// IPv6 outside `2000::/3`.
    Reserved,
    /// An IPv6 address that carries an IPv4 address; see [`EmbeddedIpv4Form`].
    EmbeddedIpv4(EmbeddedIpv4Form),
    /// An address the host reports as its own: interfaces, gateways, VPN and resolver
    /// addresses (VM §4.2 step 4: host-owned address rules).
    HostOwned,
}

impl fmt::Display for AddressClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Public => "public",
            Self::Unspecified => "unspecified",
            Self::Loopback => "loopback",
            Self::Private => "private",
            Self::SharedCgnat => "shared CGNAT space",
            Self::LinkLocal => "link-local",
            Self::Metadata => "a metadata service",
            Self::Multicast => "multicast",
            Self::Broadcast => "broadcast",
            Self::Documentation => "documentation space",
            Self::Benchmarking => "benchmarking space",
            Self::Reserved => "reserved space",
            Self::EmbeddedIpv4(form) => return write!(f, "IPv4 embedded in IPv6 ({form:?})"),
            Self::HostOwned => "an address of this host",
        };
        f.write_str(text)
    }
}

/// The IPv6 forms that carry an IPv4 address (VM §4.2 step 4: mapped/translated rules).
/// Every one is refused: the IPv4 address must be presented as IPv4, so one address has
/// one form, and a translator the host does not control would choose the real target.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmbeddedIpv4Form {
    /// `::ffff:0:0/96` (RFC 4291).
    Mapped,
    /// `::/96` other than `::` and `::1`, the deprecated IPv4-compatible form.
    Compatible,
    /// `::ffff:0:0:0/96`, the SIIT translated form (RFC 2765).
    Translated,
    /// `64:ff9b::/96`, the NAT64 well-known prefix (RFC 6052).
    Nat64WellKnown,
    /// `64:ff9b:1::/48`, the NAT64 local-use prefix (RFC 8215).
    Nat64LocalUse,
    /// `2002::/16`, 6to4 (RFC 3056).
    SixToFour,
    /// `2001::/32`, Teredo (RFC 4380); the client address is stored inverted.
    Teredo,
}

/// Known metadata and platform-service IPv4 endpoints: the common instance metadata
/// address, AWS ECS task metadata, AWS VPC DNS and time sync, Azure WireServer, Alibaba
/// Cloud metadata and Oracle Cloud Classic metadata.
pub const METADATA_IPV4: [Ipv4Addr; 7] = [
    Ipv4Addr::new(169, 254, 169, 254),
    Ipv4Addr::new(169, 254, 170, 2),
    Ipv4Addr::new(169, 254, 169, 253),
    Ipv4Addr::new(169, 254, 169, 123),
    Ipv4Addr::new(168, 63, 129, 16),
    Ipv4Addr::new(100, 100, 100, 200),
    Ipv4Addr::new(192, 0, 0, 192),
];

/// Known metadata and platform-service IPv6 endpoints: AWS instance metadata, DNS and time
/// sync (`fd00:ec2::254`, `::253`, `::123`) and Google Cloud metadata (`fd20:ce::254`).
pub const METADATA_IPV6: [Ipv6Addr; 4] = [
    Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254),
    Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0253),
    Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0123),
    Ipv6Addr::new(0xfd20, 0x00ce, 0, 0, 0, 0, 0, 0x0254),
];

/// Why a prefix was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrefixError {
    LengthTooLong {
        length: u8,
        max: u8,
    },
    /// Bits beyond the prefix length are set, so the prefix is spelled ambiguously.
    HostBitsSet,
}

impl fmt::Display for PrefixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthTooLong { length, max } => {
                write!(f, "prefix length {length} exceeds {max}")
            }
            Self::HostBitsSet => f.write_str("the prefix has host bits set"),
        }
    }
}

impl std::error::Error for PrefixError {}

/// An address prefix such as `100.64.0.0/10`, with no host bits set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "RawPrefix", into = "RawPrefix")]
pub struct IpPrefix {
    network: IpAddr,
    length: u8,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPrefix {
    network: IpAddr,
    length: u8,
}

impl TryFrom<RawPrefix> for IpPrefix {
    type Error = PrefixError;

    fn try_from(raw: RawPrefix) -> Result<Self, Self::Error> {
        Self::new(raw.network, raw.length)
    }
}

impl From<IpPrefix> for RawPrefix {
    fn from(prefix: IpPrefix) -> Self {
        Self {
            network: prefix.network,
            length: prefix.length,
        }
    }
}

fn bits(address: IpAddr) -> (u128, u8) {
    match address {
        IpAddr::V4(address) => (u128::from(u32::from(address)), 32),
        IpAddr::V6(address) => (u128::from(address), 128),
    }
}

/// The network mask of a prefix of `length` bits in a family `width` bits wide.
fn mask(length: u8, width: u8) -> u128 {
    if length == 0 {
        return 0;
    }
    let family = if width >= 128 {
        u128::MAX
    } else {
        (1u128 << width) - 1
    };
    let host_bits = u32::from(width.saturating_sub(length));
    let host = if host_bits >= 128 {
        u128::MAX
    } else {
        (1u128 << host_bits) - 1
    };
    family & !host
}

impl IpPrefix {
    /// Refuses a length beyond the family's width and set host bits.
    pub fn new(network: IpAddr, length: u8) -> Result<Self, PrefixError> {
        let (value, width) = bits(network);
        if length > width {
            return Err(PrefixError::LengthTooLong { length, max: width });
        }
        if value & !mask(length, width) != 0 {
            return Err(PrefixError::HostBitsSet);
        }
        Ok(Self { network, length })
    }

    /// The single-address prefix of `address`.
    pub fn host(address: IpAddr) -> Self {
        let length = bits(address).1;
        Self {
            network: address,
            length,
        }
    }

    pub const fn network(&self) -> IpAddr {
        self.network
    }

    pub const fn length(&self) -> u8 {
        self.length
    }

    /// True when `address` is in this prefix (same family only).
    pub fn contains(&self, address: IpAddr) -> bool {
        let (network, width) = bits(self.network);
        let (value, other_width) = bits(address);
        width == other_width && value & mask(self.length, width) == network
    }

    /// True when the two prefixes share any address.
    pub fn overlaps(&self, other: &IpPrefix) -> bool {
        self.contains(other.network) || other.contains(self.network)
    }
}

impl fmt::Display for IpPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.length)
    }
}

/// The host's address-state generation. Any change to the host's owned addresses raises
/// it, and every validated destination is bound to the generation it was checked under
/// (VM §4.2 step 6: changed host-address state forces revalidation).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HostAddressGeneration(u64);

impl HostAddressGeneration {
    /// Where a host's address state starts.
    pub const FIRST: Self = Self(1);

    /// A generation read back from the host.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for HostAddressGeneration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The addresses and prefixes the host reports as its own, under one generation. The
/// host supplies this; a guest never does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostAddressState {
    generation: HostAddressGeneration,
    owned: BTreeSet<IpPrefix>,
}

impl HostAddressState {
    /// The host's owned addresses under `generation`; a replacement needs a newer one.
    pub fn new(
        generation: HostAddressGeneration,
        owned: impl IntoIterator<Item = IpPrefix>,
    ) -> Self {
        Self {
            generation,
            owned: owned.into_iter().collect(),
        }
    }

    pub const fn generation(&self) -> HostAddressGeneration {
        self.generation
    }

    pub fn owned(&self) -> impl Iterator<Item = &IpPrefix> {
        self.owned.iter()
    }

    /// True when `address` is one of the host's own addresses.
    pub fn owns(&self, address: IpAddr) -> bool {
        self.owned.iter().any(|prefix| prefix.contains(address))
    }

    /// True when any owned prefix overlaps `prefix`.
    pub fn overlaps(&self, prefix: &IpPrefix) -> bool {
        self.owned.iter().any(|owned| owned.overlaps(prefix))
    }
}

/// An IPv4 address found inside an IPv6 address, and what it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EmbeddedIpv4 {
    pub form: EmbeddedIpv4Form,
    pub ipv4: Ipv4Addr,
    /// The IPv4 address's own class; never [`AddressClass::EmbeddedIpv4`].
    pub ipv4_class: AddressClass,
}

/// The classification of one address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AddressVerdict {
    pub address: IpAddr,
    pub class: AddressClass,
    pub embedded: Option<EmbeddedIpv4>,
}

/// Classifies `address` against the fixed special ranges and the host's own addresses.
/// Host-owned addresses come first, then metadata endpoints, then the general ranges.
pub fn classify(address: IpAddr, host: &HostAddressState) -> AddressVerdict {
    match address {
        IpAddr::V4(ipv4) => AddressVerdict {
            address,
            class: if host.owns(address) {
                AddressClass::HostOwned
            } else {
                classify_ipv4(ipv4)
            },
            embedded: None,
        },
        IpAddr::V6(ipv6) => {
            let embedded = embedded_ipv4(ipv6).map(|(form, ipv4)| EmbeddedIpv4 {
                form,
                ipv4,
                ipv4_class: if host.owns(IpAddr::V4(ipv4)) {
                    AddressClass::HostOwned
                } else {
                    classify_ipv4(ipv4)
                },
            });
            let class = if host.owns(address) {
                AddressClass::HostOwned
            } else if let Some(embedded) = embedded {
                AddressClass::EmbeddedIpv4(embedded.form)
            } else {
                classify_ipv6(ipv6)
            };
            AddressVerdict {
                address,
                class,
                embedded,
            }
        }
    }
}

fn in_v4(address: Ipv4Addr, network: [u8; 4], length: u32) -> bool {
    let shift = 32 - length;
    let value = u32::from(address);
    let network = u32::from(Ipv4Addr::from(network));
    if length == 0 {
        true
    } else {
        value >> shift == network >> shift
    }
}

fn classify_ipv4(address: Ipv4Addr) -> AddressClass {
    if METADATA_IPV4.contains(&address) {
        return AddressClass::Metadata;
    }
    const RANGES: &[([u8; 4], u32, AddressClass)] = &[
        ([0, 0, 0, 0], 8, AddressClass::Unspecified),
        ([127, 0, 0, 0], 8, AddressClass::Loopback),
        ([10, 0, 0, 0], 8, AddressClass::Private),
        ([172, 16, 0, 0], 12, AddressClass::Private),
        ([192, 168, 0, 0], 16, AddressClass::Private),
        ([100, 64, 0, 0], 10, AddressClass::SharedCgnat),
        ([169, 254, 0, 0], 16, AddressClass::LinkLocal),
        ([192, 0, 2, 0], 24, AddressClass::Documentation),
        ([198, 51, 100, 0], 24, AddressClass::Documentation),
        ([203, 0, 113, 0], 24, AddressClass::Documentation),
        ([198, 18, 0, 0], 15, AddressClass::Benchmarking),
        ([192, 0, 0, 0], 24, AddressClass::Reserved),
        ([192, 88, 99, 0], 24, AddressClass::Reserved),
        ([255, 255, 255, 255], 32, AddressClass::Broadcast),
        ([224, 0, 0, 0], 4, AddressClass::Multicast),
        ([240, 0, 0, 0], 4, AddressClass::Reserved),
    ];
    RANGES
        .iter()
        .find(|(network, length, _)| in_v4(address, *network, *length))
        .map_or(AddressClass::Public, |(_, _, class)| *class)
}

fn in_v6(address: Ipv6Addr, network: Ipv6Addr, length: u32) -> bool {
    let value = u128::from(address);
    let network = u128::from(network);
    if length == 0 {
        true
    } else {
        value >> (128 - length) == network >> (128 - length)
    }
}

fn embedded_ipv4(address: Ipv6Addr) -> Option<(EmbeddedIpv4Form, Ipv4Addr)> {
    let value = u128::from(address);
    let low32 = Ipv4Addr::from((value & 0xffff_ffff) as u32);
    let segments = address.segments();
    if in_v6(address, Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0, 0), 96) {
        Some((EmbeddedIpv4Form::Mapped, low32))
    } else if in_v6(address, Ipv6Addr::new(0, 0, 0, 0, 0xffff, 0, 0, 0), 96) {
        Some((EmbeddedIpv4Form::Translated, low32))
    } else if in_v6(address, Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0), 96) {
        Some((EmbeddedIpv4Form::Nat64WellKnown, low32))
    } else if in_v6(address, Ipv6Addr::new(0x64, 0xff9b, 1, 0, 0, 0, 0, 0), 48) {
        // RFC 6052 /48 layout: bits 48-63 then, after the zero octet "u", bits 72-87.
        let high = segments[3];
        let low = ((value >> 40) & 0xffff) as u16;
        Some((
            EmbeddedIpv4Form::Nat64LocalUse,
            Ipv4Addr::from((u32::from(high) << 16) | u32::from(low)),
        ))
    } else if in_v6(address, Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0), 16) {
        Some((
            EmbeddedIpv4Form::SixToFour,
            Ipv4Addr::from((u32::from(segments[1]) << 16) | u32::from(segments[2])),
        ))
    } else if in_v6(address, Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 32) {
        Some((
            EmbeddedIpv4Form::Teredo,
            Ipv4Addr::from(!((value & 0xffff_ffff) as u32)),
        ))
    } else if value > 1 && in_v6(address, Ipv6Addr::UNSPECIFIED, 96) {
        Some((EmbeddedIpv4Form::Compatible, low32))
    } else {
        None
    }
}

fn classify_ipv6(address: Ipv6Addr) -> AddressClass {
    if METADATA_IPV6.contains(&address) {
        return AddressClass::Metadata;
    }
    if address == Ipv6Addr::UNSPECIFIED {
        return AddressClass::Unspecified;
    }
    if address == Ipv6Addr::LOCALHOST {
        return AddressClass::Loopback;
    }
    const RANGES: &[(Ipv6Addr, u32, AddressClass)] = &[
        (
            Ipv6Addr::new(0x0100, 0, 0, 0, 0, 0, 0, 0),
            64,
            AddressClass::Reserved,
        ),
        (
            Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0),
            32,
            AddressClass::Documentation,
        ),
        (
            Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0),
            20,
            AddressClass::Documentation,
        ),
        (
            Ipv6Addr::new(0x2001, 0x0002, 0, 0, 0, 0, 0, 0),
            48,
            AddressClass::Benchmarking,
        ),
        (
            Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0),
            23,
            AddressClass::Reserved,
        ),
        (
            Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0),
            7,
            AddressClass::Private,
        ),
        (
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0),
            10,
            AddressClass::LinkLocal,
        ),
        (
            Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 0),
            10,
            AddressClass::Reserved,
        ),
        (
            Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0),
            8,
            AddressClass::Multicast,
        ),
    ];
    if let Some((_, _, class)) = RANGES
        .iter()
        .find(|(network, length, _)| in_v6(address, *network, *length))
    {
        return *class;
    }
    if in_v6(address, Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0), 3) {
        AddressClass::Public
    } else {
        AddressClass::Reserved
    }
}

/// Why an address was refused for a destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressRefused {
    pub verdict: AddressVerdict,
    pub rule: AddressRule,
}

impl fmt::Display for AddressRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} is {}, which {} does not permit",
            self.verdict.address,
            self.verdict.class,
            match self.rule {
                AddressRule::ResolvedName => "a name-resolved destination",
                AddressRule::ExactEndpoint => "an exact endpoint grant",
            }
        )?;
        if let Some(embedded) = self.verdict.embedded {
            write!(
                f,
                " (it carries {}, which is {})",
                embedded.ipv4, embedded.ipv4_class
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for AddressRefused {}

/// Which address rule applies (VM §4.2 steps 4 and the private-endpoint paragraph).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AddressRule {
    /// An address a resolver returned for an authorized name: only public addresses.
    ResolvedName,
    /// The one address an exact endpoint grant names: public, private or shared CGNAT
    /// space. Loopback, link-local, metadata, host-owned, multicast, broadcast,
    /// unspecified, embedded-IPv4, documentation, benchmarking and reserved space are
    /// refused even then.
    ExactEndpoint,
}

impl AddressRule {
    /// Checks one verdict against the rule.
    pub fn check(self, verdict: AddressVerdict) -> Result<(), AddressRefused> {
        let allowed = match self {
            Self::ResolvedName => matches!(verdict.class, AddressClass::Public),
            Self::ExactEndpoint => matches!(
                verdict.class,
                AddressClass::Public | AddressClass::Private | AddressClass::SharedCgnat
            ),
        };
        if allowed {
            Ok(())
        } else {
            Err(AddressRefused {
                verdict,
                rule: self,
            })
        }
    }
}
