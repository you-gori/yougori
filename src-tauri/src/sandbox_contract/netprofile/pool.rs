//! The host's sandbox address pool (VM-W59 network identities; VM §4.7).
//!
//! The host assigns every broader-network VM its guest addresses from one private IPv4
//! prefix and, optionally, one unique-local IPv6 prefix. The first address after each
//! network address is the gateway: the host's own address on the sandbox network, where
//! its DNS and proxy listeners run. Guest addresses come after it, lowest free first, so
//! assignment is deterministic; an address the host owns is never handed out. Each
//! sandbox also gets its own block of NAT ports, so two sandboxes never share a mapping.

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::foundation::ids::{ExecutionId, TrustScope};
use crate::sandbox_contract::destinations::{
    classify, AddressClass, DestinationPort, HostAddressGeneration, HostAddressState, IpPrefix,
    METADATA_IPV4, METADATA_IPV6,
};

use super::document::NetworkIdentity;

/// The host's NAT egress (VM-W59 NAT): the outward addresses flows are translated to and
/// the port range carved into one block per sandbox.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NatConfig {
    pub egress_ipv4: Ipv4Addr,
    /// Present exactly when the pool has an IPv6 prefix.
    pub egress_ipv6: Option<Ipv6Addr>,
    /// The first NAT port; ports below 1024 are never used.
    pub first_port: u16,
    pub ports_per_sandbox: u16,
    pub max_sandboxes: u16,
}

/// How the host's sandbox network is laid out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolConfig {
    /// A private (RFC 1918) prefix, /16 to /29.
    pub ipv4: IpPrefix,
    /// A unique-local prefix, /64 to /112.
    pub ipv6: Option<IpPrefix>,
    /// The gateway port of the HTTP CONNECT proxy listener.
    pub http_proxy_port: DestinationPort,
    /// The gateway port of the SOCKS5 proxy listener.
    pub socks_proxy_port: DestinationPort,
    pub nat: NatConfig,
    /// Candidate ranges a guest's synthetic-name layer may use (VM §4.1, line 1940).
    pub synthetic_ipv4_candidates: Vec<IpPrefix>,
    pub synthetic_ipv6_candidates: Vec<IpPrefix>,
}

/// Why the pool refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PoolError {
    Ipv4PoolNotPrivate {
        prefix: IpPrefix,
        class: AddressClass,
    },
    Ipv6PoolNotUniqueLocal {
        prefix: IpPrefix,
        class: AddressClass,
    },
    PoolLength {
        prefix: IpPrefix,
    },
    /// A host-owned prefix other than the gateway lies in the pool.
    PoolOverlapsHost {
        prefix: IpPrefix,
    },
    PoolContainsMetadata {
        prefix: IpPrefix,
        address: IpAddr,
    },
    /// An IPv6 pool needs an IPv6 egress address and the reverse.
    Ipv6EgressMismatch,
    EgressAddress {
        address: IpAddr,
        class: AddressClass,
    },
    EgressInsidePool {
        address: IpAddr,
    },
    /// The proxy ports must differ from each other and from DNS.
    ListenerPorts,
    /// The NAT port range starts below 1024, is empty or passes 65535.
    NatPortRange,
    AddressesExhausted,
    PortBlocksExhausted,
    AlreadyAssigned {
        execution: ExecutionId,
    },
    /// Only a VM sandbox gets a broader-network identity.
    NotVmSandbox,
}

impl fmt::Display for PoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ipv4PoolNotPrivate { prefix, class } => {
                write!(f, "the IPv4 pool {prefix} is {class}; it must be private")
            }
            Self::Ipv6PoolNotUniqueLocal { prefix, class } => {
                write!(
                    f,
                    "the IPv6 pool {prefix} is {class}; it must be unique-local"
                )
            }
            Self::PoolLength { prefix } => write!(f, "the pool {prefix} has an unusable size"),
            Self::PoolOverlapsHost { prefix } => {
                write!(f, "the host owns {prefix} inside the sandbox pool")
            }
            Self::PoolContainsMetadata { prefix, address } => {
                write!(f, "the pool {prefix} holds the metadata address {address}")
            }
            Self::Ipv6EgressMismatch => {
                f.write_str("an IPv6 pool and an IPv6 egress address come together")
            }
            Self::EgressAddress { address, class } => {
                write!(f, "the egress address {address} is {class}")
            }
            Self::EgressInsidePool { address } => {
                write!(f, "the egress address {address} lies in the sandbox pool")
            }
            Self::ListenerPorts => {
                f.write_str("the proxy ports must differ from each other and from port 53")
            }
            Self::NatPortRange => f.write_str("the NAT port range is unusable"),
            Self::AddressesExhausted => f.write_str("the sandbox pool has no free address"),
            Self::PortBlocksExhausted => f.write_str("every NAT port block is in use"),
            Self::AlreadyAssigned { execution } => {
                write!(f, "{execution} already has a network identity")
            }
            Self::NotVmSandbox => f.write_str("only a VM sandbox gets a network identity"),
        }
    }
}

impl std::error::Error for PoolError {}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Assignment {
    identity: NetworkIdentity,
    offset: u32,
    block: u16,
}

/// The host's sandbox address pool (VM-W59: network identities explicit).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SandboxAddressPool {
    config: PoolConfig,
    assignments: BTreeMap<ExecutionId, Assignment>,
}

fn static_class(address: IpAddr) -> AddressClass {
    classify(
        address,
        &HostAddressState::new(HostAddressGeneration::FIRST, []),
    )
    .class
}

fn ipv4_offset(prefix: IpPrefix, offset: u32) -> Option<Ipv4Addr> {
    match prefix.network() {
        IpAddr::V4(network) => u32::from(network).checked_add(offset).map(Ipv4Addr::from),
        IpAddr::V6(_) => None,
    }
}

fn ipv6_offset(prefix: IpPrefix, offset: u32) -> Option<Ipv6Addr> {
    match prefix.network() {
        IpAddr::V6(network) => u128::from(network)
            .checked_add(u128::from(offset))
            .map(Ipv6Addr::from),
        IpAddr::V4(_) => None,
    }
}

impl SandboxAddressPool {
    /// Checks the layout against the host's own addresses: private and unique-local
    /// prefixes of usable size, holding no metadata address and no host address but the
    /// gateway; egress addresses outside the pool; distinct listener ports; a NAT range
    /// from 1024 that fits in 65535.
    pub fn new(config: PoolConfig, host: &HostAddressState) -> Result<Self, PoolError> {
        let ipv4 = config.ipv4;
        let IpAddr::V4(_) = ipv4.network() else {
            return Err(PoolError::PoolLength { prefix: ipv4 });
        };
        let class = static_class(ipv4.network());
        if class != AddressClass::Private {
            return Err(PoolError::Ipv4PoolNotPrivate {
                prefix: ipv4,
                class,
            });
        }
        if !(16..=29).contains(&ipv4.length()) {
            return Err(PoolError::PoolLength { prefix: ipv4 });
        }
        if let Some(ipv6) = config.ipv6 {
            let IpAddr::V6(_) = ipv6.network() else {
                return Err(PoolError::PoolLength { prefix: ipv6 });
            };
            let class = static_class(ipv6.network());
            if class != AddressClass::Private {
                return Err(PoolError::Ipv6PoolNotUniqueLocal {
                    prefix: ipv6,
                    class,
                });
            }
            if !(64..=112).contains(&ipv6.length()) {
                return Err(PoolError::PoolLength { prefix: ipv6 });
            }
        }
        if config.ipv6.is_some() != config.nat.egress_ipv6.is_some() {
            return Err(PoolError::Ipv6EgressMismatch);
        }
        let pool = Self {
            config,
            assignments: BTreeMap::new(),
        };
        for prefix in pool.prefixes() {
            if let Some(address) = METADATA_IPV4
                .iter()
                .map(|address| IpAddr::V4(*address))
                .chain(METADATA_IPV6.iter().map(|address| IpAddr::V6(*address)))
                .find(|address| prefix.contains(*address))
            {
                return Err(PoolError::PoolContainsMetadata { prefix, address });
            }
            let gateway = pool.gateway_for(prefix.network());
            if let Some(owned) = host.owned().find(|owned| {
                owned.overlaps(&prefix) && gateway.map(IpPrefix::host).as_ref() != Some(*owned)
            }) {
                return Err(PoolError::PoolOverlapsHost { prefix: *owned });
            }
        }
        let egress = std::iter::once(IpAddr::V4(pool.config.nat.egress_ipv4))
            .chain(pool.config.nat.egress_ipv6.map(IpAddr::V6));
        for address in egress {
            let class = static_class(address);
            if !matches!(
                class,
                AddressClass::Public | AddressClass::Private | AddressClass::SharedCgnat
            ) {
                return Err(PoolError::EgressAddress { address, class });
            }
            if pool.contains(address) {
                return Err(PoolError::EgressInsidePool { address });
            }
        }
        let proxy = pool.config.http_proxy_port.get();
        let socks = pool.config.socks_proxy_port.get();
        if proxy == socks || proxy == 53 || socks == 53 {
            return Err(PoolError::ListenerPorts);
        }
        let nat = pool.config.nat;
        let span = u32::from(nat.ports_per_sandbox).checked_mul(u32::from(nat.max_sandboxes));
        let last = span.and_then(|span| u32::from(nat.first_port).checked_add(span));
        if nat.first_port < 1024
            || nat.ports_per_sandbox == 0
            || nat.max_sandboxes == 0
            || last.is_none_or(|last| last > 65_536)
        {
            return Err(PoolError::NatPortRange);
        }
        Ok(pool)
    }

    /// The pool layout.
    pub fn config(&self) -> &PoolConfig {
        &self.config
    }

    /// The pool prefixes, IPv4 first.
    pub fn prefixes(&self) -> Vec<IpPrefix> {
        std::iter::once(self.config.ipv4)
            .chain(self.config.ipv6)
            .collect()
    }

    /// The gateway (host listener) address of the IPv4 pool.
    pub fn gateway_ipv4(&self) -> Option<Ipv4Addr> {
        ipv4_offset(self.config.ipv4, 1)
    }

    /// The gateway (host listener) address of the IPv6 pool.
    pub fn gateway_ipv6(&self) -> Option<Ipv6Addr> {
        self.config.ipv6.and_then(|prefix| ipv6_offset(prefix, 1))
    }

    /// The gateway of `address`'s family.
    pub fn gateway_for(&self, address: IpAddr) -> Option<IpAddr> {
        match address {
            IpAddr::V4(_) => self.gateway_ipv4().map(IpAddr::V4),
            IpAddr::V6(_) => self.gateway_ipv6().map(IpAddr::V6),
        }
    }

    /// True when `address` lies in a pool prefix.
    pub fn contains(&self, address: IpAddr) -> bool {
        self.prefixes()
            .iter()
            .any(|prefix| prefix.contains(address))
    }

    /// The sandbox a guest address is assigned to.
    pub fn owner_of(&self, address: IpAddr) -> Option<&ExecutionId> {
        self.assignments
            .iter()
            .find(|(_, assignment)| assignment.identity.owns(address))
            .map(|(execution, _)| execution)
    }

    /// The identity assigned to `execution`.
    pub fn identity(&self, execution: &ExecutionId) -> Option<&NetworkIdentity> {
        self.assignments
            .get(execution)
            .map(|assignment| &assignment.identity)
    }

    /// Assigns `execution` the lowest free guest address in each pool, skipping the
    /// gateway, the broadcast address and every host-owned address, and the lowest free
    /// NAT port block. The same assignments in the same order give the same identities.
    pub fn assign(
        &mut self,
        execution: ExecutionId,
        scope: TrustScope,
        host: &HostAddressState,
    ) -> Result<NetworkIdentity, PoolError> {
        if !scope.category.is_vm_sandbox() {
            return Err(PoolError::NotVmSandbox);
        }
        if self.assignments.contains_key(&execution) {
            return Err(PoolError::AlreadyAssigned { execution });
        }
        let size = 1u64 << (32 - u32::from(self.config.ipv4.length()));
        let last_offset = u32::try_from(size.saturating_sub(1)).unwrap_or(u32::MAX);
        let used: Vec<u32> = self
            .assignments
            .values()
            .map(|assignment| assignment.offset)
            .collect();
        let mut chosen = None;
        for offset in 2..last_offset {
            if used.contains(&offset) {
                continue;
            }
            let Some(ipv4) = ipv4_offset(self.config.ipv4, offset) else {
                break;
            };
            let ipv6 = match self.config.ipv6 {
                Some(prefix) => match ipv6_offset(prefix, offset) {
                    Some(address) => Some(address),
                    None => break,
                },
                None => None,
            };
            if host.owns(IpAddr::V4(ipv4)) || ipv6.is_some_and(|ipv6| host.owns(IpAddr::V6(ipv6))) {
                continue;
            }
            chosen = Some((offset, ipv4, ipv6));
            break;
        }
        let (offset, ipv4, ipv6) = chosen.ok_or(PoolError::AddressesExhausted)?;
        let blocks: Vec<u16> = self
            .assignments
            .values()
            .map(|assignment| assignment.block)
            .collect();
        let block = (0..self.config.nat.max_sandboxes)
            .find(|block| !blocks.contains(block))
            .ok_or(PoolError::PortBlocksExhausted)?;
        let identity = NetworkIdentity {
            execution: execution.clone(),
            scope,
            ipv4,
            ipv6,
        };
        self.assignments.insert(
            execution,
            Assignment {
                identity: identity.clone(),
                offset,
                block,
            },
        );
        Ok(identity)
    }

    /// Returns `execution`'s addresses and port block to the pool.
    pub fn release(&mut self, execution: &ExecutionId) -> Option<NetworkIdentity> {
        self.assignments
            .remove(execution)
            .map(|assignment| assignment.identity)
    }

    /// The NAT port block of `execution`: its first port and its size.
    pub fn port_block(&self, execution: &ExecutionId) -> Option<(u16, u16)> {
        let assignment = self.assignments.get(execution)?;
        let nat = self.config.nat;
        let offset = u32::from(assignment.block).checked_mul(u32::from(nat.ports_per_sandbox))?;
        let first = u32::from(nat.first_port).checked_add(offset)?;
        Some((u16::try_from(first).ok()?, nat.ports_per_sandbox))
    }

    /// The NAT egress address of `address`'s family.
    pub fn egress_for(&self, address: IpAddr) -> Option<IpAddr> {
        match address {
            IpAddr::V4(_) => Some(IpAddr::V4(self.config.nat.egress_ipv4)),
            IpAddr::V6(_) => self.config.nat.egress_ipv6.map(IpAddr::V6),
        }
    }
}
