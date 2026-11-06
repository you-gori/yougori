//! The executor's resolvers (module docs in `mod.rs`): the host's own (`ToSocketAddrs`) and a
//! fixed one for tests and pinned deployments. Either is named by the policy's allowed
//! resolver id; the broker counts every query against the route's budget.

use std::net::{IpAddr, ToSocketAddrs};
use std::time::Duration;

use crate::sandbox_contract::destinations::{
    ResolutionQuery, Resolver, ResolverAnswer, ResolverFailure, ResolverId,
};

/// The TTL the host resolver's answers are trusted for; the policy caps it further.
pub const SYSTEM_ANSWER_TTL: Duration = Duration::from_secs(60);

/// The host's resolver, IPv4 answers only (the routes grant no IPv6).
#[derive(Clone, Debug)]
pub struct SystemResolver {
    id: ResolverId,
}

impl SystemResolver {
    pub fn new(id: ResolverId) -> Self {
        Self { id }
    }
}

impl Resolver for SystemResolver {
    fn id(&self) -> &ResolverId {
        &self.id
    }

    fn resolve(&self, query: &ResolutionQuery) -> Result<ResolverAnswer, ResolverFailure> {
        let name = query.name().clone();
        let addresses: Vec<IpAddr> = (name.as_str(), 0_u16)
            .to_socket_addrs()
            .map_err(|error| ResolverFailure::Failed {
                reason: error.to_string(),
            })?
            .map(|address| address.ip())
            .filter(IpAddr::is_ipv4)
            .collect();
        if addresses.is_empty() {
            return Err(ResolverFailure::NoData);
        }
        Ok(ResolverAnswer {
            name,
            aliases: Vec::new(),
            addresses,
            ttl: SYSTEM_ANSWER_TTL,
        })
    }
}

/// Fixed addresses for every name, for tests and pinned deployments; the TLS name check
/// still applies to what answers.
#[derive(Clone, Debug)]
pub struct FixedResolver {
    id: ResolverId,
    addresses: Vec<IpAddr>,
}

impl FixedResolver {
    pub fn new(id: ResolverId, addresses: Vec<IpAddr>) -> Self {
        Self { id, addresses }
    }
}

impl Resolver for FixedResolver {
    fn id(&self) -> &ResolverId {
        &self.id
    }

    fn resolve(&self, query: &ResolutionQuery) -> Result<ResolverAnswer, ResolverFailure> {
        if self.addresses.is_empty() {
            return Err(ResolverFailure::NoData);
        }
        Ok(ResolverAnswer {
            name: query.name().clone(),
            aliases: Vec::new(),
            addresses: self.addresses.clone(),
            ttl: SYSTEM_ANSWER_TTL,
        })
    }
}
