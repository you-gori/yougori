//! Resolution through an explicitly allowed resolver (VM §4.2 step 3).
//!
//! The broker hands a resolver only a [`ResolutionQuery`] it built from an authorized
//! [`CanonicalName`], which always has at least two labels and is absolute, so no guest
//! search suffix can be appended. An answer for any other name, of the wrong family or
//! with an over-long alias chain is refused by the broker before its addresses are used.

use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize};

use super::mode::AddressFamily;
use super::name::CanonicalName;
use crate::foundation::ids::{validate_identifier, IdError};

/// Longest CNAME chain accepted in one answer (VM-P07: CNAME chains cannot widen
/// authority; a bounded chain keeps the answer reviewable).
pub const MAX_ALIAS_CHAIN: usize = 8;

/// The identity of a resolver the policy explicitly allows.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ResolverId(String);

impl ResolverId {
    /// Accepts the ids.rs identifier grammar.
    pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
        let value = value.into();
        validate_identifier(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ResolverId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ResolverId({})", self.0)
    }
}

impl fmt::Display for ResolverId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ResolverId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// One query the broker sends: an authorized absolute name and one family. Only the
/// broker constructs it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ResolutionQuery {
    name: CanonicalName,
    family: AddressFamily,
}

impl ResolutionQuery {
    pub(crate) fn new(name: CanonicalName, family: AddressFamily) -> Self {
        Self { name, family }
    }

    /// The exact absolute name to resolve; nothing may be appended to it.
    pub fn name(&self) -> &CanonicalName {
        &self.name
    }

    /// The family asked for: A for IPv4, AAAA for IPv6.
    pub const fn family(&self) -> AddressFamily {
        self.family
    }

    /// Bytes this query releases to the resolver (VM §2.5: DNS queries are a release
    /// channel; names count where they leave the trust domain): a 12-byte header, the
    /// question name in wire form and 4 bytes of type and class.
    pub fn released_bytes(&self) -> u64 {
        12 + self.name.wire_length_bytes() + 4
    }
}

/// A resolver's answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolverAnswer {
    /// The question name the answer is for.
    pub name: CanonicalName,
    /// The CNAME chain followed, in order.
    pub aliases: Vec<CanonicalName>,
    pub addresses: Vec<IpAddr>,
    /// The smallest TTL in the answer.
    pub ttl: Duration,
}

/// Why a resolver gave no answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolverFailure {
    NameDoesNotExist,
    NoData,
    Failed { reason: String },
}

impl fmt::Display for ResolverFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NameDoesNotExist => f.write_str("the name does not exist"),
            Self::NoData => f.write_str("the name has no address of that family"),
            Self::Failed { reason } => write!(f, "resolution failed: {reason}"),
        }
    }
}

/// A resolver the host runs. Implementations resolve exactly [`ResolutionQuery::name`]
/// for [`ResolutionQuery::family`] and never apply search suffixes. Tests use fakes; this
/// crate performs no lookup itself.
pub trait Resolver {
    /// The identity the policy allows or not.
    fn id(&self) -> &ResolverId;

    fn resolve(&self, query: &ResolutionQuery) -> Result<ResolverAnswer, ResolverFailure>;
}
