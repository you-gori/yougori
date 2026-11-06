//! Destination grants and authorization before any resolution (VM §4.2; VM-W03).
//!
//! Exact names are the default. A wildcard needs verified ownership of its zone, a
//! purpose, and matches exactly one label below the zone; a built-in list of shared
//! hosting suffixes is an extra refusal, never a substitute for ownership (line 1944). A
//! private registry or internal database is reached only through an exact endpoint grant
//! whose enforcement context permits that one destination (line 1958). A sensitive
//! offline task never resolves names: it uses exact endpoints or approved catalog objects
//! (line 1956).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use super::address::{
    classify, AddressRefused, AddressRule, HostAddressGeneration, HostAddressState,
};
use super::budget::RouteBudgets;
use super::mode::{ModeRefusal, NetworkMode, RouteClass};
use super::name::{Authority, CanonicalName, DestinationHost, DestinationPort, NameError};
use super::perimeter::{EnforcementContext, PerimeterError};
use super::resolver::ResolverId;
use super::route::{route_name, RouteKind};
use crate::foundation::ids::{ContentKey, Digest, MonotonicTime, PolicyEpoch, TenantId};

route_name!(
    /// The identity of one route grant; budgets are kept per route id.
    RouteId
);

route_name!(
    /// Why a wildcard grant exists, such as `customer-preview-hosts`.
    GrantPurpose
);

/// The protocol a route carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RouteProtocol {
    /// HTTP over TLS.
    Https,
    /// Any TLS stream (transport routes only).
    Tls,
}

/// Verified ownership of a DNS zone, which a wildcard needs (line 1944).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZoneOwnership {
    pub owner: TenantId,
    pub zone: CanonicalName,
    /// Digest of the verification record, such as a DNS TXT challenge result.
    pub evidence: Digest,
    pub valid_until: MonotonicTime,
}

/// Zones too broad for a wildcard whatever ownership is claimed. The list is an extra
/// refusal and is never treated as complete protection (line 1944): every wildcard also
/// needs verified ownership.
pub const SHARED_SUFFIXES: &[&str] = &[
    "com",
    "net",
    "org",
    "io",
    "dev",
    "app",
    "ai",
    "co",
    "co.uk",
    "github.io",
    "githubusercontent.com",
    "gitlab.io",
    "herokuapp.com",
    "cloudfront.net",
    "azurewebsites.net",
    "appspot.com",
    "vercel.app",
    "netlify.app",
    "pages.dev",
    "workers.dev",
    "web.app",
    "firebaseapp.com",
    "amazonaws.com",
    "s3.amazonaws.com",
    "blob.core.windows.net",
    "ngrok.io",
    "ngrok-free.app",
    "trycloudflare.com",
    "onrender.com",
    "fly.dev",
    "r2.dev",
    "glitch.me",
    "repl.co",
];

/// A wildcard grant: one label below an owned zone, for a stated purpose.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WildcardGrant {
    zone: CanonicalName,
    ownership: ZoneOwnership,
    purpose: GrantPurpose,
}

impl WildcardGrant {
    /// Refuses a zone without matching ownership, a shared or special-use zone, and a
    /// zone of fewer than two labels.
    pub fn new(
        zone: CanonicalName,
        ownership: ZoneOwnership,
        purpose: GrantPurpose,
    ) -> Result<Self, PolicyError> {
        if ownership.zone != zone {
            return Err(PolicyError::OwnershipZoneMismatch { zone });
        }
        if SHARED_SUFFIXES.contains(&zone.as_str()) {
            return Err(PolicyError::SharedSuffix { zone });
        }
        if let Some(suffix) = zone.special_use_suffix() {
            return Err(PolicyError::SpecialUseName { name: zone, suffix });
        }
        Ok(Self {
            zone,
            ownership,
            purpose,
        })
    }

    pub fn zone(&self) -> &CanonicalName {
        &self.zone
    }

    pub fn ownership(&self) -> &ZoneOwnership {
        &self.ownership
    }

    pub fn purpose(&self) -> &GrantPurpose {
        &self.purpose
    }
}

/// An exact endpoint: one address, optionally the name TLS and HTTP use for it, and an
/// enforcement context permitting only it (line 1958). No resolution happens for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointGrant {
    name: Option<CanonicalName>,
    address: IpAddr,
    context: EnforcementContext,
}

impl EndpointGrant {
    /// Refuses an address class no endpoint grant may permit and a context that permits
    /// more than `address:port` or pairs a broad block with an exception.
    pub fn new(
        name: Option<CanonicalName>,
        address: IpAddr,
        port: DestinationPort,
        context: EnforcementContext,
    ) -> Result<Self, PolicyError> {
        let static_view = HostAddressState::new(HostAddressGeneration::FIRST, []);
        AddressRule::ExactEndpoint
            .check(classify(address, &static_view))
            .map_err(PolicyError::EndpointAddress)?;
        context
            .check_dedicated(address, port)
            .map_err(PolicyError::Perimeter)?;
        Ok(Self {
            name,
            address,
            context,
        })
    }

    pub fn name(&self) -> Option<&CanonicalName> {
        self.name.as_ref()
    }

    pub const fn address(&self) -> IpAddr {
        self.address
    }

    pub fn context(&self) -> &EnforcementContext {
        &self.context
    }
}

/// What a route grant names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GrantTarget {
    ExactName(CanonicalName),
    Wildcard(WildcardGrant),
    Endpoint(EndpointGrant),
}

impl GrantTarget {
    const fn needs_resolution(&self) -> bool {
        !matches!(self, Self::Endpoint(_))
    }
}

/// One route grant (VM-W03: typed routes with resource scope, TLS mode and budgets).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteGrant {
    pub id: RouteId,
    pub protocol: RouteProtocol,
    pub target: GrantTarget,
    pub port: DestinationPort,
    pub route: RouteKind,
    /// Whether AAAA queries and IPv6 connections are granted.
    pub ipv6: bool,
    /// The resolver for name grants; `None` for endpoint grants.
    pub resolver: Option<ResolverId>,
    pub budgets: RouteBudgets,
}

impl RouteGrant {
    /// The route class this grant asks of the network mode.
    pub fn class(&self) -> RouteClass {
        match self.route {
            RouteKind::Operation(_) => RouteClass::Operation,
            RouteKind::Transport(_) => RouteClass::Transport,
        }
    }
}

/// How sensitive the task's data is (line 1956).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TaskDataClass {
    Ordinary,
    /// A private-data task: no name resolution at all, only exact endpoints and approved
    /// catalog objects, since DNS queries themselves carry information.
    SensitiveOffline,
}

/// Why a policy was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyError {
    DuplicateRouteId {
        route: RouteId,
    },
    /// Two grants could match one destination, so authorization would be ambiguous.
    OverlappingGrants {
        first: RouteId,
        second: RouteId,
    },
    Mode {
        route: RouteId,
        refusal: ModeRefusal,
    },
    /// A sensitive offline task may not hold a grant that resolves names.
    ResolutionInSensitiveTask {
        route: RouteId,
    },
    OwnershipZoneMismatch {
        zone: CanonicalName,
    },
    OwnerNotTenant {
        zone: CanonicalName,
    },
    OwnershipExpired {
        zone: CanonicalName,
    },
    SharedSuffix {
        zone: CanonicalName,
    },
    /// A special-use or private suffix cannot be a resolution grant; use an endpoint.
    SpecialUseName {
        name: CanonicalName,
        suffix: &'static str,
    },
    MissingResolver {
        route: RouteId,
    },
    ResolverNotAllowed {
        route: RouteId,
        resolver: ResolverId,
    },
    /// An endpoint grant names a resolver, but endpoints are never resolved.
    EndpointWithResolver {
        route: RouteId,
    },
    EndpointAddress(AddressRefused),
    Perimeter(PerimeterError),
    /// Operation routes carry HTTPS only.
    OperationRouteNeedsHttps {
        route: RouteId,
    },
    /// An IPv6 grant on an endpoint of the other family, or IPv6 refused for an IPv6
    /// endpoint.
    EndpointFamilyMismatch {
        route: RouteId,
    },
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateRouteId { route } => write!(f, "route {route} is declared twice"),
            Self::OverlappingGrants { first, second } => {
                write!(
                    f,
                    "routes {first} and {second} can match the same destination"
                )
            }
            Self::Mode { route, refusal } => write!(f, "route {route}: {refusal}"),
            Self::ResolutionInSensitiveTask { route } => write!(
                f,
                "route {route} resolves names, but this sensitive task may use only exact \
                 endpoints or approved objects"
            ),
            Self::OwnershipZoneMismatch { zone } => {
                write!(f, "the ownership record is not for the zone {zone}")
            }
            Self::OwnerNotTenant { zone } => {
                write!(f, "the zone {zone} is not owned by this tenant")
            }
            Self::OwnershipExpired { zone } => {
                write!(f, "ownership of the zone {zone} is no longer verified")
            }
            Self::SharedSuffix { zone } => write!(
                f,
                "{zone} is a shared suffix; a wildcard under it would admit other parties' names"
            ),
            Self::SpecialUseName { name, suffix } => write!(
                f,
                "{name} is under the special-use suffix {suffix}; grant an exact endpoint instead"
            ),
            Self::MissingResolver { route } => {
                write!(f, "route {route} resolves names but names no resolver")
            }
            Self::ResolverNotAllowed { route, resolver } => {
                write!(
                    f,
                    "route {route} uses resolver {resolver}, which is not allowed"
                )
            }
            Self::EndpointWithResolver { route } => {
                write!(
                    f,
                    "route {route} is an exact endpoint and is never resolved"
                )
            }
            Self::EndpointAddress(refused) => fmt::Display::fmt(refused, f),
            Self::Perimeter(error) => fmt::Display::fmt(error, f),
            Self::OperationRouteNeedsHttps { route } => {
                write!(f, "operation route {route} must carry HTTPS")
            }
            Self::EndpointFamilyMismatch { route } => write!(
                f,
                "route {route}: the IPv6 grant does not match the endpoint's address family"
            ),
        }
    }
}

impl std::error::Error for PolicyError {}

/// A destination as requested: protocol plus the authority under the one parser.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DestinationRequest {
    pub protocol: RouteProtocol,
    pub authority: Authority,
}

impl DestinationRequest {
    /// Parses `text` with [`Authority::parse`], defaulting to port 443.
    pub fn parse(protocol: RouteProtocol, text: &str) -> Result<Self, NameError> {
        Ok(Self {
            protocol,
            authority: Authority::parse(text, DestinationPort::HTTPS)?,
        })
    }
}

/// How an authorized destination is reached.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Reach {
    /// Resolve the name through this resolver; AAAA only if `ipv6`.
    Resolve { resolver: ResolverId, ipv6: bool },
    /// Connect to exactly this address; nothing is resolved.
    Endpoint { address: IpAddr },
}

/// A destination authorized before any resolution (VM §4.2).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AuthorizedDestination {
    route: RouteId,
    authority: Authority,
    epoch: PolicyEpoch,
    reach: Reach,
}

impl AuthorizedDestination {
    pub fn route(&self) -> &RouteId {
        &self.route
    }

    pub fn authority(&self) -> &Authority {
        &self.authority
    }

    /// The name TLS must verify: the requested name, or the endpoint grant's name.
    pub fn tls_name<'a>(&'a self, policy: &'a DestinationPolicy) -> Option<&'a CanonicalName> {
        match &self.authority.host {
            DestinationHost::Name(name) => Some(name),
            DestinationHost::Address(_) => policy.grant(&self.route).and_then(|grant| match &grant
                .target
            {
                GrantTarget::Endpoint(endpoint) => endpoint.name(),
                _ => None,
            }),
        }
    }

    pub const fn epoch(&self) -> PolicyEpoch {
        self.epoch
    }

    pub fn reach(&self) -> &Reach {
        &self.reach
    }
}

/// Why a destination was not authorized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorizationRefusal {
    /// Offline mode exposes no destination.
    Offline,
    /// No grant names this destination.
    NotGranted { authority: Authority },
    /// The name is more than one label below a wildcard zone.
    WildcardTooDeep {
        name: CanonicalName,
        zone: CanonicalName,
    },
    /// The wildcard's zone ownership is no longer verified.
    OwnershipExpired { zone: CanonicalName },
    /// The grant exists for another port.
    PortNotGranted { authority: Authority },
    /// The grant exists for another protocol.
    ProtocolNotGranted { authority: Authority },
    /// An address needs an exact endpoint grant for that address.
    AddressNeedsEndpointGrant { address: IpAddr },
    /// A sensitive offline task may not resolve names.
    ResolutionForbidden { name: CanonicalName },
    /// The object is not in the approved catalog.
    ObjectNotApproved { key: ContentKey },
}

impl fmt::Display for AuthorizationRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Offline => f.write_str("offline mode exposes no destination"),
            Self::NotGranted { authority } => write!(f, "no route grants {authority}"),
            Self::WildcardTooDeep { name, zone } => write!(
                f,
                "{name} is more than one label below the wildcard zone {zone}"
            ),
            Self::OwnershipExpired { zone } => {
                write!(f, "ownership of the zone {zone} is no longer verified")
            }
            Self::PortNotGranted { authority } => {
                write!(f, "{authority}: that port is not granted")
            }
            Self::ProtocolNotGranted { authority } => {
                write!(f, "{authority}: that protocol is not granted")
            }
            Self::AddressNeedsEndpointGrant { address } => {
                write!(f, "{address} needs an exact endpoint grant")
            }
            Self::ResolutionForbidden { name } => write!(
                f,
                "this sensitive task may not resolve {name}; use an exact endpoint or an \
                 approved object"
            ),
            Self::ObjectNotApproved { key } => write!(f, "object {key} is not approved"),
        }
    }
}

impl std::error::Error for AuthorizationRefusal {}

/// The destination policy of one sandbox under one policy epoch (VM §4.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DestinationPolicy {
    tenant: TenantId,
    epoch: PolicyEpoch,
    mode: NetworkMode,
    data_class: TaskDataClass,
    grants: BTreeMap<RouteId, RouteGrant>,
    allowed_resolvers: BTreeSet<ResolverId>,
    approved_objects: BTreeSet<ContentKey>,
    max_answer_ttl: Duration,
}

/// The parts of a [`DestinationPolicy`], checked by [`DestinationPolicy::new`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyParts {
    pub tenant: TenantId,
    pub epoch: PolicyEpoch,
    pub mode: NetworkMode,
    pub data_class: TaskDataClass,
    pub grants: Vec<RouteGrant>,
    pub allowed_resolvers: BTreeSet<ResolverId>,
    /// The immutable catalog of approved object identities (line 1956).
    pub approved_objects: BTreeSet<ContentKey>,
    /// The longest a resolved answer is trusted, whatever its TTL.
    pub max_answer_ttl: Duration,
}

impl DestinationPolicy {
    /// Checks every grant against the mode, the data class, ownership at `now`, the
    /// allowed resolvers and every other grant.
    pub fn new(parts: PolicyParts, now: MonotonicTime) -> Result<Self, PolicyError> {
        let mut parts = parts;
        let declared = std::mem::take(&mut parts.grants);
        let mut grants = BTreeMap::new();
        for grant in declared {
            check_grant(&grant, &parts, now)?;
            if let Some(other) = grants
                .values()
                .find(|other: &&RouteGrant| overlap(other, &grant))
            {
                return Err(PolicyError::OverlappingGrants {
                    first: other.id.clone(),
                    second: grant.id.clone(),
                });
            }
            if grants.contains_key(&grant.id) {
                return Err(PolicyError::DuplicateRouteId { route: grant.id });
            }
            grants.insert(grant.id.clone(), grant);
        }
        Ok(Self {
            tenant: parts.tenant,
            epoch: parts.epoch,
            mode: parts.mode,
            data_class: parts.data_class,
            grants,
            allowed_resolvers: parts.allowed_resolvers,
            approved_objects: parts.approved_objects,
            max_answer_ttl: parts.max_answer_ttl,
        })
    }

    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    pub const fn epoch(&self) -> PolicyEpoch {
        self.epoch
    }

    pub const fn mode(&self) -> NetworkMode {
        self.mode
    }

    pub const fn data_class(&self) -> TaskDataClass {
        self.data_class
    }

    pub const fn max_answer_ttl(&self) -> Duration {
        self.max_answer_ttl
    }

    pub fn grant(&self, route: &RouteId) -> Option<&RouteGrant> {
        self.grants.get(route)
    }

    pub fn grants(&self) -> impl Iterator<Item = &RouteGrant> {
        self.grants.values()
    }

    pub fn resolver_allowed(&self, resolver: &ResolverId) -> bool {
        self.allowed_resolvers.contains(resolver)
    }

    /// Authorizes a destination before any resolution: exact grants first, then
    /// wildcards one label below an owned zone, and addresses only through an exact
    /// endpoint grant for that address.
    pub fn authorize(
        &self,
        request: &DestinationRequest,
        now: MonotonicTime,
    ) -> Result<AuthorizedDestination, AuthorizationRefusal> {
        if self.mode == NetworkMode::Offline {
            return Err(AuthorizationRefusal::Offline);
        }
        let authority = &request.authority;
        let mut near_miss = None;
        for grant in self.grants.values() {
            let host_matches = match (&grant.target, &authority.host) {
                (GrantTarget::ExactName(name), DestinationHost::Name(requested)) => {
                    name == requested
                }
                (GrantTarget::Wildcard(wildcard), DestinationHost::Name(requested)) => {
                    if requested.is_one_label_below(wildcard.zone()) {
                        if wildcard.ownership().valid_until <= now {
                            return Err(AuthorizationRefusal::OwnershipExpired {
                                zone: wildcard.zone().clone(),
                            });
                        }
                        true
                    } else {
                        if requested.is_below(wildcard.zone()) {
                            near_miss = Some(AuthorizationRefusal::WildcardTooDeep {
                                name: requested.clone(),
                                zone: wildcard.zone().clone(),
                            });
                        }
                        false
                    }
                }
                (GrantTarget::Endpoint(endpoint), DestinationHost::Address(address)) => {
                    endpoint.address() == *address
                }
                (GrantTarget::Endpoint(endpoint), DestinationHost::Name(requested)) => {
                    endpoint.name() == Some(requested)
                }
                (_, DestinationHost::Address(_)) => false,
            };
            if !host_matches {
                continue;
            }
            if grant.port != authority.port {
                near_miss = Some(AuthorizationRefusal::PortNotGranted {
                    authority: authority.clone(),
                });
                continue;
            }
            if grant.protocol != request.protocol {
                near_miss = Some(AuthorizationRefusal::ProtocolNotGranted {
                    authority: authority.clone(),
                });
                continue;
            }
            let reach = match (&grant.target, &grant.resolver) {
                (GrantTarget::Endpoint(endpoint), _) => Reach::Endpoint {
                    address: endpoint.address(),
                },
                (_, Some(resolver)) => {
                    if self.data_class == TaskDataClass::SensitiveOffline {
                        if let DestinationHost::Name(name) = &authority.host {
                            return Err(AuthorizationRefusal::ResolutionForbidden {
                                name: name.clone(),
                            });
                        }
                    }
                    Reach::Resolve {
                        resolver: resolver.clone(),
                        ipv6: grant.ipv6,
                    }
                }
                (_, None) => continue,
            };
            return Ok(AuthorizedDestination {
                route: grant.id.clone(),
                authority: authority.clone(),
                epoch: self.epoch,
                reach,
            });
        }
        Err(match (&authority.host, near_miss) {
            (_, Some(refusal)) => refusal,
            (DestinationHost::Address(address), None) => {
                AuthorizationRefusal::AddressNeedsEndpointGrant { address: *address }
            }
            (DestinationHost::Name(_), None) => AuthorizationRefusal::NotGranted {
                authority: authority.clone(),
            },
        })
    }

    /// Authorizes an object from the immutable approved catalog (line 1956).
    pub fn authorize_object(&self, key: &ContentKey) -> Result<(), AuthorizationRefusal> {
        if self.approved_objects.contains(key) {
            Ok(())
        } else {
            Err(AuthorizationRefusal::ObjectNotApproved { key: *key })
        }
    }
}

fn check_grant(
    grant: &RouteGrant,
    parts: &PolicyParts,
    now: MonotonicTime,
) -> Result<(), PolicyError> {
    parts
        .mode
        .permits(grant.class())
        .map_err(|refusal| PolicyError::Mode {
            route: grant.id.clone(),
            refusal,
        })?;
    if matches!(grant.route, RouteKind::Operation(_)) && grant.protocol != RouteProtocol::Https {
        return Err(PolicyError::OperationRouteNeedsHttps {
            route: grant.id.clone(),
        });
    }
    if grant.target.needs_resolution() && parts.data_class == TaskDataClass::SensitiveOffline {
        return Err(PolicyError::ResolutionInSensitiveTask {
            route: grant.id.clone(),
        });
    }
    match &grant.target {
        GrantTarget::ExactName(name) => {
            if let Some(suffix) = name.special_use_suffix() {
                return Err(PolicyError::SpecialUseName {
                    name: name.clone(),
                    suffix,
                });
            }
        }
        GrantTarget::Wildcard(wildcard) => {
            if wildcard.ownership().owner != parts.tenant {
                return Err(PolicyError::OwnerNotTenant {
                    zone: wildcard.zone().clone(),
                });
            }
            if wildcard.ownership().valid_until <= now {
                return Err(PolicyError::OwnershipExpired {
                    zone: wildcard.zone().clone(),
                });
            }
        }
        GrantTarget::Endpoint(endpoint) => {
            if grant.resolver.is_some() {
                return Err(PolicyError::EndpointWithResolver {
                    route: grant.id.clone(),
                });
            }
            if grant.ipv6 != endpoint.address().is_ipv6() {
                return Err(PolicyError::EndpointFamilyMismatch {
                    route: grant.id.clone(),
                });
            }
            endpoint
                .context()
                .check_dedicated(endpoint.address(), grant.port)
                .map_err(PolicyError::Perimeter)?;
        }
    }
    if grant.target.needs_resolution() {
        match &grant.resolver {
            None => {
                return Err(PolicyError::MissingResolver {
                    route: grant.id.clone(),
                })
            }
            Some(resolver) if !parts.allowed_resolvers.contains(resolver) => {
                return Err(PolicyError::ResolverNotAllowed {
                    route: grant.id.clone(),
                    resolver: resolver.clone(),
                })
            }
            Some(_) => {}
        }
    }
    Ok(())
}

/// True when some destination could match both grants on the same port and protocol.
fn overlap(first: &RouteGrant, second: &RouteGrant) -> bool {
    if first.port != second.port || first.protocol != second.protocol {
        return false;
    }
    let name_of = |target: &GrantTarget| -> Option<CanonicalName> {
        match target {
            GrantTarget::ExactName(name) => Some(name.clone()),
            GrantTarget::Endpoint(endpoint) => endpoint.name().cloned(),
            GrantTarget::Wildcard(_) => None,
        }
    };
    match (&first.target, &second.target) {
        (GrantTarget::Wildcard(left), GrantTarget::Wildcard(right)) => left.zone() == right.zone(),
        (GrantTarget::Wildcard(wildcard), other) | (other, GrantTarget::Wildcard(wildcard)) => {
            name_of(other).is_some_and(|name| name.is_one_label_below(wildcard.zone()))
        }
        (GrantTarget::Endpoint(left), GrantTarget::Endpoint(right))
            if left.address() == right.address() =>
        {
            true
        }
        (left, right) => match (name_of(left), name_of(right)) {
            (Some(left), Some(right)) => left == right,
            _ => false,
        },
    }
}
