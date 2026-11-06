//! The network-authority facet of a profile (VM §1.3: explicit required and observed
//! properties, never a score).
//!
//! A [`NetworkAuthorityReport`] lists what the profile grants, entry by entry: the mode
//! and the broader authority it must report (VM §4.1), the mode claims it holds and the
//! ones it is refused, the V01 predicates it can never satisfy, and every route,
//! endpoint, resolver, publication, link and guest compatibility layer. There is no
//! level, tier or score, and two reports are not ordered against each other.

use crate::foundation::ids::{Digest, ExecutionId};
use crate::sandbox_contract::destinations::{
    classify, route_reference, AddressClass, Authority, DestinationHost, DestinationPort,
    HostAddressGeneration, HostAddressState, ModeClaim, NetworkMode, ResolverId, RouteId,
    ServiceIdentity,
};
use crate::sandbox_contract::policy::{DeploymentFacet, SecurityPredicate};

use super::document::{
    EgressTarget, ImplementationName, LinkDirection, NetworkProfile, PublicationAudience,
    PublicationAuthentication, RecordedText,
};

/// Every V02 mode claim, in declaration order.
const ALL_CLAIMS: [ModeClaim; 6] = [
    ModeClaim::NoHostFacingNic,
    ModeClaim::TypedOperationsOnly,
    ModeClaim::HostValidatesEveryOperation,
    ModeClaim::BypassFailsWithoutNic,
    ModeClaim::NoNetworkExposure,
    ModeClaim::ExplicitConnectionsOnly,
];

/// One granted authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorityEntry {
    /// A transport route to an exact name (VM §4.3: a transport property only).
    NamedTransportRoute {
        route: RouteId,
        reference: String,
        ipv6: bool,
        perimeter_prefixes: usize,
    },
    /// An exact endpoint; `private_exception` when its address is not public.
    ExactEndpoint {
        route: RouteId,
        reference: String,
        reason: RecordedText,
        private_exception: bool,
    },
    AllowedResolver {
        resolver: ResolverId,
    },
    Publication {
        service: ServiceIdentity,
        port: DestinationPort,
        public: bool,
        authentication: PublicationAuthentication,
    },
    SandboxLink {
        direction: LinkDirection,
        peer: ExecutionId,
        service: ServiceIdentity,
        port: DestinationPort,
    },
    /// A justified guest-side compatibility layer (VM-W08).
    GuestLayer {
        layer: &'static str,
        implementation: ImplementationName,
    },
}

/// The network-authority facet of one profile (VM §1.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkAuthorityReport {
    /// Always [`DeploymentFacet::NetworkAuthority`].
    pub facet: DeploymentFacet,
    pub profile: Digest,
    pub mode: NetworkMode,
    /// What a broader mode must report (VM §4.1, line 1934).
    pub broader_authority: Option<&'static str>,
    pub claims_held: Vec<ModeClaim>,
    pub claims_refused: Vec<ModeClaim>,
    /// V01 predicates this profile can never satisfy: `NoDirectGuestNetwork` always (a
    /// broader mode has a host-facing NIC), `ContractOffline` whenever it grants an
    /// egress route, a publication or a link.
    pub unsatisfiable_predicates: Vec<SecurityPredicate>,
    pub entries: Vec<AuthorityEntry>,
}

impl NetworkAuthorityReport {
    /// The report of `profile`.
    pub fn of(profile: &NetworkProfile) -> Self {
        let mode = profile.network_mode();
        let (claims_held, claims_refused) = ALL_CLAIMS
            .into_iter()
            .partition(|claim| profile.claim(*claim).is_ok());
        let document = profile.document();
        let mut unsatisfiable_predicates = Vec::new();
        if mode.has_host_facing_nic() {
            unsatisfiable_predicates.push(SecurityPredicate::NoDirectGuestNetwork);
        }
        if !(document.egress.is_empty() && document.ingress.is_empty() && document.links.is_empty())
        {
            unsatisfiable_predicates.push(SecurityPredicate::ContractOffline);
        }
        let static_view = HostAddressState::new(HostAddressGeneration::FIRST, []);
        let mut entries = Vec::new();
        for grant in &document.egress {
            let host = match &grant.target {
                EgressTarget::ExactName { name } => DestinationHost::Name(name.clone()),
                EgressTarget::Endpoint { address, .. } => DestinationHost::Address(*address),
            };
            let reference = route_reference(&Authority {
                host,
                port: grant.port,
            });
            entries.push(match &grant.target {
                EgressTarget::ExactName { .. } => AuthorityEntry::NamedTransportRoute {
                    route: grant.id.clone(),
                    reference,
                    ipv6: grant.ipv6,
                    perimeter_prefixes: grant.perimeter_prefixes.len(),
                },
                EgressTarget::Endpoint {
                    address, reason, ..
                } => AuthorityEntry::ExactEndpoint {
                    route: grant.id.clone(),
                    reference,
                    reason: reason.clone(),
                    private_exception: classify(*address, &static_view).class
                        != AddressClass::Public,
                },
            });
        }
        entries.extend(
            document
                .resolvers
                .iter()
                .map(|resolver| AuthorityEntry::AllowedResolver {
                    resolver: resolver.id.clone(),
                }),
        );
        entries.extend(
            document
                .ingress
                .iter()
                .map(|entry| AuthorityEntry::Publication {
                    service: entry.service.clone(),
                    port: entry.port,
                    public: entry.audience == PublicationAudience::Public,
                    authentication: entry.authentication,
                }),
        );
        entries.extend(
            document
                .links
                .iter()
                .map(|link| AuthorityEntry::SandboxLink {
                    direction: link.direction,
                    peer: link.peer.execution.clone(),
                    service: link.service.clone(),
                    port: link.port,
                }),
        );
        for (layer, justification) in [
            ("guest TUN stack", &document.guest.tun),
            ("synthetic names", &document.guest.synthetic_names),
        ] {
            if let Some(justification) = justification {
                entries.push(AuthorityEntry::GuestLayer {
                    layer,
                    implementation: justification.implementation.clone(),
                });
            }
        }
        Self {
            facet: DeploymentFacet::NetworkAuthority,
            profile: profile.digest(),
            mode,
            broader_authority: mode.broader_authority(),
            claims_held,
            claims_refused,
            unsatisfiable_predicates,
            entries,
        }
    }

    /// The report as plain lines, in a fixed order.
    pub fn lines(&self) -> Vec<String> {
        let mut lines = vec![format!("{}: {}", self.facet, self.mode.label())];
        if let Some(authority) = self.broader_authority {
            lines.push(format!("broader authority: {authority}"));
        }
        lines.extend(
            self.claims_held
                .iter()
                .map(|claim| format!("claim held: {claim:?}")),
        );
        lines.extend(
            self.claims_refused
                .iter()
                .map(|claim| format!("claim refused: {claim:?}")),
        );
        lines.extend(
            self.unsatisfiable_predicates
                .iter()
                .map(|predicate| format!("never satisfied: {predicate:?}")),
        );
        for entry in &self.entries {
            lines.push(match entry {
                AuthorityEntry::NamedTransportRoute {
                    route,
                    reference,
                    ipv6,
                    perimeter_prefixes,
                } => format!(
                    "transport route {route}: {reference}{}; {perimeter_prefixes} perimeter \
                     prefixes",
                    if *ipv6 { ", IPv6 too" } else { "" }
                ),
                AuthorityEntry::ExactEndpoint {
                    route,
                    reference,
                    reason,
                    private_exception,
                } => format!(
                    "{} {route}: {reference}; reason: {reason}",
                    if *private_exception {
                        "private exception"
                    } else {
                        "exact endpoint"
                    }
                ),
                AuthorityEntry::AllowedResolver { resolver } => {
                    format!("allowed resolver: {resolver}")
                }
                AuthorityEntry::Publication {
                    service,
                    port,
                    public,
                    authentication,
                } => format!(
                    "publication {service} on port {port}: {}, {authentication:?}",
                    if *public { "public" } else { "private" }
                ),
                AuthorityEntry::SandboxLink {
                    direction,
                    peer,
                    service,
                    port,
                } => format!("sandbox link {direction:?} with {peer}: {service} on port {port}"),
                AuthorityEntry::GuestLayer {
                    layer,
                    implementation,
                } => format!("{layer}: {implementation}"),
            });
        }
        lines
    }
}
