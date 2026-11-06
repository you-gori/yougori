//! The broader VM network profile document (VM-W59; VM §4.1, §4.2, §4.7).
//!
//! A [`NetworkProfile`] is the whole network authority of one broader-network VM: its
//! network identity, egress grants by exact name or exact endpoint, allowed resolvers,
//! publications, sandbox-to-sandbox links, flow quotas, release budgets and the guest
//! compatibility it is offered. The document is untrusted input with a pinned version and
//! closed fields. Reading sorts every list and refuses duplicates, so one authority has
//! one digest; the digest is the profile's identity and is what a user-owned general VM's
//! `perimeter_profile` names.
//!
//! The profile composes V02 decisions rather than repeating them: names, ports and
//! addresses are parsed and classified by `destinations`, grants are checked by
//! [`DestinationPolicy::new`], publications by [`IngressTable::publish`], links by
//! [`SandboxConnections`] and release budgets by [`ReleaseAccount::new`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::{NonZeroU32, NonZeroU64};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::foundation::coordination::PerimeterId;
use crate::foundation::ids::{
    digest, Digest, DigestBuilder, ExecutionId, MonotonicTime, PolicyEpoch, TenantId, TrustScope,
};
use crate::foundation::text::is_hazardous;
use crate::foundation::transfer::GeneralReleaseBudget;
use crate::sandbox_contract::destinations::route::route_name;
use crate::sandbox_contract::destinations::{
    classify, AddressClass, Audience, AuthenticationMode, CanonicalName, ChannelPolicy,
    ConnectionGrant, ConnectionRefusal, DestinationPolicy, DestinationPort, EndpointGrant,
    EnforcementContext, GrantTarget, HazardHandling, HostAddressGeneration, HostAddressState,
    InFlightAllowance, IngressError, IngressTable, IpPrefix, ModeClaim, ModeRefusal, NetworkMode,
    PassThroughHazard, PolicyError, PolicyParts, PrincipalId, PublicationRequest, ReleaseAccount,
    ReleaseChannel, ReleaseError, ResolverId, RouteBudgets, RouteError, RouteGrant, RouteId,
    RouteKind, RouteProtocol, SandboxConnections, SandboxEndpoint, ServiceIdentity, TaskDataClass,
    TransportRoute, METADATA_IPV6,
};

/// The profile version this build reads (VM-W59).
pub const NETWORK_PROFILE_VERSION: u32 = 1;
/// Most egress grants one profile may hold; the document is bounded input.
pub const MAX_EGRESS_GRANTS: usize = 256;
/// Most allowed resolvers one profile may name.
pub const MAX_RESOLVERS: usize = 16;
/// Most upstream addresses one allowed resolver may have.
pub const MAX_RESOLVER_UPSTREAMS: usize = 8;
/// Most perimeter prefixes one name grant may pin.
pub const MAX_PERIMETER_PREFIXES: usize = 16;
/// Most publications one profile may declare.
pub const MAX_PUBLICATIONS: usize = 64;
/// Most sandbox links one profile may declare.
pub const MAX_LINKS: usize = 64;
/// The shortest IPv4 perimeter prefix a name grant may pin: a /24 holds at most 256
/// addresses, each of which is classified.
pub const MIN_IPV4_PERIMETER_PREFIX_LENGTH: u8 = 24;
/// The shortest IPv6 perimeter prefix a name grant may pin. Every IPv6 special-purpose
/// range inside `2000::/3` is a /48 or wider, so a /48-or-longer prefix whose first and
/// last addresses are public is public throughout.
pub const MIN_IPV6_PERIMETER_PREFIX_LENGTH: u8 = 48;

/// The digest domain of [`NetworkProfile::digest`].
const DIGEST_DOMAIN: &str = "yougori/sandbox/network-profile/v1";

/// Names the scratch perimeter the dedicated endpoint contexts are built under while a
/// document is checked. The perimeter only says where a context lives; it never changes
/// whether a grant is valid.
const VALIDATION_PERIMETER_DOMAIN: &str = "yougori/sandbox/network-profile/validation-perimeter/v1";

/// The pinned profile version. Any other version is refused, never reinterpreted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct ProfileVersion(u32);

impl ProfileVersion {
    /// The version this build reads.
    pub const CURRENT: Self = Self(NETWORK_PROFILE_VERSION);

    /// The version number.
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for ProfileVersion {
    type Error = String;

    fn try_from(found: u32) -> Result<Self, Self::Error> {
        if found == NETWORK_PROFILE_VERSION {
            Ok(Self(found))
        } else {
            Err(format!(
                "network profile version {found} is not supported; this build reads only \
                 version {NETWORK_PROFILE_VERSION}"
            ))
        }
    }
}

impl From<ProfileVersion> for u32 {
    fn from(version: ProfileVersion) -> Self {
        version.0
    }
}

/// The two broader network modes a profile can describe (VM §4.1). Strict action mode
/// and offline mode have no broader profile, so neither can be named here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BroaderNetworkKind {
    /// A hardware VM with explicitly authorized connections and publications.
    DeclaredTransport,
    /// A user-owned general-purpose VM with a minimal NIC under this profile.
    UserOwnedGeneralVm,
}

/// How sensitive the task's data is (VM §4.2, line 1956).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    Ordinary,
    /// No name resolution at all; only exact endpoints (V02 refuses name grants).
    SensitiveOffline,
}

impl From<DataClass> for TaskDataClass {
    fn from(class: DataClass) -> Self {
        match class {
            DataClass::Ordinary => Self::Ordinary,
            DataClass::SensitiveOffline => Self::SensitiveOffline,
        }
    }
}

/// Why a recorded reason or justification was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TextError {
    Empty,
    TooLong {
        bytes: usize,
        max: usize,
    },
    /// Control characters could spoof an approval view (VM §4.7, line 2038).
    ControlCharacter {
        character: char,
    },
    /// Any other character `foundation::text` judges hazardous (bidirectional, zero-width
    /// and other invisible, private-use or unprintable) could reorder or hide text.
    FormatCharacter {
        character: char,
    },
}

impl fmt::Display for TextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("the text is empty"),
            Self::TooLong { bytes, max } => write!(f, "the text has {bytes} bytes; at most {max}"),
            Self::ControlCharacter { character } => {
                write!(f, "the text contains the control character {character:?}")
            }
            Self::FormatCharacter { character } => {
                write!(f, "the text contains the format character {character:?}")
            }
        }
    }
}

impl std::error::Error for TextError {}

/// A reason a person recorded for an exception or a justification (VM-W59 private
/// exceptions; VM-W08 justification gate). It is shown to people, so it is bounded and
/// carries no control or format characters.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RecordedText(String);

impl RecordedText {
    /// Longest accepted text, in bytes.
    pub const MAX_BYTES: usize = 512;

    /// Refuses empty, over-long and control- or format-character text.
    pub fn new(text: impl Into<String>) -> Result<Self, TextError> {
        let text = text.into();
        if text.trim().is_empty() {
            return Err(TextError::Empty);
        }
        if text.len() > Self::MAX_BYTES {
            return Err(TextError::TooLong {
                bytes: text.len(),
                max: Self::MAX_BYTES,
            });
        }
        if let Some(character) = text.chars().find(|character| character.is_control()) {
            return Err(TextError::ControlCharacter { character });
        }
        if let Some(character) = text.chars().find(|character| is_hazardous(*character)) {
            return Err(TextError::FormatCharacter { character });
        }
        Ok(Self(text))
    }

    /// The text as recorded.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for RecordedText {
    type Error = TextError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::new(text)
    }
}

impl From<RecordedText> for String {
    fn from(text: RecordedText) -> Self {
        text.0
    }
}

impl fmt::Display for RecordedText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The sandbox's network identity (VM-W59): its execution, trust scope and the guest
/// addresses the host assigned. A guest address is private (RFC 1918) or unique-local
/// space, never a host, loopback, metadata or other-sandbox address; the host checks the
/// assignment against its pool when it admits the profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkIdentity {
    pub execution: ExecutionId,
    pub scope: TrustScope,
    pub ipv4: Ipv4Addr,
    pub ipv6: Option<Ipv6Addr>,
}

impl NetworkIdentity {
    /// The V02 sandbox endpoint of this identity.
    pub fn endpoint(&self) -> SandboxEndpoint {
        SandboxEndpoint {
            execution: self.execution.clone(),
            scope: self.scope,
        }
    }

    /// The guest address of the family `address` belongs to.
    pub fn address_like(&self, address: IpAddr) -> Option<IpAddr> {
        match address {
            IpAddr::V4(_) => Some(IpAddr::V4(self.ipv4)),
            IpAddr::V6(_) => self.ipv6.map(IpAddr::V6),
        }
    }

    /// True when `address` is one of this identity's guest addresses.
    pub fn owns(&self, address: IpAddr) -> bool {
        self.address_like(address) == Some(address)
    }
}

/// One upstream address of an allowed resolver, which the perimeter permits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolverUpstream {
    pub address: IpAddr,
    pub port: DestinationPort,
}

/// A resolver the profile allows (VM §4.2 step 3), with the public upstream addresses the
/// host's resolver uses, so the perimeter can permit exactly those.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowedResolver {
    pub id: ResolverId,
    pub upstream: Vec<ResolverUpstream>,
}

/// The protocol an egress grant carries: V02 transport routes carry TLS streams.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressProtocol {
    Tls,
    Https,
}

impl From<EgressProtocol> for RouteProtocol {
    fn from(protocol: EgressProtocol) -> Self {
        match protocol {
            EgressProtocol::Tls => Self::Tls,
            EgressProtocol::Https => Self::Https,
        }
    }
}

strict_netprofile_enum! {
    /// What an egress grant names: an exact name, resolved through an allowed resolver,
    /// or an exact endpoint, never resolved (VM §4.2). A private, shared or other
    /// non-public destination is reachable only as an endpoint, and every endpoint
    /// records why it exists (VM-W59 private exceptions; line 1958). Wildcards are not
    /// part of the broader profile.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum EgressTarget tag "kind" {
        ExactName { name: CanonicalName },
        Endpoint {
            address: IpAddr,
            /// The name TLS and the guest's DNS use for the endpoint, if any.
            name: Option<CanonicalName>,
            reason: RecordedText,
        },
    }
}

impl EgressTarget {
    /// The name the target answers to, if any.
    pub fn name(&self) -> Option<&CanonicalName> {
        match self {
            Self::ExactName { name } => Some(name),
            Self::Endpoint { name, .. } => name.as_ref(),
        }
    }

    /// The endpoint address, for an endpoint target.
    pub fn endpoint_address(&self) -> Option<IpAddr> {
        match self {
            Self::ExactName { .. } => None,
            Self::Endpoint { address, .. } => Some(*address),
        }
    }
}

/// One egress grant (VM-W59; VM-W03): a V02 transport route by exact name or endpoint,
/// with its hazards declared, its budgets, and, for a name grant, the prefixes the
/// independent perimeter may permit for it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressGrant {
    pub id: RouteId,
    pub target: EgressTarget,
    pub port: DestinationPort,
    pub protocol: EgressProtocol,
    /// Whether AAAA answers and IPv6 flows are granted.
    pub ipv6: bool,
    /// The allowed resolver of a name grant; `None` for an endpoint.
    pub resolver: Option<ResolverId>,
    /// How each pass-through hazard is handled (V02 [`TransportRoute::new`]).
    pub hazards: BTreeMap<PassThroughHazard, HazardHandling>,
    pub budgets: RouteBudgets,
    /// Name grants only: the public prefixes resolved addresses must lie in. When set,
    /// the host refuses an answer outside them and the perimeter permits exactly them;
    /// when empty, the perimeter cannot express the grant and its claim fails.
    pub perimeter_prefixes: Vec<IpPrefix>,
}

/// How callers authenticate to a publication (V02 [`AuthenticationMode`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationAuthentication {
    None,
    PlatformSession,
    BearerToken,
    MutualTls,
}

impl From<PublicationAuthentication> for AuthenticationMode {
    fn from(mode: PublicationAuthentication) -> Self {
        match mode {
            PublicationAuthentication::None => Self::None,
            PublicationAuthentication::PlatformSession => Self::PlatformSession,
            PublicationAuthentication::BearerToken => Self::BearerToken,
            PublicationAuthentication::MutualTls => Self::MutualTls,
        }
    }
}

strict_netprofile_enum! {
    /// Who may reach a publication (VM §4.7; V02 [`Audience`]).
    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum PublicationAudience tag "kind" {
        Public,
        Private { principals: BTreeSet<PrincipalId> },
    }
}

impl From<&PublicationAudience> for Audience {
    fn from(audience: &PublicationAudience) -> Self {
        match audience {
            PublicationAudience::Public => Self::Public,
            PublicationAudience::Private { principals } => Self::Private {
                principals: principals.clone(),
            },
        }
    }
}

/// One publication (VM §4.7): service identity, port, audience, authentication and a
/// lifetime counted from when the host publishes it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationEntry {
    pub service: ServiceIdentity,
    pub port: DestinationPort,
    pub audience: PublicationAudience,
    pub authentication: PublicationAuthentication,
    pub lifetime_seconds: NonZeroU64,
}

/// Which end of a sandbox link this profile grants (VM §4.7: both ends must grant).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkDirection {
    /// This sandbox calls the peer.
    Outbound,
    /// The peer calls this sandbox.
    Inbound,
}

/// The other end of a sandbox link.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkPeer {
    pub execution: ExecutionId,
    pub scope: TrustScope,
}

impl LinkPeer {
    /// The V02 sandbox endpoint of the peer.
    pub fn endpoint(&self) -> SandboxEndpoint {
        SandboxEndpoint {
            execution: self.execution.clone(),
            scope: self.scope,
        }
    }
}

/// This profile's copy of one directed sandbox link (VM §4.7; V02 [`ConnectionGrant`]).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkEntry {
    pub direction: LinkDirection,
    pub peer: LinkPeer,
    pub service: ServiceIdentity,
    pub port: DestinationPort,
    pub lifetime_seconds: NonZeroU64,
}

/// Flow quotas (VM-W59 quotas): concurrent flows, and new flows within any window of
/// `interval_seconds`. Bytes are budgeted per route through V02 [`RouteBudgets`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowQuotas {
    pub max_concurrent_flows: NonZeroU32,
    pub max_new_flows_per_interval: NonZeroU32,
    pub interval_seconds: NonZeroU64,
}

/// The sandbox's release channels and in-flight allowance (VM §2.5; V02
/// [`ReleaseAccount`]). The VM-D12 general release budget is the host's, not the
/// profile's.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseBudgets {
    pub channels: BTreeMap<ReleaseChannel, ChannelPolicy>,
    pub in_flight_allowance: InFlightAllowance,
}

/// Which proxy listeners the guest is configured to use (VM §4.1, line 1938: standard
/// HTTP CONNECT or SOCKS first). The host runs both either way; this shapes only the
/// guest's configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyOffer {
    pub http_connect: bool,
    pub socks5: bool,
}

route_name!(
    /// An application that needs a compatibility layer, such as `legacy-updater`.
    ApplicationName
);

route_name!(
    /// The supported implementation a compatibility layer reuses (VM §4.1, line 1938).
    ImplementationName
);

/// The recorded justification for a guest TUN stack or synthetic names (VM-W08: only
/// when justified): why, which applications bypass the proxy, and which supported
/// implementation is reused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Justification {
    pub reason: RecordedText,
    pub applications: BTreeSet<ApplicationName>,
    pub implementation: ImplementationName,
}

/// Guest network compatibility (VM-W08): proxy first, optional guest-side layers only
/// with a justification. None of it changes a host decision (VM-P09).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestCompatibility {
    pub proxy: ProxyOffer,
    pub tun: Option<Justification>,
    pub synthetic_names: Option<Justification>,
}

/// The network profile document as written (VM-W59).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkProfileDocument {
    pub version: ProfileVersion,
    pub kind: BroaderNetworkKind,
    pub tenant: TenantId,
    pub data_class: DataClass,
    pub identity: NetworkIdentity,
    pub resolvers: Vec<AllowedResolver>,
    pub egress: Vec<EgressGrant>,
    pub ingress: Vec<PublicationEntry>,
    pub links: Vec<LinkEntry>,
    pub quotas: FlowQuotas,
    pub release: ReleaseBudgets,
    pub guest: GuestCompatibility,
    /// The longest a resolved answer is trusted, whatever its TTL.
    pub max_answer_ttl_seconds: NonZeroU64,
}

/// Why a profile document was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProfileError {
    /// A broader profile is for a VM sandbox; a labelled runtime never holds one.
    IdentityNotVmSandbox,
    /// A guest address must be private or unique-local space.
    GuestAddress {
        address: IpAddr,
        class: AddressClass,
    },
    TooMany {
        field: &'static str,
        count: usize,
        max: usize,
    },
    DuplicateResolver {
        resolver: ResolverId,
    },
    ResolverWithoutUpstream {
        resolver: ResolverId,
    },
    DuplicateUpstream {
        resolver: ResolverId,
    },
    /// Resolver upstreams must be public; the host resolver is never a private exception.
    UpstreamNotPublic {
        resolver: ResolverId,
        address: IpAddr,
        class: AddressClass,
    },
    /// An allowed resolver no grant uses would only widen the perimeter.
    UnusedResolver {
        resolver: ResolverId,
    },
    DuplicateRoute {
        route: RouteId,
    },
    /// One name may appear in one grant only, so a resolved address maps to one route.
    NameInSeveralGrants {
        name: CanonicalName,
    },
    EndpointWithPerimeterPrefixes {
        route: RouteId,
    },
    /// An endpoint grant may not name the sandbox's own address.
    EndpointIsOwnAddress {
        route: RouteId,
    },
    /// An IPv6 grant for a sandbox without an IPv6 address.
    Ipv6WithoutIdentity {
        route: RouteId,
    },
    DuplicatePerimeterPrefix {
        route: RouteId,
        prefix: IpPrefix,
    },
    PerimeterPrefixTooBroad {
        route: RouteId,
        prefix: IpPrefix,
        min_length: u8,
    },
    /// A perimeter prefix holds an address that is not public, such as a metadata
    /// endpoint or reserved space.
    PerimeterPrefixNotPublic {
        route: RouteId,
        prefix: IpPrefix,
        address: IpAddr,
        class: AddressClass,
    },
    /// An IPv6 prefix on a grant without IPv6.
    PerimeterPrefixFamily {
        route: RouteId,
        prefix: IpPrefix,
    },
    /// The grant pins prefixes and grants IPv6 but pins no IPv6 prefix.
    MissingIpv6PerimeterPrefix {
        route: RouteId,
    },
    DuplicatePublication {
        service: ServiceIdentity,
        port: DestinationPort,
    },
    DuplicateLink {
        service: ServiceIdentity,
        port: DestinationPort,
    },
    LinkToSelf,
    /// Proxy first (VM §4.1): the guest is offered at least one proxy listener.
    ProxyNotOffered,
    /// A justification must name the applications that need the layer.
    JustificationWithoutApplications,
    Policy(PolicyError),
    Route {
        route: RouteId,
        error: RouteError,
    },
    Ingress(IngressError),
    Connection(ConnectionRefusal),
    Release(ReleaseError),
    /// The canonical encoding could not be produced.
    Encoding(String),
}

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IdentityNotVmSandbox => {
                f.write_str("a broader network profile belongs to a VM sandbox")
            }
            Self::GuestAddress { address, class } => write!(
                f,
                "the guest address {address} is {class}; it must be private or unique-local"
            ),
            Self::TooMany { field, count, max } => {
                write!(f, "{field} has {count} entries; at most {max}")
            }
            Self::DuplicateResolver { resolver } => {
                write!(f, "resolver {resolver} is listed twice")
            }
            Self::ResolverWithoutUpstream { resolver } => {
                write!(f, "resolver {resolver} names no upstream address")
            }
            Self::DuplicateUpstream { resolver } => {
                write!(f, "resolver {resolver} lists an upstream twice")
            }
            Self::UpstreamNotPublic {
                resolver,
                address,
                class,
            } => write!(
                f,
                "resolver {resolver} upstream {address} is {class}; upstreams must be public"
            ),
            Self::UnusedResolver { resolver } => {
                write!(f, "resolver {resolver} is allowed but no grant uses it")
            }
            Self::DuplicateRoute { route } => write!(f, "route {route} is declared twice"),
            Self::NameInSeveralGrants { name } => {
                write!(f, "{name} appears in more than one egress grant")
            }
            Self::EndpointWithPerimeterPrefixes { route } => write!(
                f,
                "route {route} is an exact endpoint; perimeter prefixes are for name grants"
            ),
            Self::EndpointIsOwnAddress { route } => {
                write!(f, "route {route} names the sandbox's own address")
            }
            Self::Ipv6WithoutIdentity { route } => write!(
                f,
                "route {route} grants IPv6 but the sandbox has no IPv6 address"
            ),
            Self::DuplicatePerimeterPrefix { route, prefix } => {
                write!(f, "route {route} pins {prefix} twice")
            }
            Self::PerimeterPrefixTooBroad {
                route,
                prefix,
                min_length,
            } => write!(
                f,
                "route {route} pins {prefix}; perimeter prefixes must be /{min_length} or longer"
            ),
            Self::PerimeterPrefixNotPublic {
                route,
                prefix,
                address,
                class,
            } => write!(
                f,
                "route {route} pins {prefix}, which holds {address} ({class})"
            ),
            Self::PerimeterPrefixFamily { route, prefix } => write!(
                f,
                "route {route} pins the IPv6 prefix {prefix} but does not grant IPv6"
            ),
            Self::MissingIpv6PerimeterPrefix { route } => write!(
                f,
                "route {route} grants IPv6 and pins prefixes, but no IPv6 prefix"
            ),
            Self::DuplicatePublication { service, port } => {
                write!(f, "{service} on port {port} is published twice")
            }
            Self::DuplicateLink { service, port } => {
                write!(f, "the link for {service} on port {port} is declared twice")
            }
            Self::LinkToSelf => f.write_str("a sandbox link must name another sandbox"),
            Self::ProxyNotOffered => {
                f.write_str("proxy first: the guest must be offered a proxy listener")
            }
            Self::JustificationWithoutApplications => {
                f.write_str("a justification must name the applications that need it")
            }
            Self::Policy(error) => fmt::Display::fmt(error, f),
            Self::Route { route, error } => write!(f, "route {route}: {error}"),
            Self::Ingress(error) => fmt::Display::fmt(error, f),
            Self::Connection(error) => fmt::Display::fmt(error, f),
            Self::Release(error) => fmt::Display::fmt(error, f),
            Self::Encoding(reason) => write!(f, "the profile could not be encoded: {reason}"),
        }
    }
}

impl std::error::Error for ProfileError {}

/// Why reading a profile from JSON failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProfileReadError {
    /// Not a well-formed document: syntax, an unknown field or kind, an unsupported
    /// version or a field value its own type refuses.
    Syntax(String),
    Invalid(ProfileError),
}

impl fmt::Display for ProfileReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax(reason) => write!(f, "the network profile is malformed: {reason}"),
            Self::Invalid(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl std::error::Error for ProfileReadError {}

/// A network mode that is not this profile's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProfileModeError {
    pub expected: NetworkMode,
    pub found: NetworkMode,
}

impl fmt::Display for ProfileModeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "this profile runs as {}, not {}",
            self.expected.label(),
            self.found.label()
        )
    }
}

impl std::error::Error for ProfileModeError {}

/// A checked broader VM network profile (VM-W59). Its digest is its identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "NetworkProfileDocument", into = "NetworkProfileDocument")]
pub struct NetworkProfile {
    document: NetworkProfileDocument,
    digest: Digest,
}

impl TryFrom<NetworkProfileDocument> for NetworkProfile {
    type Error = ProfileError;

    fn try_from(document: NetworkProfileDocument) -> Result<Self, Self::Error> {
        Self::new(document)
    }
}

impl From<NetworkProfile> for NetworkProfileDocument {
    fn from(profile: NetworkProfile) -> Self {
        profile.document
    }
}

impl NetworkProfile {
    /// Normalizes and checks a document: list order is sorted, duplicates refused, every
    /// field checked here and every grant, publication, link and release budget checked
    /// by V02.
    pub fn new(document: NetworkProfileDocument) -> Result<Self, ProfileError> {
        let mut document = document;
        normalize_and_check(&mut document)?;
        let encoded = serde_json::to_vec(&document)
            .map_err(|error| ProfileError::Encoding(error.to_string()))?;
        let digest = DigestBuilder::new(DIGEST_DOMAIN).bytes(&encoded).finish();
        let profile = Self { document, digest };
        profile.check_with_destinations()?;
        Ok(profile)
    }

    /// Reads and checks a JSON document.
    pub fn from_json(text: &str) -> Result<Self, ProfileReadError> {
        let document: NetworkProfileDocument = serde_json::from_str(text)
            .map_err(|error| ProfileReadError::Syntax(error.to_string()))?;
        Self::new(document).map_err(ProfileReadError::Invalid)
    }

    /// The normalized document as JSON.
    pub fn to_json(&self) -> Result<String, ProfileError> {
        serde_json::to_string(&self.document)
            .map_err(|error| ProfileError::Encoding(error.to_string()))
    }

    /// The normalized document.
    pub fn document(&self) -> &NetworkProfileDocument {
        &self.document
    }

    /// The profile's identity: a domain-separated digest of its normalized document.
    pub const fn digest(&self) -> Digest {
        self.digest
    }

    /// The sandbox's network identity.
    pub fn identity(&self) -> &NetworkIdentity {
        &self.document.identity
    }

    /// The flow quotas.
    pub const fn quotas(&self) -> FlowQuotas {
        self.document.quotas
    }

    /// The egress grants, sorted by route id.
    pub fn egress(&self) -> &[EgressGrant] {
        &self.document.egress
    }

    /// The egress grant with this route id.
    pub fn grant(&self, route: &RouteId) -> Option<&EgressGrant> {
        self.document.egress.iter().find(|grant| grant.id == *route)
    }

    /// The grant whose target answers to `name`, if any.
    pub fn grant_for_name(&self, name: &CanonicalName) -> Option<&EgressGrant> {
        self.document
            .egress
            .iter()
            .find(|grant| grant.target.name() == Some(name))
    }

    /// The endpoint grant for exactly `address:port`, if any.
    pub fn endpoint_grant(&self, address: IpAddr, port: DestinationPort) -> Option<&EgressGrant> {
        self.document
            .egress
            .iter()
            .find(|grant| grant.target.endpoint_address() == Some(address) && grant.port == port)
    }

    /// The network mode this profile runs as (VM §4.1). A user-owned general VM names
    /// this profile's digest as its perimeter profile.
    pub fn network_mode(&self) -> NetworkMode {
        match self.document.kind {
            BroaderNetworkKind::DeclaredTransport => NetworkMode::DeclaredTransport,
            BroaderNetworkKind::UserOwnedGeneralVm => NetworkMode::UserOwnedGeneralVm {
                perimeter_profile: self.digest,
            },
        }
    }

    /// Refuses a mode other than exactly this profile's, including a user-owned general
    /// VM that names another profile.
    pub fn check_mode(&self, mode: NetworkMode) -> Result<(), ProfileModeError> {
        let expected = self.network_mode();
        if mode == expected {
            Ok(())
        } else {
            Err(ProfileModeError {
                expected,
                found: mode,
            })
        }
    }

    /// The V02 claim check: a broader profile never holds the strict mode's claims
    /// (VM §4.1, line 1936); a user-owned general VM holds none at all.
    pub fn claim(&self, claim: ModeClaim) -> Result<(), ModeRefusal> {
        self.network_mode().require_claim(claim)
    }

    /// The V02 route grants of this profile, with each endpoint's dedicated enforcement
    /// context on `perimeter` (line 1958).
    pub fn route_grants(&self, perimeter: PerimeterId) -> Result<Vec<RouteGrant>, ProfileError> {
        self.document
            .egress
            .iter()
            .map(|grant| route_grant(grant, perimeter))
            .collect()
    }

    /// The V02 destination policy of this profile under `epoch`.
    pub fn destination_policy(
        &self,
        perimeter: PerimeterId,
        epoch: PolicyEpoch,
        now: MonotonicTime,
    ) -> Result<DestinationPolicy, ProfileError> {
        DestinationPolicy::new(
            PolicyParts {
                tenant: self.document.tenant.clone(),
                epoch,
                mode: self.network_mode(),
                data_class: self.document.data_class.into(),
                grants: self.route_grants(perimeter)?,
                allowed_resolvers: self
                    .document
                    .resolvers
                    .iter()
                    .map(|resolver| resolver.id.clone())
                    .collect(),
                approved_objects: BTreeSet::new(),
                max_answer_ttl: Duration::from_secs(self.document.max_answer_ttl_seconds.get()),
            },
            now,
        )
        .map_err(ProfileError::Policy)
    }

    /// The V02 publication requests of this profile, published at `now`.
    pub fn publication_requests(&self, now: MonotonicTime) -> Vec<PublicationRequest> {
        self.document
            .ingress
            .iter()
            .map(|entry| PublicationRequest {
                service: entry.service.clone(),
                port: entry.port,
                audience: Audience::from(&entry.audience),
                authentication: entry.authentication.into(),
                expires_at: now.saturating_add(Duration::from_secs(entry.lifetime_seconds.get())),
            })
            .collect()
    }

    /// This profile's copies of its sandbox links as V02 grants issued at `now`.
    pub fn connection_grants(&self, now: MonotonicTime) -> Vec<(LinkDirection, ConnectionGrant)> {
        let own = self.document.identity.endpoint();
        self.document
            .links
            .iter()
            .map(|link| {
                let (caller, callee) = match link.direction {
                    LinkDirection::Outbound => (own.clone(), link.peer.endpoint()),
                    LinkDirection::Inbound => (link.peer.endpoint(), own.clone()),
                };
                (
                    link.direction,
                    ConnectionGrant {
                        caller,
                        callee,
                        service: link.service.clone(),
                        port: link.port,
                        expires_at: now
                            .saturating_add(Duration::from_secs(link.lifetime_seconds.get())),
                    },
                )
            })
            .collect()
    }

    /// The V02 release account of this profile, charging the host's `general` budget.
    pub fn release_account(
        &self,
        general: GeneralReleaseBudget,
    ) -> Result<ReleaseAccount, ProfileError> {
        ReleaseAccount::new(
            self.document.release.channels.clone(),
            general,
            self.document.release.in_flight_allowance.clone(),
        )
        .map_err(ProfileError::Release)
    }

    /// Runs the V02 checks: the destination policy, every publication on a scratch
    /// table, every link on a scratch connection set and the release account.
    fn check_with_destinations(&self) -> Result<(), ProfileError> {
        let perimeter = PerimeterId::new(digest(VALIDATION_PERIMETER_DOMAIN, &[]));
        let start = MonotonicTime::default();
        self.destination_policy(perimeter, PolicyEpoch::FIRST, start)?;
        let mode = self.network_mode();
        let mut table = IngressTable::new(
            self.document.identity.execution.clone(),
            mode,
            Duration::MAX,
        );
        for request in self.publication_requests(start) {
            table
                .publish(request, start)
                .map_err(ProfileError::Ingress)?;
        }
        let mut connections = SandboxConnections::new();
        for (direction, grant) in self.connection_grants(start) {
            match direction {
                LinkDirection::Outbound => connections.grant_outbound(mode, grant, start),
                LinkDirection::Inbound => connections.grant_inbound(mode, grant, start),
            }
            .map_err(ProfileError::Connection)?;
        }
        self.release_account(GeneralReleaseBudget::with_limit(0))?;
        Ok(())
    }
}

fn route_grant(grant: &EgressGrant, perimeter: PerimeterId) -> Result<RouteGrant, ProfileError> {
    let route =
        TransportRoute::new(grant.hazards.clone()).map_err(|error| ProfileError::Route {
            route: grant.id.clone(),
            error,
        })?;
    let target = match &grant.target {
        EgressTarget::ExactName { name } => GrantTarget::ExactName(name.clone()),
        EgressTarget::Endpoint { address, name, .. } => GrantTarget::Endpoint(
            EndpointGrant::new(
                name.clone(),
                *address,
                grant.port,
                EnforcementContext::dedicated(perimeter, *address, grant.port),
            )
            .map_err(ProfileError::Policy)?,
        ),
    };
    Ok(RouteGrant {
        id: grant.id.clone(),
        protocol: grant.protocol.into(),
        target,
        port: grant.port,
        route: RouteKind::Transport(route),
        ipv6: grant.ipv6,
        resolver: grant.resolver.clone(),
        budgets: grant.budgets,
    })
}

fn static_view() -> HostAddressState {
    HostAddressState::new(HostAddressGeneration::FIRST, [])
}

fn check_count(field: &'static str, count: usize, max: usize) -> Result<(), ProfileError> {
    if count > max {
        Err(ProfileError::TooMany { field, count, max })
    } else {
        Ok(())
    }
}

fn check_guest_address(address: IpAddr) -> Result<(), ProfileError> {
    let class = classify(address, &static_view()).class;
    if class == AddressClass::Private {
        Ok(())
    } else {
        Err(ProfileError::GuestAddress { address, class })
    }
}

/// Checks one perimeter prefix of a name grant: long enough, of a granted family, and
/// public throughout.
fn check_perimeter_prefix(grant: &EgressGrant, prefix: IpPrefix) -> Result<(), ProfileError> {
    let route = || grant.id.clone();
    let not_public = |address: IpAddr| {
        let class = classify(address, &static_view()).class;
        if class == AddressClass::Public {
            Ok(())
        } else {
            Err(ProfileError::PerimeterPrefixNotPublic {
                route: route(),
                prefix,
                address,
                class,
            })
        }
    };
    match prefix.network() {
        IpAddr::V4(network) => {
            if prefix.length() < MIN_IPV4_PERIMETER_PREFIX_LENGTH {
                return Err(ProfileError::PerimeterPrefixTooBroad {
                    route: route(),
                    prefix,
                    min_length: MIN_IPV4_PERIMETER_PREFIX_LENGTH,
                });
            }
            let count = 1u32 << (32 - u32::from(prefix.length()));
            let base = u32::from(network);
            for offset in 0..count {
                if let Some(value) = base.checked_add(offset) {
                    not_public(IpAddr::V4(Ipv4Addr::from(value)))?;
                }
            }
        }
        IpAddr::V6(network) => {
            if !grant.ipv6 {
                return Err(ProfileError::PerimeterPrefixFamily {
                    route: route(),
                    prefix,
                });
            }
            if prefix.length() < MIN_IPV6_PERIMETER_PREFIX_LENGTH {
                return Err(ProfileError::PerimeterPrefixTooBroad {
                    route: route(),
                    prefix,
                    min_length: MIN_IPV6_PERIMETER_PREFIX_LENGTH,
                });
            }
            let host_bits = 128 - u32::from(prefix.length());
            let host_mask = if host_bits == 0 {
                0
            } else {
                u128::MAX >> (128 - host_bits)
            };
            let last = Ipv6Addr::from(u128::from(network) | host_mask);
            not_public(IpAddr::V6(network))?;
            not_public(IpAddr::V6(last))?;
            if let Some(metadata) = METADATA_IPV6
                .iter()
                .find(|metadata| prefix.contains(IpAddr::V6(**metadata)))
            {
                not_public(IpAddr::V6(*metadata))?;
            }
        }
    }
    Ok(())
}

fn normalize_and_check(document: &mut NetworkProfileDocument) -> Result<(), ProfileError> {
    let identity = document.identity.clone();
    if !identity.scope.category.is_vm_sandbox() {
        return Err(ProfileError::IdentityNotVmSandbox);
    }
    check_guest_address(IpAddr::V4(identity.ipv4))?;
    if let Some(ipv6) = identity.ipv6 {
        check_guest_address(IpAddr::V6(ipv6))?;
    }
    check_count("resolvers", document.resolvers.len(), MAX_RESOLVERS)?;
    check_count("egress", document.egress.len(), MAX_EGRESS_GRANTS)?;
    check_count("ingress", document.ingress.len(), MAX_PUBLICATIONS)?;
    check_count("links", document.links.len(), MAX_LINKS)?;

    document
        .resolvers
        .sort_by(|left, right| left.id.cmp(&right.id));
    if let Some(pair) = document
        .resolvers
        .windows(2)
        .find(|pair| pair[0].id == pair[1].id)
    {
        return Err(ProfileError::DuplicateResolver {
            resolver: pair[0].id.clone(),
        });
    }
    for resolver in &mut document.resolvers {
        check_count("upstream", resolver.upstream.len(), MAX_RESOLVER_UPSTREAMS)?;
        if resolver.upstream.is_empty() {
            return Err(ProfileError::ResolverWithoutUpstream {
                resolver: resolver.id.clone(),
            });
        }
        resolver.upstream.sort();
        if resolver.upstream.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ProfileError::DuplicateUpstream {
                resolver: resolver.id.clone(),
            });
        }
        for upstream in &resolver.upstream {
            let class = classify(upstream.address, &static_view()).class;
            if class != AddressClass::Public {
                return Err(ProfileError::UpstreamNotPublic {
                    resolver: resolver.id.clone(),
                    address: upstream.address,
                    class,
                });
            }
        }
    }

    document
        .egress
        .sort_by(|left, right| left.id.cmp(&right.id));
    if let Some(pair) = document
        .egress
        .windows(2)
        .find(|pair| pair[0].id == pair[1].id)
    {
        return Err(ProfileError::DuplicateRoute {
            route: pair[0].id.clone(),
        });
    }
    let mut names = BTreeSet::new();
    for grant in &mut document.egress {
        if let Some(name) = grant.target.name() {
            if !names.insert(name.clone()) {
                return Err(ProfileError::NameInSeveralGrants { name: name.clone() });
            }
        }
        if grant.ipv6 && identity.ipv6.is_none() {
            return Err(ProfileError::Ipv6WithoutIdentity {
                route: grant.id.clone(),
            });
        }
        check_count(
            "perimeter_prefixes",
            grant.perimeter_prefixes.len(),
            MAX_PERIMETER_PREFIXES,
        )?;
        grant.perimeter_prefixes.sort();
        if let Some(pair) = grant
            .perimeter_prefixes
            .windows(2)
            .find(|pair| pair[0] == pair[1])
        {
            return Err(ProfileError::DuplicatePerimeterPrefix {
                route: grant.id.clone(),
                prefix: pair[0],
            });
        }
        match &grant.target {
            EgressTarget::ExactName { .. } => {
                for prefix in &grant.perimeter_prefixes {
                    check_perimeter_prefix(grant, *prefix)?;
                }
                let pins_ipv6 = grant
                    .perimeter_prefixes
                    .iter()
                    .any(|prefix| prefix.network().is_ipv6());
                if grant.ipv6 && !grant.perimeter_prefixes.is_empty() && !pins_ipv6 {
                    return Err(ProfileError::MissingIpv6PerimeterPrefix {
                        route: grant.id.clone(),
                    });
                }
            }
            EgressTarget::Endpoint { address, .. } => {
                if !grant.perimeter_prefixes.is_empty() {
                    return Err(ProfileError::EndpointWithPerimeterPrefixes {
                        route: grant.id.clone(),
                    });
                }
                if identity.owns(*address) {
                    return Err(ProfileError::EndpointIsOwnAddress {
                        route: grant.id.clone(),
                    });
                }
            }
        }
    }
    let used: BTreeSet<&ResolverId> = document
        .egress
        .iter()
        .filter_map(|grant| grant.resolver.as_ref())
        .collect();
    if let Some(unused) = document
        .resolvers
        .iter()
        .find(|resolver| !used.contains(&resolver.id))
    {
        return Err(ProfileError::UnusedResolver {
            resolver: unused.id.clone(),
        });
    }

    document
        .ingress
        .sort_by(|left, right| (&left.service, left.port).cmp(&(&right.service, right.port)));
    if let Some(pair) = document
        .ingress
        .windows(2)
        .find(|pair| pair[0].service == pair[1].service && pair[0].port == pair[1].port)
    {
        return Err(ProfileError::DuplicatePublication {
            service: pair[0].service.clone(),
            port: pair[0].port,
        });
    }

    document.links.sort();
    if let Some(pair) = document.links.windows(2).find(|pair| {
        pair[0].direction == pair[1].direction
            && pair[0].peer == pair[1].peer
            && pair[0].service == pair[1].service
            && pair[0].port == pair[1].port
    }) {
        return Err(ProfileError::DuplicateLink {
            service: pair[0].service.clone(),
            port: pair[0].port,
        });
    }
    if document
        .links
        .iter()
        .any(|link| link.peer.execution == identity.execution)
    {
        return Err(ProfileError::LinkToSelf);
    }

    let guest = &document.guest;
    if !guest.proxy.http_connect && !guest.proxy.socks5 {
        return Err(ProfileError::ProxyNotOffered);
    }
    for justification in [&guest.tun, &guest.synthetic_names].into_iter().flatten() {
        if justification.applications.is_empty() {
            return Err(ProfileError::JustificationWithoutApplications);
        }
    }
    Ok(())
}
