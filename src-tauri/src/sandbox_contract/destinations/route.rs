//! Typed routes and their TLS modes (VM §4.3; VM-W03; VM-W11).
//!
//! An operation route terminates TLS at the credential executor (or the executor builds
//! the provider request itself) and inspects typed HTTP operations. A transport route
//! passes TLS through and grants only a transport property: it never claims method,
//! path, authority or header enforcement (line 1964), and each pass-through hazard
//! (encrypted ClientHello, missing SNI, HTTP/3, in-tunnel protocol changes) is either
//! refused or exposed as an explicitly decided broader transport grant.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::name::{CanonicalName, NameError};
use crate::foundation::ids::Digest;
use crate::foundation::transfer::CredentialRef;

/// Where TLS ends on an operation route (VM §4.3, line 1962).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationTls {
    /// The guest's TLS terminates at the credential executor.
    TerminatedAtExecutor,
    /// The executor constructs the provider request directly; the guest sends a typed
    /// operation, not TLS.
    ConstructedByExecutor,
}

/// The HTTP methods an operation may use. Methods are case-sensitive tokens; CONNECT and
/// TRACE are never operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
    Options,
}

impl HttpMethod {
    /// Parses an exact uppercase method; anything else is `None`.
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "GET" => Self::Get,
            "HEAD" => Self::Head,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "PATCH" => Self::Patch,
            "DELETE" => Self::Delete,
            "OPTIONS" => Self::Options,
            _ => return None,
        })
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
            Self::Options => "OPTIONS",
        }
    }

    /// Methods whose requests carry no body here (RFC 9110 defines no body semantics).
    pub const fn forbids_body(self) -> bool {
        matches!(self, Self::Get | Self::Head | Self::Options)
    }
}

macro_rules! route_name {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Accepts the ids.rs identifier grammar.
            pub fn new(
                value: impl Into<String>,
            ) -> Result<Self, crate::foundation::ids::IdError> {
                let value = value.into();
                crate::foundation::ids::validate_identifier(&value)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self, D::Error> {
                Self::new(<String as serde::Deserialize>::deserialize(deserializer)?)
                    .map_err(serde::de::Error::custom)
            }
        }
    };
}
pub(crate) use route_name;

route_name!(
    /// The name of one typed operation on a route.
    OperationName
);

/// One segment of a path template.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PathSegment {
    /// A literal segment, compared after normalization.
    Literal(String),
    /// Exactly one non-empty segment.
    Parameter,
}

/// An operation's path: literal segments and single-segment `{parameters}`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PathTemplate {
    segments: Vec<PathSegment>,
}

impl PathTemplate {
    /// Parses `/a/{id}/b`. Segments are unreserved characters or `{name}`; empty, dot
    /// and encoded segments are refused.
    pub fn parse(text: &str) -> Result<Self, RouteError> {
        let invalid = || RouteError::InvalidPathTemplate {
            template: text.to_owned(),
        };
        let rest = text.strip_prefix('/').ok_or_else(invalid)?;
        if rest.is_empty() {
            return Ok(Self {
                segments: Vec::new(),
            });
        }
        let mut segments = Vec::new();
        for segment in rest.split('/') {
            if segment.starts_with('{') && segment.ends_with('}') && segment.len() > 2 {
                segments.push(PathSegment::Parameter);
            } else if !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
                })
            {
                segments.push(PathSegment::Literal(segment.to_owned()));
            } else {
                return Err(invalid());
            }
        }
        Ok(Self { segments })
    }

    pub fn segments(&self) -> &[PathSegment] {
        &self.segments
    }

    /// True when the normalized `segments` match.
    pub fn matches(&self, segments: &[String]) -> bool {
        self.segments.len() == segments.len()
            && self
                .segments
                .iter()
                .zip(segments)
                .all(|(template, actual)| match template {
                    PathSegment::Literal(literal) => literal == actual,
                    PathSegment::Parameter => !actual.is_empty(),
                })
    }

    /// True when some path matches both templates.
    fn overlaps(&self, other: &PathTemplate) -> bool {
        self.segments.len() == other.segments.len()
            && self
                .segments
                .iter()
                .zip(&other.segments)
                .all(|pair| match pair {
                    (PathSegment::Literal(left), PathSegment::Literal(right)) => left == right,
                    _ => true,
                })
    }
}

/// Whether an operation changes state outside the sandbox.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectClass {
    ReadOnly,
    /// Counts against the route's effect budget.
    External,
}

/// One typed operation an operation route permits (VM §4.3: bind operation, path and
/// query semantics).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationSpec {
    pub name: OperationName,
    pub method: HttpMethod,
    pub path: PathTemplate,
    /// The query keys the operation accepts; any other key is refused.
    pub query_keys: BTreeSet<String>,
    pub effect: EffectClass,
}

/// What an operation route does with a redirect (VM §4.3: disable or re-authorize).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedirectPolicy {
    /// Redirects are not followed.
    Disabled,
    /// A redirect target goes through full destination authorization, resolution and
    /// address validation again, and must stay on the same route.
    Reauthorize,
}

/// Why a route declaration was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteError {
    NoOperations,
    DuplicateOperation {
        name: OperationName,
    },
    /// Two operations could match one request, so binding would be ambiguous.
    AmbiguousOperations {
        first: OperationName,
        second: OperationName,
    },
    InvalidPathTemplate {
        template: String,
    },
    /// A client that pins certificates cannot have its TLS terminated; it is an
    /// individual integration project (line 1976).
    PinnedClientNeedsIntegration,
    /// A pass-through hazard has no declared handling.
    UndeclaredHazard {
        hazard: PassThroughHazard,
    },
    /// The hazard cannot be refused through pass-through TLS, because the broker cannot
    /// see it; only an explicit broader transport grant is truthful (line 1964).
    CannotEnforceThroughPassThrough {
        hazard: PassThroughHazard,
    },
}

impl fmt::Display for RouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoOperations => f.write_str("an operation route needs at least one operation"),
            Self::DuplicateOperation { name } => write!(f, "operation {name} is declared twice"),
            Self::AmbiguousOperations { first, second } => {
                write!(
                    f,
                    "operations {first} and {second} can match the same request"
                )
            }
            Self::InvalidPathTemplate { template } => {
                write!(f, "{template:?} is not a valid path template")
            }
            Self::PinnedClientNeedsIntegration => f.write_str(
                "this client pins certificates, so its TLS cannot be terminated; it needs its \
                 own integration",
            ),
            Self::UndeclaredHazard { hazard } => {
                write!(
                    f,
                    "the transport route does not say how it handles {hazard:?}"
                )
            }
            Self::CannotEnforceThroughPassThrough { hazard } => write!(
                f,
                "{hazard:?} cannot be refused through pass-through TLS; declare a broader \
                 transport grant or use an operation route"
            ),
        }
    }
}

impl std::error::Error for RouteError {}

/// A typed operation route (VM §4.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationRoute {
    tls: OperationTls,
    credential: Option<CredentialRef>,
    operations: Vec<OperationSpec>,
    redirects: RedirectPolicy,
}

impl OperationRoute {
    /// Declares an operation route, refusing no or ambiguous operations and a
    /// certificate-pinning client whose TLS would be terminated.
    pub fn new(
        tls: OperationTls,
        credential: Option<CredentialRef>,
        operations: Vec<OperationSpec>,
        redirects: RedirectPolicy,
        client_pins_certificates: bool,
    ) -> Result<Self, RouteError> {
        if operations.is_empty() {
            return Err(RouteError::NoOperations);
        }
        if client_pins_certificates && tls == OperationTls::TerminatedAtExecutor {
            return Err(RouteError::PinnedClientNeedsIntegration);
        }
        for (index, first) in operations.iter().enumerate() {
            for second in &operations[index + 1..] {
                if first.name == second.name {
                    return Err(RouteError::DuplicateOperation {
                        name: first.name.clone(),
                    });
                }
                if first.method == second.method && first.path.overlaps(&second.path) {
                    return Err(RouteError::AmbiguousOperations {
                        first: first.name.clone(),
                        second: second.name.clone(),
                    });
                }
            }
        }
        Ok(Self {
            tls,
            credential,
            operations,
            redirects,
        })
    }

    pub const fn tls(&self) -> OperationTls {
        self.tls
    }

    /// The credential the executor injects; the guest never holds it.
    pub const fn credential(&self) -> Option<CredentialRef> {
        self.credential
    }

    pub const fn is_credentialed(&self) -> bool {
        self.credential.is_some()
    }

    pub fn operations(&self) -> &[OperationSpec] {
        &self.operations
    }

    pub const fn redirects(&self) -> RedirectPolicy {
        self.redirects
    }
}

/// A pass-through TLS hazard that needs explicit handling (line 1964).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PassThroughHazard {
    /// Encrypted ClientHello hides the real server name behind an outer one.
    EncryptedClientHello,
    /// No SNI at all.
    MissingSni,
    /// HTTP/3 over QUIC (UDP).
    Http3,
    /// Upgrades, tunnels or other protocol changes inside the encrypted stream, which
    /// the broker cannot see.
    InTunnelProtocolChange,
}

impl PassThroughHazard {
    /// Every hazard a transport route must declare.
    pub const ALL: [Self; 4] = [
        Self::EncryptedClientHello,
        Self::MissingSni,
        Self::Http3,
        Self::InTunnelProtocolChange,
    ];
}

/// A reference to an explicit decision record that accepted a broader transport grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DecisionRef(Digest);

impl DecisionRef {
    /// The decision record a digest names.
    pub const fn new(digest: Digest) -> Self {
        Self(digest)
    }

    pub const fn digest(self) -> Digest {
        self.0
    }
}

/// How a transport route handles one hazard.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HazardHandling {
    /// Connections showing the hazard are refused.
    Refuse,
    /// Connections showing the hazard proceed under a broader transport grant that an
    /// explicit decision accepted; the guarantees it removes are not claimed.
    BroaderTransportGrant(DecisionRef),
}

/// A pass-through transport route (VM §4.3). Certificate pinning by the client is
/// compatible with it, since nothing is intercepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportRoute {
    handling: BTreeMap<PassThroughHazard, HazardHandling>,
}

impl TransportRoute {
    /// Declares a transport route. Every hazard must be declared, and an in-tunnel
    /// protocol change can only be a broader grant, because pass-through cannot refuse it.
    pub fn new(handling: BTreeMap<PassThroughHazard, HazardHandling>) -> Result<Self, RouteError> {
        for hazard in PassThroughHazard::ALL {
            match handling.get(&hazard) {
                None => return Err(RouteError::UndeclaredHazard { hazard }),
                Some(HazardHandling::Refuse)
                    if hazard == PassThroughHazard::InTunnelProtocolChange =>
                {
                    return Err(RouteError::CannotEnforceThroughPassThrough { hazard })
                }
                Some(_) => {}
            }
        }
        Ok(Self { handling })
    }

    /// How `hazard` is handled.
    pub fn handling(&self, hazard: PassThroughHazard) -> HazardHandling {
        self.handling
            .get(&hazard)
            .copied()
            .unwrap_or(HazardHandling::Refuse)
    }

    fn accept(
        &self,
        hazard: PassThroughHazard,
        broader: &mut Vec<(PassThroughHazard, DecisionRef)>,
    ) -> Result<(), TlsRefusal> {
        match self.handling(hazard) {
            HazardHandling::Refuse => Err(TlsRefusal::HazardRefused { hazard }),
            HazardHandling::BroaderTransportGrant(decision) => {
                broader.push((hazard, decision));
                Ok(())
            }
        }
    }

    /// Admits one TLS connection from the facts of its ClientHello. The server name is
    /// read with the one destination parser and must equal the authorized name; an
    /// accepted hazard removes the guarantee it defeats. SNI never proves the HTTP
    /// authority, so no admission carries an HTTP property.
    pub fn admit_hello(
        &self,
        authorized_name: Option<&CanonicalName>,
        hello: &ClientHelloFacts,
    ) -> Result<TransportAdmission, TlsRefusal> {
        let mut broader = Vec::new();
        if hello.transport == HelloTransport::Quic {
            self.accept(PassThroughHazard::Http3, &mut broader)?;
        }
        if hello.ech_offered {
            self.accept(PassThroughHazard::EncryptedClientHello, &mut broader)?;
        }
        let mut name_matched = false;
        match &hello.sni {
            None => self.accept(PassThroughHazard::MissingSni, &mut broader)?,
            Some(sni) => {
                let sni = CanonicalName::parse(sni).map_err(TlsRefusal::MalformedSni)?;
                match authorized_name {
                    Some(expected) if *expected == sni => name_matched = !hello.ech_offered,
                    _ => {
                        return Err(TlsRefusal::SniMismatch {
                            expected: authorized_name.cloned(),
                            presented: sni,
                        })
                    }
                }
            }
        }
        // Whatever ALPN says, the broker cannot see inside the stream.
        self.accept(PassThroughHazard::InTunnelProtocolChange, &mut broader)?;
        let mut properties = BTreeSet::from([EnforcementProperty::DestinationAddressValidated]);
        if name_matched {
            properties.insert(EnforcementProperty::TlsServerNameMatched);
        }
        Ok(TransportAdmission {
            properties,
            broader_grants: broader,
        })
    }
}

/// How a ClientHello travelled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HelloTransport {
    Tcp,
    Quic,
}

/// The facts of a ClientHello the broker can observe without decrypting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientHelloFacts {
    pub transport: HelloTransport,
    /// The (outer) server name, as sent.
    pub sni: Option<String>,
    pub ech_offered: bool,
    pub alpn: Vec<String>,
}

/// What one admitted transport connection may claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportAdmission {
    /// Only transport properties; never an HTTP-level one.
    pub properties: BTreeSet<EnforcementProperty>,
    /// The broader grants this connection relies on, with their decisions.
    pub broader_grants: Vec<(PassThroughHazard, DecisionRef)>,
}

/// Why a TLS connection was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TlsRefusal {
    HazardRefused {
        hazard: PassThroughHazard,
    },
    MalformedSni(NameError),
    /// The server name is not the authorized one (or the endpoint has no name).
    SniMismatch {
        expected: Option<CanonicalName>,
        presented: CanonicalName,
    },
}

impl fmt::Display for TlsRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HazardRefused { hazard } => {
                write!(f, "the route refuses connections with {hazard:?}")
            }
            Self::MalformedSni(error) => write!(f, "the TLS server name is invalid: {error}"),
            Self::SniMismatch {
                expected,
                presented,
            } => match expected {
                Some(expected) => write!(
                    f,
                    "the TLS server name {presented} is not the authorized {expected}"
                ),
                None => write!(f, "the endpoint has no name, but SNI {presented} was sent"),
            },
        }
    }
}

impl std::error::Error for TlsRefusal {}

/// A property a route can enforce (VM §4.3; VM-W03: transport routes cannot claim L7
/// enforcement).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementProperty {
    /// The connection goes to an address the broker validated.
    DestinationAddressValidated,
    /// The TLS server name equals the authorized name (transport level only).
    TlsServerNameMatched,
    /// The executor verified TLS for the authorized name itself.
    TlsVerifiedForAuthorizedName,
    HttpAuthorityBound,
    HttpMethodBound,
    HttpPathBound,
    HttpQueryBound,
    HeaderPolicyEnforced,
    RedirectsControlled,
    /// The executor injects the credential; the guest never sees it.
    CredentialInjectedByExecutor,
}

impl EnforcementProperty {
    /// True for properties that need inspected application traffic (L7).
    pub const fn is_application_layer(self) -> bool {
        !matches!(
            self,
            Self::DestinationAddressValidated | Self::TlsServerNameMatched
        )
    }
}

/// Why a route refused a claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimRefusal {
    /// A transport route cannot inspect opaque content (line 1964).
    TransportCannotInspect { property: EnforcementProperty },
    /// The route does not provide the property.
    NotProvided { property: EnforcementProperty },
}

impl fmt::Display for ClaimRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TransportCannotInspect { property } => write!(
                f,
                "a pass-through transport route cannot claim {property:?}; it grants only a \
                 transport property"
            ),
            Self::NotProvided { property } => {
                write!(f, "this route does not provide {property:?}")
            }
        }
    }
}

impl std::error::Error for ClaimRefusal {}

/// A typed route (VM §4.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteKind {
    Operation(OperationRoute),
    Transport(TransportRoute),
}

impl RouteKind {
    /// The properties every admitted request or connection on this route has.
    pub fn properties(&self) -> BTreeSet<EnforcementProperty> {
        use EnforcementProperty as P;
        match self {
            Self::Operation(route) => {
                let mut properties = BTreeSet::from([
                    P::DestinationAddressValidated,
                    P::TlsVerifiedForAuthorizedName,
                    P::HttpAuthorityBound,
                    P::HttpMethodBound,
                    P::HttpPathBound,
                    P::HttpQueryBound,
                    P::HeaderPolicyEnforced,
                    P::RedirectsControlled,
                ]);
                if route.is_credentialed() {
                    properties.insert(P::CredentialInjectedByExecutor);
                }
                properties
            }
            Self::Transport(route) => {
                let mut properties = BTreeSet::from([P::DestinationAddressValidated]);
                let name_always_checked = [
                    PassThroughHazard::MissingSni,
                    PassThroughHazard::EncryptedClientHello,
                ]
                .iter()
                .all(|hazard| route.handling(*hazard) == HazardHandling::Refuse);
                if name_always_checked {
                    properties.insert(P::TlsServerNameMatched);
                }
                properties
            }
        }
    }

    /// Refuses a claim the route cannot back; a transport route refuses every
    /// application-layer property.
    pub fn claim(&self, property: EnforcementProperty) -> Result<(), ClaimRefusal> {
        if matches!(self, Self::Transport(_)) && property.is_application_layer() {
            return Err(ClaimRefusal::TransportCannotInspect { property });
        }
        if self.properties().contains(&property) {
            Ok(())
        } else {
            Err(ClaimRefusal::NotProvided { property })
        }
    }
}
