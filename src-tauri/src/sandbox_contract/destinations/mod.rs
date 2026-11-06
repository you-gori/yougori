//! V02: destination validation, typed routes and ingress grants
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md, VM part §4.1–§4.4 and §4.7, the
//! budgets of §2.5, VM-W03, VM-W08, VM-W11, VM-W13, VM-W15; scenarios VM-P06–VM-P10,
//! VM-P26, VM-P33 and VM-P36).
//!
//! Tier 0 only (VM §12.1): pure, synchronous policy and canonicalization code. Nothing
//! here resolves a name, opens a connection, installs a perimeter rule or touches a VM;
//! resolution goes through the [`Resolver`] trait and time through the shared
//! [`crate::foundation::ids::Clock`].
//!
//! - [`mode`]: the four network modes and their claims (§4.1), and optional synthetic
//!   addressing with explicit collision, IPv6 and protocol handling.
//! - [`name`] and [`address`]: one parser for names, ports and authorities, the one
//!   route reference spelling of a destination ([`route_reference`]), and the
//!   classification of every address (§4.2 steps 1, 2 and 4).
//! - [`policy`] and [`broker`]: exact, wildcard and endpoint grants authorized before any
//!   resolution; resolution through an allowed resolver; revalidation on redirects, new
//!   connections and changed policy or host-address state; name, connection, byte and
//!   effect budgets (§4.2 steps 3, 5, 6 and 7).
//! - [`budget`]: route budgets and the release channels of §2.5, charging CORE-05's
//!   VM-D12 general release budget.
//! - [`route`] and [`http`]: operation routes that inspect typed HTTP and transport
//!   routes that grant only a transport property (§4.3).
//! - [`perimeter`]: the perimeter as a declared profile, the must-probe rule, and rule
//!   enforcement as CORE-01 evidence only (§4.4).
//! - [`ingress`]: publications and sandbox-to-sandbox connections (§4.7).

/// Declares an internally tagged enum whose every variant refuses unknown fields when
/// read. Serde ignores fields after the tag of a unit variant, so reading goes through a
/// twin enum in which each unit variant is an empty struct variant; the written form is
/// the same. The pattern is the one in `foundation/report/mod.rs`, kept local.
macro_rules! strict_tagged_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident (tag = $tag:literal, wire = $wire:ident, wire_name = $wire_name:literal) {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident $({
                    $(
                        $(#[$field_meta:meta])*
                        $field:ident : $field_type:ty
                    ),* $(,)?
                })?
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(serde::Serialize)]
        #[serde(tag = $tag, rename_all = "snake_case")]
        $vis enum $name {
            $(
                $(#[$variant_meta])*
                $variant $({
                    $(
                        $(#[$field_meta])*
                        $field: $field_type
                    ),*
                })?
            ),*
        }

        #[derive(serde::Deserialize)]
        #[serde(tag = $tag, rename_all = "snake_case", deny_unknown_fields)]
        enum $wire {
            $(
                $variant {
                    $($(
                        $field: $field_type
                    ),*)?
                }
            ),*
        }

        impl From<$wire> for $name {
            fn from(wire: $wire) -> Self {
                match wire {
                    $(
                        $wire::$variant { $($($field),*)? } => Self::$variant $({ $($field),* })?,
                    )*
                }
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let record = crate::foundation::strict_serde::read_tagged(deserializer, $tag)?;
                <$wire as serde::Deserialize>::deserialize(record)
                    .map(Self::from)
                    .map_err(serde::de::Error::custom)
            }
        }
    };
}

pub mod address;
pub mod broker;
pub mod budget;
pub mod http;
pub mod ingress;
pub mod mode;
pub mod name;
pub mod perimeter;
pub mod policy;
mod punycode;
pub mod resolver;
pub mod route;

#[cfg(test)]
mod tests;

pub use address::{
    classify, AddressClass, AddressRefused, AddressRule, AddressVerdict, EmbeddedIpv4,
    EmbeddedIpv4Form, HostAddressGeneration, HostAddressState, IpPrefix, PrefixError,
    METADATA_IPV4, METADATA_IPV6,
};
pub use broker::{
    ConnectionPermit, DestinationBroker, DestinationRefusal, EffectOutcome, EffectReservation,
    ReceiveReservation, SendReservation, ValidatedDestination,
};
pub use budget::{
    BudgetBook, BudgetExhausted, BudgetKind, BudgetReservation, BudgetScope, ChannelPolicy,
    InFlightAllowance, ReleaseAccount, ReleaseChannel, ReleaseError, ReleaseReservation,
    ReleaseTrustClass, RouteBudgets, RouteUsage, SettleError,
};
pub use http::{
    bind_request, normalize_target, redirect_target, BodyFraming, BoundRequest, HttpVersion,
    InspectedRequest, RedirectTarget, RequestRefusal, TlsFacts, METHOD_OVERRIDE_HEADERS,
    RESERVED_CREDENTIAL_HEADERS,
};
pub use ingress::{
    Audience, AuthenticationMode, ConnectionAuthorization, ConnectionGrant, ConnectionRefusal,
    InboundCaller, IngressError, IngressSession, IngressTable, MissingSide, PrincipalId,
    Publication, PublicationId, PublicationRequest, SandboxConnections, SandboxEndpoint,
    ServiceIdentity,
};
pub use mode::{
    AddressFamily, CollisionSource, GuestProtocol, GuestQueryType, ModeClaim, ModeRefusal,
    NetworkMode, ProtocolHandling, ProtocolRefusal, RouteClass, SkippedCandidate,
    SyntheticAddressPlan, SyntheticAnswer, SyntheticAssignment, SyntheticError,
};
pub use name::{
    route_reference, ALabelProblem, Authority, CanonicalName, DestinationHost, DestinationPort,
    IpLiteralForm, NameError, MAX_LABEL_BYTES, MAX_NAME_BYTES, MIN_LABELS,
};
pub use perimeter::{
    check_rules, EnforcementContext, MustProbe, PerimeterAssessment, PerimeterError,
    PerimeterOptions, PerimeterPlatform, PerimeterProfile, PerimeterProperty, PerimeterRule,
    PerimeterTarget, PortSelector, ProbeOutcome, RemoteEnforcement, RuleAction, RuleEnforced,
};
pub use policy::{
    AuthorizationRefusal, AuthorizedDestination, DestinationPolicy, DestinationRequest,
    EndpointGrant, GrantPurpose, GrantTarget, PolicyError, PolicyParts, Reach, RouteGrant, RouteId,
    RouteProtocol, TaskDataClass, WildcardGrant, ZoneOwnership, SHARED_SUFFIXES,
};
pub use resolver::{
    ResolutionQuery, Resolver, ResolverAnswer, ResolverFailure, ResolverId, MAX_ALIAS_CHAIN,
};
pub use route::{
    ClaimRefusal, ClientHelloFacts, DecisionRef, EffectClass, EnforcementProperty, HazardHandling,
    HelloTransport, HttpMethod, OperationName, OperationRoute, OperationSpec, OperationTls,
    PassThroughHazard, PathSegment, PathTemplate, RedirectPolicy, RouteError, RouteKind,
    TlsRefusal, TransportAdmission, TransportRoute,
};
