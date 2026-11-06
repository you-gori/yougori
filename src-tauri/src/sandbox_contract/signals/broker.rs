//! The destination broker's refusals as signals (V02
//! [`DestinationBroker`](crate::sandbox_contract::destinations::DestinationBroker); VM part §4.2
//! "Name resolution and destination validation", §2.5 "Bound releases and post-revocation
//! exposure"; VM-W11).
//!
//! The broker refuses most requests as designed: a destination no grant names, a port,
//! protocol, resolver or address family not granted, a stale validation, an expired answer,
//! a name that does not resolve, an answer it cannot use (a refused address class among
//! them, which the resolver or the policy supplied, not the guest), a spent budget. None of
//! those is a violation, and neither is a reservation the account never issued or already
//! settled ([`ReleaseError::UnknownReservation`], [`SettleError::Unknown`]): reservations
//! are move-only host values the guest never holds, so that is host wiring
//! ([`Ordinary::HostWiring`]). Two refusals are the guest's own misuse:
//!
//! - a connection to an address outside the destination's validated answer
//!   ([`DestinationRefusal::AddressNotValidated`]): the guest steering a validated name to
//!   another address. The perimeter saw traffic outside the destination rules:
//!   [`ViolationKind::PerimeterRule`] by the [`HostObserver::Perimeter`], V14's observer
//!   for "destinations, packets, connections".
//! - a release overrun: more bytes left than were reserved, beyond the documented in-flight
//!   allowance of the release account ([`ReleaseError::AllowanceExceeded`]) or beyond the
//!   route reservation, which has no allowance ([`SettleError::ExceedsReservation`]):
//!   [`ViolationKind::BudgetOverrun`] by the [`HostObserver::Broker`], which V14 gives
//!   release budgets
//!   ([`MonitoredResource::ReleaseBudgetSpentBytes`](crate::sandbox_contract::response::MonitoredResource)).
//!
//! Either stops the sandbox whose guest did it and names no grant: the route grant is
//! shared by every sandbox holding the route, and one guest's misuse does not compromise
//! it. The subject is the route the request was made on.

use crate::foundation::ids::{Digest, DigestBuilder};
use crate::sandbox_contract::destinations::{
    AuthorizationRefusal, DestinationRefusal, ReleaseError, ResolverFailure, RouteId, SettleError,
    SyntheticError,
};
use crate::sandbox_contract::response::{HostObserver, ViolationKind};

use super::observed::{Classification, Observed, Ordinary};

/// The digest domain of a broker signal's subject.
pub const ROUTE_SUBJECT_DOMAIN: &str = "yougori/sandbox/signals/route-subject/v1";

/// What made a broker refusal a guest violation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BrokerViolation {
    /// A connection to an address outside the destination's validated answer.
    UnvalidatedAddress,
    /// More bytes left than were reserved, beyond any documented allowance.
    ReleaseOverrun,
}

impl BrokerViolation {
    /// The V14 kind the violation is filed under.
    pub const fn kind(self) -> ViolationKind {
        match self {
            Self::UnvalidatedAddress => ViolationKind::PerimeterRule,
            Self::ReleaseOverrun => ViolationKind::BudgetOverrun,
        }
    }

    /// The host observer that sees it.
    pub const fn observer(self) -> HostObserver {
        match self {
            Self::UnvalidatedAddress => HostObserver::Perimeter,
            Self::ReleaseOverrun => HostObserver::Broker,
        }
    }
}

/// The broker request a refusal answered, as the host knows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerContext {
    /// The sandbox whose broker refused, and when on the shared host clock.
    pub observed: Observed,
    /// The route the request was made on.
    pub route: RouteId,
}

/// The subject of a broker signal: the route.
pub fn route_subject(route: &RouteId) -> Digest {
    DigestBuilder::new(ROUTE_SUBJECT_DOMAIN)
        .str(route.as_str())
        .finish()
}

/// Classifies one broker refusal: the guest violation, or why it is not one.
fn classify(refusal: &DestinationRefusal) -> Result<BrokerViolation, Ordinary> {
    match refusal {
        DestinationRefusal::AddressNotValidated { .. } => Ok(BrokerViolation::UnvalidatedAddress),
        DestinationRefusal::Release(error) => classify_release(error),
        DestinationRefusal::Settle(error) => match error {
            SettleError::Unknown => Err(Ordinary::HostWiring),
            SettleError::ExceedsReservation { .. } => Ok(BrokerViolation::ReleaseOverrun),
        },
        DestinationRefusal::Authorization(refusal) => Err(match refusal {
            AuthorizationRefusal::OwnershipExpired { .. } => Ordinary::NotCurrent,
            AuthorizationRefusal::Offline
            | AuthorizationRefusal::NotGranted { .. }
            | AuthorizationRefusal::WildcardTooDeep { .. }
            | AuthorizationRefusal::PortNotGranted { .. }
            | AuthorizationRefusal::ProtocolNotGranted { .. }
            | AuthorizationRefusal::AddressNeedsEndpointGrant { .. }
            | AuthorizationRefusal::ResolutionForbidden { .. }
            | AuthorizationRefusal::ObjectNotApproved { .. } => Ordinary::NotPermitted,
        }),
        DestinationRefusal::Stale { .. } | DestinationRefusal::Expired => Err(Ordinary::NotCurrent),
        DestinationRefusal::UnknownRoute { .. }
        | DestinationRefusal::ResolverNotAllowed { .. }
        | DestinationRefusal::ResolutionForbidden
        | DestinationRefusal::Ipv6NotGranted
        | DestinationRefusal::RedirectsDisabled
        | DestinationRefusal::RedirectLeavesRoute { .. } => Err(Ordinary::NotPermitted),
        DestinationRefusal::EndpointNotResolved
        | DestinationRefusal::NotAnEndpoint
        | DestinationRefusal::NotNewer => Err(Ordinary::HostConfiguration),
        DestinationRefusal::ResolverFailed(failure) => Err(match failure {
            ResolverFailure::NameDoesNotExist | ResolverFailure::NoData => Ordinary::NotFound,
            ResolverFailure::Failed { .. } => Ordinary::UnusableDestination,
        }),
        DestinationRefusal::AnswerForOtherName { .. }
        | DestinationRefusal::WrongFamily { .. }
        | DestinationRefusal::AliasChainTooLong { .. }
        | DestinationRefusal::EmptyAnswer
        | DestinationRefusal::Address(_)
        | DestinationRefusal::Redirect(_) => Err(Ordinary::UnusableDestination),
        DestinationRefusal::Synthetic(error) => Err(match error {
            SyntheticError::Collision { .. } => Ordinary::UnusableDestination,
            SyntheticError::Exhausted { .. } => Ordinary::LimitReached,
            SyntheticError::NoUsableCandidate { .. }
            | SyntheticError::UnsuitableCandidate { .. }
            | SyntheticError::NoIpv6Range => Ordinary::HostConfiguration,
        }),
        DestinationRefusal::Budget(_) => Err(Ordinary::LimitReached),
    }
}

fn classify_release(error: &ReleaseError) -> Result<BrokerViolation, Ordinary> {
    match error {
        ReleaseError::AllowanceExceeded { .. } => Ok(BrokerViolation::ReleaseOverrun),
        ReleaseError::UnknownReservation => Err(Ordinary::HostWiring),
        ReleaseError::Exhausted(_) => Err(Ordinary::LimitReached),
        // Closed by an earlier overrun, which was the violation and was signalled then.
        ReleaseError::ChannelNotPermitted { .. }
        | ReleaseError::OwnBudgetChannel { .. }
        | ReleaseError::Closed => Err(Ordinary::NotPermitted),
        ReleaseError::UndocumentedAllowance => Err(Ordinary::HostConfiguration),
    }
}

/// How one relay broker refusal reads for the response path (pure, no clock): a guest
/// violation ([`BrokerViolation`]); a relay protocol fault, where the confined relay
/// forwarded something the broker's own rebuild or book contradicts (a fault of, or an
/// attack through, the guest-facing parser: the broker refuses the exchange, and the engine
/// tells the user and audits it without revoking anything, because it concerns the relay,
/// not the guest); or an ordinary refusal with its reason (an undeclared operation, a limit,
/// an upstream that failed, a response the echo scan refused, a host-side configuration).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrokerRefusalClass {
    Violation(BrokerViolation),
    RelayProtocol,
    Ordinary(Ordinary),
}

/// Classifies one relay broker refusal (pure). Only V02's destination refusals can be guest
/// violations (and through the relay neither is reachable by the guest: the broker picks
/// every address and every reservation itself); the relay's own protocol faults are told,
/// not revoked; everything else is ordinary.
pub fn classify_broker_refusal(
    refusal: &crate::sandbox_contract::relay_broker::BrokerRefusal,
) -> BrokerRefusalClass {
    use crate::sandbox_contract::relay_broker::{BrokerRefusal as R, InjectionRefusal as I};
    match refusal {
        R::Destination(refusal) => match classify(refusal) {
            Ok(violation) => BrokerRefusalClass::Violation(violation),
            Err(ordinary) => BrokerRefusalClass::Ordinary(ordinary),
        },
        R::ExchangeNotIncreasing { .. }
        | R::RouteMismatch { .. }
        | R::BytesDiffer { .. }
        | R::BindingDiffers
        | R::SniMismatch { .. } => BrokerRefusalClass::RelayProtocol,
        R::TooManyOpenExchanges { .. } => BrokerRefusalClass::Ordinary(Ordinary::LimitReached),
        R::Relay(_) | R::Request(_) | R::PlaintextRefused { .. } | R::NoServerName { .. } => {
            BrokerRefusalClass::Ordinary(Ordinary::NotPermitted)
        }
        // The guest's own request: a credential header it may not send, an operation that is
        // no provider contract, a head too short to inject into.
        R::Credential(I::GuestCredentialHeader { .. })
        | R::Credential(I::OperationNotContract { .. })
        | R::Credential(I::MalformedHead) => BrokerRefusalClass::Ordinary(Ordinary::NotPermitted),
        R::Credential(I::OverAllowance { .. }) => {
            BrokerRefusalClass::Ordinary(Ordinary::LimitReached)
        }
        // The host's side: no audience, a grant or vault refusal (a credential not enrolled),
        // a class mismatch, a stored value that is no header value.
        R::Credential(I::NoAudience { .. })
        | R::Credential(I::Grant(_))
        | R::Credential(I::Vault(_))
        | R::Credential(I::ClassMismatch { .. })
        | R::Credential(I::InvalidHeaderValue) => {
            BrokerRefusalClass::Ordinary(Ordinary::HostConfiguration)
        }
        R::GuestTlsUnknown => BrokerRefusalClass::Ordinary(Ordinary::HostWiring),
        R::Response(_) | R::Upstream(_) | R::Echo(_) => {
            BrokerRefusalClass::Ordinary(Ordinary::NotFound)
        }
        R::Cancelled => BrokerRefusalClass::Ordinary(Ordinary::NotCurrent),
    }
}

/// The signal of one broker refusal (pure): a guest violation the perimeter or the broker
/// observed, about the sandbox, on the route and against no grant; or why the refusal
/// drafts nothing.
pub fn destination_refusal_signal(
    refusal: &DestinationRefusal,
    context: &BrokerContext,
) -> Classification<BrokerViolation> {
    match classify(refusal) {
        Ok(cause) => Classification::Violation {
            cause,
            draft: context.observed.violation(
                cause.kind(),
                cause.observer(),
                route_subject(&context.route),
                None,
            ),
        },
        Err(reason) => Classification::Ordinary { reason },
    }
}
