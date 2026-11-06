//! Why the broker refused an exchange, in full for the broker's own record, and the
//! closed [`ExchangeRefusal`] the relay is told (M09D; VM part §3.1: authority stays with
//! the broker; VM-W11; VM-W28: no credential in the relay).
//!
//! A [`BrokerRefusal`] names the stage and the typed reason. None of its variants can
//! hold a credential: the credential's header value never leaves the injector and the
//! upstream bytes, and an echo is reported by where and how it was found
//! ([`EchoFinding`]), never by what. The relay learns only
//! [`BrokerRefusal::exchange_refusal`], which names the stage and nothing of the policy,
//! the destination's address or a credential.

use std::fmt;
use std::io;

use super::credential::{EchoFinding, InjectionRefusal};
use crate::sandbox_contract::destinations::{DestinationRefusal, RequestRefusal, RouteId};
use crate::sandbox_contract::relay::{RelayRefusal, ResponseRefusal};
use crate::sandbox_contract::relay_link::{ExchangeId, ExchangeRefusal};

/// The stage of the upstream connection a failure happened in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UpstreamStage {
    Connect,
    Handshake,
    Send,
    Receive,
}

impl UpstreamStage {
    const fn describe(self) -> &'static str {
        match self {
            Self::Connect => "connecting",
            Self::Handshake => "the TLS handshake",
            Self::Send => "sending the request",
            Self::Receive => "receiving the response",
        }
    }
}

/// Why the TLS handshake with the upstream failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TlsFailure {
    /// The certificate does not name the authorized destination.
    CertificateNameMismatch,
    /// The certificate does not chain to a trusted root.
    UntrustedCertificate,
    /// The certificate is invalid for another reason (expired, revoked, malformed).
    InvalidCertificate,
    /// The upstream speaks none of the offered application protocols (`http/1.1` only).
    NoApplicationProtocol,
    /// The upstream sent a fatal alert.
    Alert,
    /// The upstream offers no protocol version or cipher suite the broker accepts.
    Incompatible,
    /// Any other handshake failure.
    Other,
}

impl TlsFailure {
    const fn describe(self) -> &'static str {
        match self {
            Self::CertificateNameMismatch => {
                "the upstream's certificate does not name the authorized destination"
            }
            Self::UntrustedCertificate => {
                "the upstream's certificate does not chain to a trusted root"
            }
            Self::InvalidCertificate => "the upstream's certificate is invalid",
            Self::NoApplicationProtocol => "the upstream does not speak http/1.1",
            Self::Alert => "the upstream ended the handshake with an alert",
            Self::Incompatible => "the upstream offers no acceptable TLS version or cipher suite",
            Self::Other => "the TLS handshake failed",
        }
    }
}

/// Why the upstream connection failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpstreamFailure {
    /// A stage did not finish within its deadline.
    TimedOut {
        stage: UpstreamStage,
    },
    Io {
        stage: UpstreamStage,
        kind: io::ErrorKind,
    },
    Tls(TlsFailure),
    /// The handshake settled on an application protocol other than `http/1.1`.
    NotHttp11 {
        negotiated: String,
    },
    /// The upstream closed the connection before it took the whole request.
    ClosedEarly {
        stage: UpstreamStage,
    },
    /// The authorized destination's name is not a valid TLS server name.
    InvalidServerName,
}

impl fmt::Display for UpstreamFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TimedOut { stage } => {
                write!(f, "the upstream timed out while {}", stage.describe())
            }
            Self::Io { stage, kind } => {
                write!(
                    f,
                    "the upstream failed while {} ({kind:?})",
                    stage.describe()
                )
            }
            Self::Tls(failure) => f.write_str(failure.describe()),
            Self::NotHttp11 { negotiated } => write!(
                f,
                "the upstream negotiated {negotiated:?}; only http/1.1 is spoken"
            ),
            Self::ClosedEarly { stage } => write!(
                f,
                "the upstream closed the connection while {}",
                stage.describe()
            ),
            Self::InvalidServerName => {
                f.write_str("the authorized destination is not a valid TLS server name")
            }
        }
    }
}

impl std::error::Error for UpstreamFailure {}

/// Why the broker refused an exchange (see the module notes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrokerRefusal {
    /// [`MAX_OPEN_EXCHANGES`](crate::sandbox_contract::relay_link::MAX_OPEN_EXCHANGES)
    /// exchanges are open already.
    TooManyOpenExchanges {
        max: usize,
    },
    /// The exchange is not numbered above the last one, so answering it could answer an
    /// exchange twice.
    ExchangeNotIncreasing {
        exchange: ExchangeId,
        last: ExchangeId,
    },
    /// The broker's own reader or relay step refused the forwarded request.
    Relay(RelayRefusal),
    /// V02 refused the request's authority or binding, read by the broker.
    Request(RequestRefusal),
    /// The broker's policy authorizes the request's authority on another route than the
    /// one the relay named.
    RouteMismatch {
        forwarded: RouteId,
        authorized: RouteId,
    },
    /// The forwarded bytes are not exactly the bytes the broker rebuilds from them.
    BytesDiffer {
        forwarded_bytes: u64,
        rebuilt_bytes: u64,
    },
    /// The relay step bound the request differently from the broker's first reading.
    BindingDiffers,
    /// The guest's TLS server name is not the authorized destination's.
    SniMismatch {
        sni: Option<String>,
        server_name: String,
    },
    /// The authorized destination has no name or address TLS could verify.
    NoServerName {
        route: RouteId,
    },
    /// Plaintext is configured for a route that carries a credential.
    PlaintextRefused {
        route: RouteId,
    },
    /// Authorization, resolution, a connection, a reservation or a settlement failed in
    /// the broker's book.
    Destination(DestinationRefusal),
    /// The credential could not be added.
    Credential(InjectionRefusal),
    /// The broker's response step refused the upstream's response.
    Response(ResponseRefusal),
    Upstream(UpstreamFailure),
    /// The response reflects the credential, a fixture secret or a canary; it was not
    /// sent to the relay.
    Echo(EchoFinding),
    /// The facts of the guest's TLS connection are not known on the broker's side.
    GuestTlsUnknown,
    /// The exchange was dropped before it finished, such as when the link loop stopped.
    Cancelled,
}

impl BrokerRefusal {
    /// The refusal the relay is told: the stage, never the policy, an address or a
    /// credential.
    pub fn exchange_refusal(&self) -> ExchangeRefusal {
        match self {
            Self::TooManyOpenExchanges { .. }
            | Self::ExchangeNotIncreasing { .. }
            | Self::GuestTlsUnknown
            | Self::Cancelled => ExchangeRefusal::Unavailable,
            Self::Relay(refusal) => relay_refusal(refusal),
            Self::Request(_)
            | Self::BytesDiffer { .. }
            | Self::BindingDiffers
            | Self::SniMismatch { .. } => ExchangeRefusal::RequestRefused,
            Self::RouteMismatch { .. }
            | Self::NoServerName { .. }
            | Self::PlaintextRefused { .. }
            | Self::Credential(_) => ExchangeRefusal::NotPermitted,
            Self::Destination(refusal) => destination_refusal(refusal),
            Self::Response(refusal) => match refusal {
                ResponseRefusal::OverBudget { .. } => ExchangeRefusal::BudgetExhausted,
                ResponseRefusal::Destination(refusal) => match destination_refusal(refusal) {
                    ExchangeRefusal::BudgetExhausted => ExchangeRefusal::BudgetExhausted,
                    _ => ExchangeRefusal::UpstreamFailed,
                },
                _ => ExchangeRefusal::UpstreamFailed,
            },
            Self::Upstream(_) | Self::Echo(_) => ExchangeRefusal::UpstreamFailed,
        }
    }
}

fn relay_refusal(refusal: &RelayRefusal) -> ExchangeRefusal {
    match refusal {
        RelayRefusal::Read(_)
        | RelayRefusal::Incomplete
        | RelayRefusal::Request(_)
        | RelayRefusal::FramingDisagreement { .. } => ExchangeRefusal::RequestRefused,
        RelayRefusal::NotAnOperationRoute { .. }
        | RelayRefusal::PermitForOtherRoute { .. }
        | RelayRefusal::AuthorizedOnOtherRoute { .. }
        | RelayRefusal::CredentialAllowanceWithoutCredential { .. } => {
            ExchangeRefusal::NotPermitted
        }
        RelayRefusal::Destination(refusal) => destination_refusal(refusal),
    }
}

fn destination_refusal(refusal: &DestinationRefusal) -> ExchangeRefusal {
    match refusal {
        DestinationRefusal::Budget(_) | DestinationRefusal::Release(_) => {
            ExchangeRefusal::BudgetExhausted
        }
        DestinationRefusal::ResolverFailed(_)
        | DestinationRefusal::AnswerForOtherName { .. }
        | DestinationRefusal::WrongFamily { .. }
        | DestinationRefusal::AliasChainTooLong { .. }
        | DestinationRefusal::EmptyAnswer => ExchangeRefusal::UpstreamFailed,
        DestinationRefusal::Stale { .. }
        | DestinationRefusal::Expired
        | DestinationRefusal::Settle(_) => ExchangeRefusal::Unavailable,
        _ => ExchangeRefusal::NotPermitted,
    }
}

impl fmt::Display for BrokerRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyOpenExchanges { max } => {
                write!(f, "{max} exchanges are open already")
            }
            Self::ExchangeNotIncreasing { exchange, last } => {
                write!(f, "{exchange} is not above the last opened, {last}")
            }
            Self::Relay(refusal) => fmt::Display::fmt(refusal, f),
            Self::Request(refusal) => fmt::Display::fmt(refusal, f),
            Self::RouteMismatch {
                forwarded,
                authorized,
            } => write!(
                f,
                "the relay named route {forwarded}, but the request's authority is authorized \
                 on route {authorized}"
            ),
            Self::BytesDiffer {
                forwarded_bytes,
                rebuilt_bytes,
            } => write!(
                f,
                "the {forwarded_bytes} forwarded bytes are not the {rebuilt_bytes} bytes the \
                 broker rebuilds from them"
            ),
            Self::BindingDiffers => {
                f.write_str("the relay step bound the request differently from the broker")
            }
            Self::SniMismatch { sni, server_name } => write!(
                f,
                "the guest's TLS server name {sni:?} is not the authorized {server_name}"
            ),
            Self::NoServerName { route } => write!(
                f,
                "route {route}'s destination has no name or address TLS could verify"
            ),
            Self::PlaintextRefused { route } => write!(
                f,
                "route {route} carries a credential, so it is never sent in plaintext"
            ),
            Self::Destination(refusal) => fmt::Display::fmt(refusal, f),
            Self::Credential(refusal) => fmt::Display::fmt(refusal, f),
            Self::Response(refusal) => fmt::Display::fmt(refusal, f),
            Self::Upstream(failure) => fmt::Display::fmt(failure, f),
            Self::Echo(finding) => fmt::Display::fmt(finding, f),
            Self::GuestTlsUnknown => {
                f.write_str("the facts of the guest's TLS connection are not known")
            }
            Self::Cancelled => f.write_str("the exchange was dropped before it finished"),
        }
    }
}

impl std::error::Error for BrokerRefusal {}

impl From<RelayRefusal> for BrokerRefusal {
    fn from(refusal: RelayRefusal) -> Self {
        Self::Relay(refusal)
    }
}

impl From<RequestRefusal> for BrokerRefusal {
    fn from(refusal: RequestRefusal) -> Self {
        Self::Request(refusal)
    }
}

impl From<DestinationRefusal> for BrokerRefusal {
    fn from(refusal: DestinationRefusal) -> Self {
        Self::Destination(refusal)
    }
}

impl From<InjectionRefusal> for BrokerRefusal {
    fn from(refusal: InjectionRefusal) -> Self {
        Self::Credential(refusal)
    }
}

impl From<ResponseRefusal> for BrokerRefusal {
    fn from(refusal: ResponseRefusal) -> Self {
        Self::Response(refusal)
    }
}

impl From<UpstreamFailure> for BrokerRefusal {
    fn from(failure: UpstreamFailure) -> Self {
        Self::Upstream(failure)
    }
}
