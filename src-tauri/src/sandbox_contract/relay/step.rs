//! The relay step: one guest request from wire bytes to a typed forward decision (VM §3.1:
//! the guest relay parses bounded frames and forwards typed requests; VM §4.3; VM §4.2
//! step 7 and §2.5: bytes reserved centrally before use; VM-W11; VM-P10, VM-P30).
//!
//! [`RelayStep::start`] binds the step to the sandbox's route, which must be an operation
//! route, and lowers the body limit to the route's outbound byte budget.
//! [`RelayStep::finish`] then runs, in order: the reader's outcome; the broker's
//! authorization of the permitted connection's authority under the current policy, which
//! must land on the same route; V02's [`bind_request`] against that authority and the
//! TLS facts; a check that V02 and the reader agree on the body framing; the rebuild of the
//! outbound bytes; and the reservation of those bytes, plus the caller's credential
//! allowance on a credentialed route, against the route's byte budget and the
//! provider-request release channel, and of one effect for an operation with an external
//! effect. Only then is a [`ForwardDecision`] returned. A refusal leaves nothing reserved.
//!
//! The forwarded bytes are rebuilt from the bound request, never copied from the guest:
//! the method and the origin-form target come from [`BoundRequest`] (so review,
//! authorization and outbound encoding cannot disagree, VM §4.3), `host` is written from
//! the bound authority, the body is re-framed with one `content-length` (`0` for a method
//! that may carry a body but sent none), and the other header fields V02 accepted follow
//! in received order with lowercase names. The fields in [`NOT_FORWARDED_HEADERS`] are not
//! copied.
//!
//! On a credentialed route the executor adds its credential header after this step. The
//! caller passes that header's length as the credential allowance, and the executor
//! settles the send reservation with the bytes that actually left, credential included.

use std::fmt;

use super::reader::{
    ReadOutcome, ReadProgress, ReadRefusal, ReadRequest, ReaderLimits, RequestReader,
};
use crate::foundation::ids::Clock;
use crate::sandbox_contract::destinations::{
    bind_request, BodyFraming, BoundRequest, ConnectionPermit, DestinationBroker, DestinationPort,
    DestinationRefusal, DestinationRequest, EffectClass, EffectOutcome, EffectReservation,
    OperationRoute, RequestRefusal, RouteId, RouteKind, RouteProtocol, SendReservation, TlsFacts,
};

/// Header fields of the guest's request that are never forwarded. `host` is rewritten from
/// the bound authority; `content-length` and `transfer-encoding` are replaced by one
/// `content-length` of the decoded body, which has no trailers, so `trailer` goes too;
/// `connection` and `te` are hop-by-hop; and `expect` has no use upstream because the
/// relay reads the whole body first (the reader reports `100-continue` to the transport).
pub const NOT_FORWARDED_HEADERS: [&str; 7] = [
    "host",
    "content-length",
    "transfer-encoding",
    "trailer",
    "connection",
    "te",
    "expect",
];

/// Why the relay refused to forward a request (VM §4.3; VM-P10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayRefusal {
    Read(ReadRefusal),
    /// The request has not been read to its end.
    Incomplete,
    /// The route carries pass-through TLS, so there is no HTTP request to inspect.
    NotAnOperationRoute {
        route: RouteId,
    },
    /// The connection permit is for another route.
    PermitForOtherRoute {
        route: RouteId,
        permit: RouteId,
    },
    /// Under the current policy the permitted authority belongs to another route.
    AuthorizedOnOtherRoute {
        route: RouteId,
        authorized: RouteId,
    },
    /// A credential allowance was given for a route without a credential.
    CredentialAllowanceWithoutCredential {
        route: RouteId,
        bytes: u64,
    },
    /// V02 refused the inspected request.
    Request(RequestRefusal),
    /// V02 and the reader read the framing differently; nothing is forwarded on a guess.
    FramingDisagreement {
        reader: BodyFraming,
        inspected: BodyFraming,
    },
    /// Authorization, a reservation or a settlement through the broker failed.
    Destination(DestinationRefusal),
}

impl fmt::Display for RelayRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(refusal) => fmt::Display::fmt(refusal, f),
            Self::Incomplete => f.write_str("the request has not been read to its end"),
            Self::NotAnOperationRoute { route } => write!(
                f,
                "route {route} passes TLS through, so its requests cannot be inspected"
            ),
            Self::PermitForOtherRoute { route, permit } => write!(
                f,
                "the connection permit is for route {permit}, not route {route}"
            ),
            Self::AuthorizedOnOtherRoute { route, authorized } => write!(
                f,
                "the permitted authority now belongs to route {authorized}, not route {route}"
            ),
            Self::CredentialAllowanceWithoutCredential { route, bytes } => write!(
                f,
                "route {route} has no credential, so a {bytes}-byte credential allowance is \
                 refused"
            ),
            Self::Request(refusal) => fmt::Display::fmt(refusal, f),
            Self::FramingDisagreement { reader, inspected } => write!(
                f,
                "the reader framed the body as {reader:?} but inspection as {inspected:?}"
            ),
            Self::Destination(refusal) => fmt::Display::fmt(refusal, f),
        }
    }
}

impl std::error::Error for RelayRefusal {}

impl From<ReadRefusal> for RelayRefusal {
    fn from(refusal: ReadRefusal) -> Self {
        Self::Read(refusal)
    }
}

impl From<RequestRefusal> for RelayRefusal {
    fn from(refusal: RequestRefusal) -> Self {
        Self::Request(refusal)
    }
}

impl From<DestinationRefusal> for RelayRefusal {
    fn from(refusal: DestinationRefusal) -> Self {
        Self::Destination(refusal)
    }
}

/// The parts of a [`ForwardDecision`], for the caller that sends the bytes and settles
/// the reservations with the broker. Dropping them leaks the reservations.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "the reservations stay held until they are settled with the broker"]
pub struct ForwardParts {
    pub bound: BoundRequest,
    /// The exact bytes to send upstream; the executor adds only its credential header.
    pub bytes: Vec<u8>,
    /// Covers [`Self::bytes`] plus the credential allowance. Settle it with
    /// [`DestinationBroker::complete_send`] and the bytes that actually left, credential
    /// header included.
    pub send: SendReservation,
    /// Settle with [`DestinationBroker::settle_effect`] once the outcome is known.
    pub effect: Option<EffectReservation>,
}

/// A request the relay may forward: the bound operation, the exact bytes to send upstream
/// and the reservations already held for them.
///
/// Dropping a decision leaks its reservations: the route's byte (and effect) budget and
/// the release channel stay held. Send it and settle the parts, or call
/// [`ForwardDecision::abandon`].
#[derive(Debug, PartialEq, Eq)]
#[must_use = "dropping a ForwardDecision leaks its reservations; settle its parts or abandon it"]
pub struct ForwardDecision {
    bound: BoundRequest,
    bytes: Vec<u8>,
    send: SendReservation,
    effect: Option<EffectReservation>,
}

impl ForwardDecision {
    pub fn bound(&self) -> &BoundRequest {
        &self.bound
    }

    /// The exact bytes to send upstream, rebuilt from the bound request.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The reservation of [`Self::bytes`] plus the credential allowance against the
    /// route's byte budget and the provider-request release channel.
    pub fn send_reservation(&self) -> &SendReservation {
        &self.send
    }

    /// The route effect reserved for an operation with an external effect.
    pub fn effect_reservation(&self) -> Option<&EffectReservation> {
        self.effect.as_ref()
    }

    pub fn into_parts(self) -> ForwardParts {
        ForwardParts {
            bound: self.bound,
            bytes: self.bytes,
            send: self.send,
            effect: self.effect,
        }
    }

    /// Returns both reservations unused, for a request that will not be sent after all.
    pub fn abandon<C: Clock>(
        self,
        broker: &mut DestinationBroker<C>,
    ) -> Result<(), DestinationRefusal> {
        let sent = broker.complete_send(self.send, 0);
        let effect = match self.effect {
            Some(effect) => broker.settle_effect(effect, EffectOutcome::NotPerformed),
            None => Ok(()),
        };
        sent.and(effect)
    }
}

/// One guest request on one sandbox route, from its first byte to a forward decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayStep {
    route: RouteId,
    reader: RequestReader,
}

impl RelayStep {
    /// Starts reading a request for `route`, which must be an operation route of the
    /// broker's policy. The body limit is `limits`' lowered to the route's outbound byte
    /// budget, since a larger body could never be sent.
    pub fn start<C: Clock>(
        broker: &DestinationBroker<C>,
        route: &RouteId,
        limits: ReaderLimits,
    ) -> Result<Self, RelayRefusal> {
        let grant =
            broker
                .policy()
                .grant(route)
                .ok_or_else(|| DestinationRefusal::UnknownRoute {
                    route: route.clone(),
                })?;
        if !matches!(grant.route, RouteKind::Operation(_)) {
            return Err(RelayRefusal::NotAnOperationRoute {
                route: route.clone(),
            });
        }
        Ok(Self {
            route: route.clone(),
            reader: RequestReader::new(limits.with_body_cap(grant.budgets.bytes_out)),
        })
    }

    pub fn route(&self) -> &RouteId {
        &self.route
    }

    /// Feeds the next bytes from the guest to the reader.
    pub fn feed(&mut self, input: &[u8]) -> Result<ReadProgress, RelayRefusal> {
        Ok(self.reader.feed(input)?)
    }

    /// True once the head is complete and accepted with `Expect: 100-continue`; the
    /// transport may answer the guest `100 Continue` (see
    /// [`RequestReader::expects_continue`]).
    pub fn expects_continue(&self) -> bool {
        self.reader.expects_continue()
    }

    /// Inspects, authorizes and reserves the complete request for sending on `permit`, a
    /// connection the broker permitted for this route; `tls` are the facts of the guest's
    /// TLS connection the request arrived on. `credential_allowance` is the length of the
    /// credential header the executor will add on a credentialed route, and must be zero
    /// on any other route.
    pub fn finish<C: Clock>(
        self,
        broker: &mut DestinationBroker<C>,
        permit: &ConnectionPermit,
        tls: &TlsFacts,
        credential_allowance: u64,
    ) -> Result<ForwardDecision, RelayRefusal> {
        let read = match self.reader.into_outcome() {
            ReadOutcome::Complete(read) => read,
            ReadOutcome::NeedMore => return Err(RelayRefusal::Incomplete),
            ReadOutcome::Refused(refusal) => return Err(refusal.into()),
        };
        if permit.route() != &self.route {
            return Err(RelayRefusal::PermitForOtherRoute {
                route: self.route,
                permit: permit.route().clone(),
            });
        }
        let authorized = broker.authorize(&DestinationRequest {
            protocol: RouteProtocol::Https,
            authority: permit.authority().clone(),
        })?;
        if authorized.route() != &self.route {
            return Err(RelayRefusal::AuthorizedOnOtherRoute {
                route: self.route,
                authorized: authorized.route().clone(),
            });
        }
        let bound = {
            let route = operation_route(broker, &self.route)?;
            if !route.is_credentialed() && credential_allowance > 0 {
                return Err(RelayRefusal::CredentialAllowanceWithoutCredential {
                    route: self.route,
                    bytes: credential_allowance,
                });
            }
            bind_request(
                &self.route,
                route,
                authorized.authority(),
                read.request(),
                tls,
            )?
        };
        if bound.body != read.framing() {
            return Err(RelayRefusal::FramingDisagreement {
                reader: read.framing(),
                inspected: bound.body,
            });
        }
        let bytes = rebuild(&bound, &read);
        let reserved = u64::try_from(bytes.len())
            .ok()
            .and_then(|length| length.checked_add(credential_allowance))
            .unwrap_or(u64::MAX);
        let send = broker.reserve_send(permit, reserved)?;
        let effect = match bound.effect {
            EffectClass::ReadOnly => None,
            EffectClass::External => match broker.reserve_effect(&self.route) {
                Ok(effect) => Some(effect),
                Err(refusal) => {
                    // The effect refusal is the reason; a failure to return the byte
                    // reservation as well would only hide it.
                    let _ = broker.complete_send(send, 0);
                    return Err(refusal.into());
                }
            },
        };
        Ok(ForwardDecision {
            bound,
            bytes,
            send,
            effect,
        })
    }
}

fn operation_route<'a, C: Clock>(
    broker: &'a DestinationBroker<C>,
    route: &RouteId,
) -> Result<&'a OperationRoute, RelayRefusal> {
    let grant = broker
        .policy()
        .grant(route)
        .ok_or_else(|| DestinationRefusal::UnknownRoute {
            route: route.clone(),
        })?;
    match &grant.route {
        RouteKind::Operation(operation) => Ok(operation),
        RouteKind::Transport(_) => Err(RelayRefusal::NotAnOperationRoute {
            route: route.clone(),
        }),
    }
}

/// Writes the outbound request from the bound request and the read request's accepted
/// header fields and decoded body.
fn rebuild(bound: &BoundRequest, read: &ReadRequest) -> Vec<u8> {
    let mut head = format!(
        "{} {} HTTP/1.1\r\nhost: ",
        bound.method.as_str(),
        bound.outbound_target()
    );
    head.push_str(&bound.authority.host.to_string());
    if bound.authority.port != DestinationPort::HTTPS {
        head.push(':');
        head.push_str(&bound.authority.port.to_string());
    }
    head.push_str("\r\n");
    for (name, value) in &read.request().headers {
        let name = name.to_ascii_lowercase();
        if NOT_FORWARDED_HEADERS.contains(&name.as_str()) {
            continue;
        }
        head.push_str(&name);
        head.push(':');
        if !value.is_empty() {
            head.push(' ');
            head.push_str(value);
        }
        head.push_str("\r\n");
    }
    if bound.body != BodyFraming::None || !bound.method.forbids_body() {
        head.push_str("content-length: ");
        head.push_str(&read.body().len().to_string());
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    let mut bytes = head.into_bytes();
    bytes.extend_from_slice(read.body());
    bytes
}
