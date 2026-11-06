//! The relay step for the response: the upstream's bytes to the bytes the guest gets,
//! with the route's inbound byte budget reserved in the broker before use (VM §3.1;
//! VM §4.3: disable or re-authorize redirects, prevent parser disagreement; VM §4.2 step
//! 7 and §2.5: bytes reserved centrally; VM-W03: budget scope explicit; VM-W11; VM-P10,
//! VM-P32).
//!
//! [`ResponseStep::start`] binds the step to the bound request's route, which must be an
//! operation route of the broker's policy and the route of the connection permit, takes
//! the request's method from the [`BoundRequest`], and makes the response's one
//! reservation before any byte is read: [`DestinationBroker::reserve_received`] for the
//! most the response may bring, the head limit plus the body limit, capped by what the
//! route's `BytesIn` budget has left. A response that fits the remaining budget is never
//! refused for the reservation's size; one that runs past a reservation the budget capped
//! is refused as [`ResponseRefusal::OverBudget`]. Without that cap the reader's own limits
//! end a response before it can pass the reservation. [`ResponseStep::finish`] settles
//! with [`DestinationBroker::complete_received`] and the exact bytes received: heads, body
//! and chunk framing. Every byte handed to the step until it completes or refuses counts
//! as received from the upstream: a refusal, an [`ResponseStep::abandon`] or an incomplete
//! finish settles with what arrived, never leaving anything reserved, and V02 charges an
//! overrun (bytes past the reservation that came in the same feed) as it does for sends.
//!
//! What the guest gets is rebuilt from the parsed response, never copied: an `HTTP/1.1`
//! status line with the status code and the reason phrase only when it is visible ASCII
//! and spaces; the final head's fields in received order with lowercase names, without
//! [`NOT_RETURNED_HEADERS`], any `Proxy-*` field and the fields `Connection` names; and the
//! decoded body framed by one `content-length`. A body-less response keeps the declared
//! length a HEAD or `304` response describes and gets none for `204`. Interim responses
//! are never forwarded. A 3xx `Location` is passed on but never followed: the result
//! reports the [`Redirect`] with V02's reading of the target. A caller follows a redirect
//! only through [`DestinationBroker::follow_redirect`], which applies the route's
//! [`RedirectPolicy`](crate::sandbox_contract::destinations::RedirectPolicy) and
//! re-authorizes the target, and then sends a new request through the relay step.

use std::fmt;

use super::reader::{ReadProgress, ReaderLimits};
use super::response::{
    ReadResponse, ResponseFraming, ResponseOutcome, ResponseReadRefusal, ResponseReader,
};
use crate::foundation::ids::Clock;
use crate::sandbox_contract::destinations::{
    redirect_target, Authority, BodyFraming, BoundRequest, BudgetKind, ConnectionPermit,
    DestinationBroker, DestinationRefusal, ReceiveReservation, RedirectTarget, RequestRefusal,
    RouteId, RouteKind,
};

/// Header fields of the upstream's response that are never returned to the guest: the
/// hop-by-hop fields, and `content-length`, which is replaced by the decoded body's.
/// Fields starting with [`PROXY_HEADER_PREFIX`] and those `Connection` names go too.
pub const NOT_RETURNED_HEADERS: [&str; 7] = [
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
];

/// Response fields whose lowercase name starts with this are hop-by-hop and dropped.
pub const PROXY_HEADER_PREFIX: &str = "proxy-";

/// Why the relay refused the upstream's response (VM §4.3; VM-P10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResponseRefusal {
    Read(ResponseReadRefusal),
    /// The response has not been read to its end.
    Incomplete,
    /// The route carries pass-through TLS, so there is no HTTP response to read.
    NotAnOperationRoute {
        route: RouteId,
    },
    /// The connection permit is for another route.
    PermitForOtherRoute {
        route: RouteId,
        permit: RouteId,
    },
    /// The response ran past the bytes the route's inbound budget had left for it.
    OverBudget {
        route: RouteId,
        reserved: u64,
    },
    /// The route is unknown, the permit is stale, or a reservation or settlement of the
    /// route's budget failed.
    Destination(DestinationRefusal),
}

impl fmt::Display for ResponseRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(refusal) => fmt::Display::fmt(refusal, f),
            Self::Incomplete => f.write_str("the response has not been read to its end"),
            Self::NotAnOperationRoute { route } => write!(
                f,
                "route {route} passes TLS through, so its responses cannot be read"
            ),
            Self::PermitForOtherRoute { route, permit } => write!(
                f,
                "the connection permit is for route {permit}, not route {route}"
            ),
            Self::OverBudget { route, reserved } => write!(
                f,
                "the response ran past the {reserved} bytes route {route} had left to receive"
            ),
            Self::Destination(refusal) => fmt::Display::fmt(refusal, f),
        }
    }
}

impl std::error::Error for ResponseRefusal {}

impl From<ResponseReadRefusal> for ResponseRefusal {
    fn from(refusal: ResponseReadRefusal) -> Self {
        Self::Read(refusal)
    }
}

impl From<DestinationRefusal> for ResponseRefusal {
    fn from(refusal: DestinationRefusal) -> Self {
        Self::Destination(refusal)
    }
}

/// A redirect the response carried, reported and never followed. A caller follows it
/// only through [`DestinationBroker::follow_redirect`], which applies the route's
/// redirect policy and re-authorizes the target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Redirect {
    pub status: u16,
    /// The `Location` value, passed on to the guest as received.
    pub location: String,
    /// V02's reading of the location against the bound authority, for the caller's
    /// information; it authorizes nothing.
    pub target: Result<RedirectTarget, RequestRefusal>,
}

/// The response the guest gets, rebuilt from the parsed response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestResponse {
    status: u16,
    bytes: Vec<u8>,
    redirect: Option<Redirect>,
    received_bytes: u64,
}

impl GuestResponse {
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// The exact bytes to send to the guest.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// The redirect of a 3xx response with a `Location`, which the relay did not follow
    /// (only [`DestinationBroker::follow_redirect`] may).
    pub fn redirect(&self) -> Option<&Redirect> {
        self.redirect.as_ref()
    }

    /// The bytes received from the upstream and charged to the route's inbound budget.
    pub const fn received_bytes(&self) -> u64 {
        self.received_bytes
    }
}

/// The upstream's response to one forwarded request, from its first byte to the bytes
/// the guest gets.
///
/// Dropping a step leaks its inbound reservation in the broker; finish it or call
/// [`ResponseStep::abandon`].
#[derive(Debug, PartialEq, Eq)]
#[must_use = "dropping a ResponseStep leaks its inbound reservation; finish or abandon it"]
pub struct ResponseStep {
    route: RouteId,
    authority: Authority,
    reader: ResponseReader,
    /// Open until the step settles.
    reservation: Option<ReceiveReservation>,
    /// The bytes reserved, when the route's remaining budget set that size.
    budget_cap: Option<u64>,
    /// Bytes handed to the step while it was open.
    received: u64,
    refused: Option<ResponseRefusal>,
}

impl ResponseStep {
    /// Starts reading the response to `bound`, which was sent on `permit`, and reserves
    /// the most the response may bring against the route's inbound budget in the broker.
    pub fn start<C: Clock>(
        broker: &mut DestinationBroker<C>,
        permit: &ConnectionPermit,
        bound: &BoundRequest,
        limits: ReaderLimits,
    ) -> Result<Self, ResponseRefusal> {
        let route = &bound.route;
        let grant =
            broker
                .policy()
                .grant(route)
                .ok_or_else(|| DestinationRefusal::UnknownRoute {
                    route: route.clone(),
                })?;
        if !matches!(grant.route, RouteKind::Operation(_)) {
            return Err(ResponseRefusal::NotAnOperationRoute {
                route: route.clone(),
            });
        }
        if permit.route() != route {
            return Err(ResponseRefusal::PermitForOtherRoute {
                route: route.clone(),
                permit: permit.route().clone(),
            });
        }
        let usage = broker.usage(route);
        let left = grant.budgets.bytes_in.saturating_sub(
            usage
                .used(BudgetKind::BytesIn)
                .saturating_add(usage.reserved(BudgetKind::BytesIn)),
        );
        let most = u64::try_from(limits.max_head_bytes())
            .unwrap_or(u64::MAX)
            .saturating_add(limits.max_body_bytes());
        let reserved = most.min(left);
        let reservation = broker.reserve_received(permit, reserved)?;
        Ok(Self {
            route: route.clone(),
            authority: bound.authority.clone(),
            reader: ResponseReader::new(limits, bound.method),
            reservation: Some(reservation),
            budget_cap: (reserved < most).then_some(reserved),
            received: 0,
            refused: None,
        })
    }

    pub fn route(&self) -> &RouteId {
        &self.route
    }

    /// Feeds the next bytes from the upstream. A refusal settles the reservation with
    /// what arrived and is final.
    pub fn feed<C: Clock>(
        &mut self,
        broker: &mut DestinationBroker<C>,
        input: &[u8],
    ) -> Result<ReadProgress, ResponseRefusal> {
        if let Some(refusal) = &self.refused {
            return Err(refusal.clone());
        }
        let result = self.advance(input);
        self.keep_refusal(broker, result)
    }

    /// The upstream closed the connection: completes a body read until the end of the
    /// input and refuses a response that has not ended.
    pub fn end_of_input<C: Clock>(
        &mut self,
        broker: &mut DestinationBroker<C>,
    ) -> Result<ReadProgress, ResponseRefusal> {
        if let Some(refusal) = &self.refused {
            return Err(refusal.clone());
        }
        let result = self.reader.end_of_input().map_err(ResponseRefusal::from);
        self.keep_refusal(broker, result)
    }

    /// Settles the reservation with the bytes received and rebuilds the response for the
    /// guest.
    pub fn finish<C: Clock>(
        self,
        broker: &mut DestinationBroker<C>,
    ) -> Result<GuestResponse, ResponseRefusal> {
        let Self {
            authority,
            reader,
            reservation,
            received,
            refused,
            ..
        } = self;
        if let Some(refusal) = refused {
            return Err(refusal);
        }
        let read = match reader.into_outcome() {
            ResponseOutcome::Complete(read) => read,
            ResponseOutcome::NeedMore => {
                // The refusal is the reason; a failure to settle as well would only hide it.
                let _ = settle(broker, reservation, received);
                return Err(ResponseRefusal::Incomplete);
            }
            ResponseOutcome::Refused(refusal) => {
                let _ = settle(broker, reservation, received);
                return Err(refusal.into());
            }
        };
        settle(broker, reservation, received)?;
        Ok(GuestResponse {
            status: read.status(),
            bytes: rebuild(&read),
            redirect: redirect(&read, &authority),
            received_bytes: received,
        })
    }

    /// Gives the response up: settles the reservation with what arrived.
    pub fn abandon<C: Clock>(
        self,
        broker: &mut DestinationBroker<C>,
    ) -> Result<(), DestinationRefusal> {
        settle(broker, self.reservation, self.received)
    }

    /// Hands the reader no more than a budget-capped reservation has room for.
    fn advance(&mut self, input: &[u8]) -> Result<ReadProgress, ResponseRefusal> {
        let before = self.received;
        self.received = before.saturating_add(u64::try_from(input.len()).unwrap_or(u64::MAX));
        let Some(reserved) = self.budget_cap else {
            // The reader's limits end the response within the reservation.
            return Ok(self.reader.feed(input)?);
        };
        let room = reserved.saturating_sub(before);
        let take = usize::try_from(room).map_or(input.len(), |room| room.min(input.len()));
        let progress = self.reader.feed(input.get(..take).unwrap_or_default())?;
        if take == input.len() {
            return Ok(progress);
        }
        match progress {
            // The response ended within the reservation; the reader refuses what follows.
            ReadProgress::Complete => {
                Ok(self.reader.feed(input.get(take..).unwrap_or_default())?)
            }
            ReadProgress::NeedMore => Err(ResponseRefusal::OverBudget {
                route: self.route.clone(),
                reserved,
            }),
        }
    }

    /// On a refusal, settles the reservation with what arrived and keeps the refusal for
    /// every later call.
    fn keep_refusal<C: Clock, T>(
        &mut self,
        broker: &mut DestinationBroker<C>,
        result: Result<T, ResponseRefusal>,
    ) -> Result<T, ResponseRefusal> {
        if let Err(refusal) = &result {
            // The refusal is the reason; a failure to settle as well would only hide it.
            let _ = settle(broker, self.reservation.take(), self.received);
            self.refused = Some(refusal.clone());
        }
        result
    }
}

/// Settles an open reservation with the bytes received.
fn settle<C: Clock>(
    broker: &mut DestinationBroker<C>,
    reservation: Option<ReceiveReservation>,
    received: u64,
) -> Result<(), DestinationRefusal> {
    reservation.map_or(Ok(()), |reservation| {
        broker.complete_received(reservation, received)
    })
}

/// The reason phrase the guest gets: the received one without surrounding spaces, when it
/// is visible ASCII and spaces.
fn guest_reason(reason: &str) -> Option<&str> {
    let reason = reason.trim_matches(' ');
    let visible = reason
        .bytes()
        .all(|byte| byte == b' ' || byte.is_ascii_graphic());
    (visible && !reason.is_empty()).then_some(reason)
}

/// Writes the guest's response from the parsed one.
fn rebuild(read: &ReadResponse) -> Vec<u8> {
    let mut head = format!("HTTP/1.1 {} ", read.status());
    if let Some(reason) = guest_reason(read.reason()) {
        head.push_str(reason);
    }
    head.push_str("\r\n");
    let named: Vec<String> = read
        .headers()
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, value)| value.split(','))
        .map(|option| option.trim_matches([' ', '\t']).to_ascii_lowercase())
        .filter(|option| !option.is_empty())
        .collect();
    for (name, value) in read.headers() {
        let name = name.to_ascii_lowercase();
        if NOT_RETURNED_HEADERS.contains(&name.as_str())
            || name.starts_with(PROXY_HEADER_PREFIX)
            || named.contains(&name)
        {
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
    let length = match read.framing() {
        ResponseFraming::Framed(BodyFraming::None) if read.status() == 204 => None,
        // HEAD and 304 describe the representation's length without sending it.
        ResponseFraming::Framed(BodyFraming::None) => read.content_length(),
        ResponseFraming::Framed(_) | ResponseFraming::UntilClose => {
            Some(u64::try_from(read.body().len()).unwrap_or(u64::MAX))
        }
    };
    if let Some(length) = length {
        head.push_str("content-length: ");
        head.push_str(&length.to_string());
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    let mut bytes = head.into_bytes();
    bytes.extend_from_slice(read.body());
    bytes
}

/// The redirect of a 3xx response (other than `304`) with a `Location`; the reader
/// refused more than one.
fn redirect(read: &ReadResponse, authority: &Authority) -> Option<Redirect> {
    let status = read.status();
    if !(300..=399).contains(&status) || status == 304 {
        return None;
    }
    let (_, location) = read
        .headers()
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("location"))?;
    Some(Redirect {
        status,
        location: location.clone(),
        target: redirect_target(authority, location),
    })
}

#[cfg(test)]
#[path = "tests/response_step.rs"]
mod tests;
