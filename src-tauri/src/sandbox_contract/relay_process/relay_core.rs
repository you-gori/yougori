//! The relay's core, sans-IO (M09E; VM part §3.1: the guest relay parses bounded frames
//! and forwards typed requests; VM §4.3; VM-W11; VM-W28 "No credential in relay").
//!
//! [`RelayCore`] takes what the guest does, one guest connection at a time, and what the
//! broker answers, and returns [`RelayAction`]s for the caller to carry out. It holds no
//! broker state, no budget, no credential and no socket: only the sandbox's
//! [`RouteTable`] and the [`ReaderLimits`] handed over at launch.
//!
//! - A guest connection reaches one [`GuestEndpoint`]; the route table names its route.
//!   An endpoint not in the table is refused at once.
//! - The guest's bytes go through a fresh [`RequestReader`] per connection. `Expect:
//!   100-continue` is answered by the relay itself ([`CONTINUE_RESPONSE`]). Once the
//!   request is complete it is rebuilt from the parsed request, never copied from the
//!   guest ([`forward_bytes`]), numbered above every exchange before it and sent as
//!   [`RelayMessage::Forward`].
//! - The broker's [`BrokerMessage::Response`] bytes go to the guest of that exchange. A
//!   refusal by the relay or the broker, a closed link or a guest that stops early gets
//!   the fixed [`GUEST_ERROR_RESPONSE`], which carries no detail; the reason stays with the
//!   relay ([`GuestRefusal`]).
//! - At most [`MAX_OPEN_EXCHANGES`] guest connections are held at once, being read or
//!   forwarded and unanswered, so the link's own limit is never reached.
//!
//! The rebuilt request is the fixed point the broker's relay step expects (M09D's
//! contract): the request line with the target as V02 normalizes it (path segments, query
//! keys in sorted order), `host` with the canonical authority (`:port` only for a port
//! other than 443), the guest's other accepted fields in received order with lowercase
//! names, without [`NOT_FORWARDED_HEADERS`], then one `content-length` of the decoded body
//! (none for a method that forbids a body and sent none), the empty line and the body. The
//! broker re-reads it and decides everything again.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::sandbox_contract::destinations::route::route_name;
use crate::sandbox_contract::destinations::{
    normalize_target, Authority, BodyFraming, DestinationPort, HttpMethod, RequestRefusal, RouteId,
};
use crate::sandbox_contract::relay::{
    ReadOutcome, ReadProgress, ReadRefusal, ReadRequest, ReaderLimits, RequestReader,
    NOT_FORWARDED_HEADERS,
};
use crate::sandbox_contract::relay_link::{
    BrokerMessage, CloseReason, ExchangeId, ExchangeRefusal, RelayMessage, WireBytes,
    MAX_OPEN_EXCHANGES,
};

route_name!(
    /// A guest-facing endpoint of the relay: what a guest connection reached, as the guest
    /// transport (M06) reports it. The route table names its route.
    GuestEndpoint
);

/// The most entries a route table holds.
pub const MAX_ROUTES: usize = 256;

/// The fixed answer to a guest whose exchange the relay or the broker refused, or that a
/// closed link cut short. It names no stage, policy, destination or credential.
pub const GUEST_ERROR_RESPONSE: &[u8] =
    b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";

/// The interim answer to a guest that sent `Expect: 100-continue`: the relay reads the
/// whole body before anything is forwarded.
pub const CONTINUE_RESPONSE: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\n";

/// One entry of a [`RouteTable`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteEntry {
    pub endpoint: GuestEndpoint,
    pub route: RouteId,
}

/// Why a route table was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteTableError {
    Empty,
    TooManyRoutes { max: usize },
    DuplicateEndpoint { endpoint: GuestEndpoint },
}

impl fmt::Display for RouteTableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("the route table has no route"),
            Self::TooManyRoutes { max } => write!(f, "the route table has more than {max} routes"),
            Self::DuplicateEndpoint { endpoint } => {
                write!(f, "endpoint {endpoint} appears twice in the route table")
            }
        }
    }
}

impl std::error::Error for RouteTableError {}

/// The sandbox's route table: which route each guest endpoint names. Policy data handed
/// over at launch; it holds no budget, credential or destination, and authorizes nothing:
/// the broker authorizes every request again.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<RouteEntry>", into = "Vec<RouteEntry>")]
pub struct RouteTable {
    routes: BTreeMap<GuestEndpoint, RouteId>,
}

impl RouteTable {
    /// A table of 1 to [`MAX_ROUTES`] entries, each endpoint once.
    pub fn new(entries: Vec<RouteEntry>) -> Result<Self, RouteTableError> {
        if entries.is_empty() {
            return Err(RouteTableError::Empty);
        }
        if entries.len() > MAX_ROUTES {
            return Err(RouteTableError::TooManyRoutes { max: MAX_ROUTES });
        }
        let mut routes = BTreeMap::new();
        for entry in entries {
            if routes.contains_key(&entry.endpoint) {
                return Err(RouteTableError::DuplicateEndpoint {
                    endpoint: entry.endpoint,
                });
            }
            routes.insert(entry.endpoint, entry.route);
        }
        Ok(Self { routes })
    }

    /// The route `endpoint` names, if any.
    pub fn route(&self, endpoint: &GuestEndpoint) -> Option<&RouteId> {
        self.routes.get(endpoint)
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

impl TryFrom<Vec<RouteEntry>> for RouteTable {
    type Error = RouteTableError;

    fn try_from(entries: Vec<RouteEntry>) -> Result<Self, Self::Error> {
        Self::new(entries)
    }
}

impl From<RouteTable> for Vec<RouteEntry> {
    fn from(table: RouteTable) -> Self {
        table
            .routes
            .into_iter()
            .map(|(endpoint, route)| RouteEntry { endpoint, route })
            .collect()
    }
}

/// One guest connection, numbered by the guest port.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GuestConnection(u64);

impl GuestConnection {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for GuestConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "guest connection {}", self.0)
    }
}

/// Why the relay answered a guest with [`GUEST_ERROR_RESPONSE`]. The guest never sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuestRefusal {
    /// The endpoint is not in the route table.
    UnknownEndpoint { endpoint: GuestEndpoint },
    /// [`MAX_OPEN_EXCHANGES`] guest connections are held already.
    TooManyExchanges { max: usize },
    /// The connection is already held.
    DuplicateConnection,
    /// The reader refused the guest's bytes.
    Read(ReadRefusal),
    /// The request could not be rebuilt for forwarding.
    Request(RequestRefusal),
    /// The guest stopped sending before its request ended.
    Incomplete,
    /// The guest sent bytes after its request had been forwarded.
    BytesAfterRequest,
    /// Every exchange number has been used.
    ExchangesExhausted,
    /// The broker refused the exchange.
    Broker(ExchangeRefusal),
    /// The link ended before the broker answered.
    LinkEnded,
}

impl fmt::Display for GuestRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownEndpoint { endpoint } => {
                write!(f, "endpoint {endpoint} is not in the route table")
            }
            Self::TooManyExchanges { max } => write!(f, "{max} guest exchanges are held already"),
            Self::DuplicateConnection => f.write_str("the guest connection is already held"),
            Self::Read(refusal) => fmt::Display::fmt(refusal, f),
            Self::Request(refusal) => fmt::Display::fmt(refusal, f),
            Self::Incomplete => f.write_str("the guest stopped before its request ended"),
            Self::BytesAfterRequest => {
                f.write_str("the guest sent bytes after its request was forwarded")
            }
            Self::ExchangesExhausted => f.write_str("every exchange number has been used"),
            Self::Broker(refusal) => write!(f, "the broker refused the exchange ({refusal:?})"),
            Self::LinkEnded => f.write_str("the link ended before the broker answered"),
        }
    }
}

impl std::error::Error for GuestRefusal {}

impl From<RequestRefusal> for GuestRefusal {
    fn from(refusal: RequestRefusal) -> Self {
        Self::Request(refusal)
    }
}

/// What the caller does next.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayAction {
    /// Send this message to the broker.
    Forward(RelayMessage),
    /// Write [`CONTINUE_RESPONSE`] to the guest connection, which stays open.
    Continue { connection: GuestConnection },
    /// Write the broker's response to the guest connection and end it.
    Respond {
        connection: GuestConnection,
        response: WireBytes,
    },
    /// Write [`GUEST_ERROR_RESPONSE`] to the guest connection and end it.
    Refuse {
        connection: GuestConnection,
        refusal: GuestRefusal,
    },
}

/// A guest connection whose request is being read.
#[derive(Debug)]
struct Reading {
    route: RouteId,
    reader: RequestReader,
    continued: bool,
}

/// The relay's core (see the module notes).
#[derive(Debug)]
pub struct RelayCore {
    routes: RouteTable,
    limits: ReaderLimits,
    /// The number of the next exchange; `None` once every number is used.
    next: Option<ExchangeId>,
    reading: BTreeMap<GuestConnection, Reading>,
    /// Forwarded and unanswered, with the guest connection waiting for each, if it still
    /// is.
    open: BTreeMap<ExchangeId, Option<GuestConnection>>,
    /// Guest connections waiting for the broker.
    waiting: BTreeSet<GuestConnection>,
    link_open: bool,
}

impl RelayCore {
    pub fn new(routes: RouteTable, limits: ReaderLimits) -> Self {
        Self {
            routes,
            limits,
            next: Some(ExchangeId::FIRST),
            reading: BTreeMap::new(),
            open: BTreeMap::new(),
            waiting: BTreeSet::new(),
            link_open: true,
        }
    }

    pub fn routes(&self) -> &RouteTable {
        &self.routes
    }

    pub const fn limits(&self) -> ReaderLimits {
        self.limits
    }

    /// Exchanges forwarded and not yet answered by the broker.
    pub fn open_exchanges(&self) -> usize {
        self.open.len()
    }

    /// True when exchanges wait for the broker.
    pub fn awaits_broker(&self) -> bool {
        !self.open.is_empty()
    }

    /// True when no guest connection is held and no exchange is open.
    pub fn is_idle(&self) -> bool {
        self.reading.is_empty() && self.open.is_empty() && self.waiting.is_empty()
    }

    /// True until the link closed or failed.
    pub const fn link_open(&self) -> bool {
        self.link_open
    }

    /// The guest opened `connection` to `endpoint`.
    pub fn open(
        &mut self,
        connection: GuestConnection,
        endpoint: &GuestEndpoint,
    ) -> Vec<RelayAction> {
        if self.holds(connection) {
            return vec![self.refuse_held(connection, GuestRefusal::DuplicateConnection)];
        }
        let refusal = if !self.link_open {
            Some(GuestRefusal::LinkEnded)
        } else if self.reading.len() + self.open.len() >= MAX_OPEN_EXCHANGES {
            Some(GuestRefusal::TooManyExchanges {
                max: MAX_OPEN_EXCHANGES,
            })
        } else {
            None
        };
        if let Some(refusal) = refusal {
            return vec![RelayAction::Refuse {
                connection,
                refusal,
            }];
        }
        let Some(route) = self.routes.route(endpoint) else {
            return vec![RelayAction::Refuse {
                connection,
                refusal: GuestRefusal::UnknownEndpoint {
                    endpoint: endpoint.clone(),
                },
            }];
        };
        self.reading.insert(
            connection,
            Reading {
                route: route.clone(),
                reader: RequestReader::new(self.limits),
                continued: false,
            },
        );
        Vec::new()
    }

    /// The guest sent `bytes` on `connection`.
    pub fn receive(&mut self, connection: GuestConnection, bytes: &[u8]) -> Vec<RelayAction> {
        if self.waiting.contains(&connection) {
            if bytes.is_empty() {
                return Vec::new();
            }
            return vec![self.refuse_held(connection, GuestRefusal::BytesAfterRequest)];
        }
        let Some(reading) = self.reading.get_mut(&connection) else {
            return Vec::new();
        };
        match reading.reader.feed(bytes) {
            Err(refusal) => vec![self.refuse_held(connection, GuestRefusal::Read(refusal))],
            Ok(ReadProgress::NeedMore) => {
                if reading.reader.expects_continue() && !reading.continued {
                    reading.continued = true;
                    vec![RelayAction::Continue { connection }]
                } else {
                    Vec::new()
                }
            }
            Ok(ReadProgress::Complete) => self.forward(connection),
        }
    }

    /// The guest ended its side of `connection`. A request not yet complete is refused; a
    /// forwarded one still gets its answer.
    pub fn guest_closed(&mut self, connection: GuestConnection) -> Vec<RelayAction> {
        if self.reading.contains_key(&connection) {
            return vec![self.refuse_held(connection, GuestRefusal::Incomplete)];
        }
        Vec::new()
    }

    /// The guest port dropped `connection`: nothing more can be written to it. An open
    /// exchange of it stays open until the broker answers, and the answer is dropped.
    pub fn guest_gone(&mut self, connection: GuestConnection) {
        self.forget(connection);
    }

    /// The broker sent `message`.
    pub fn broker(&mut self, message: BrokerMessage) -> Vec<RelayAction> {
        match message {
            BrokerMessage::Response {
                exchange, response, ..
            } => match self.answered(exchange) {
                Some(connection) => vec![RelayAction::Respond {
                    connection,
                    response,
                }],
                None => Vec::new(),
            },
            BrokerMessage::Refused { exchange, refusal } => match self.answered(exchange) {
                Some(connection) => vec![RelayAction::Refuse {
                    connection,
                    refusal: GuestRefusal::Broker(refusal),
                }],
                None => Vec::new(),
            },
            BrokerMessage::Close { .. } => self.link_ended(),
        }
    }

    /// The link closed or failed: every held guest connection gets the fixed error, and
    /// every later one too.
    pub fn link_ended(&mut self) -> Vec<RelayAction> {
        self.link_open = false;
        self.open.clear();
        let held: Vec<GuestConnection> = self
            .reading
            .keys()
            .chain(self.waiting.iter())
            .copied()
            .collect();
        self.reading.clear();
        self.waiting.clear();
        held.into_iter()
            .map(|connection| RelayAction::Refuse {
                connection,
                refusal: GuestRefusal::LinkEnded,
            })
            .collect()
    }

    /// The message that closes the link from the relay's side, once nothing is open; the
    /// core then counts the link as ended.
    pub fn close(&mut self, reason: CloseReason) -> Option<RelayMessage> {
        if !self.link_open {
            return None;
        }
        self.link_open = false;
        Some(RelayMessage::Close { reason })
    }

    fn holds(&self, connection: GuestConnection) -> bool {
        self.reading.contains_key(&connection) || self.waiting.contains(&connection)
    }

    /// Forgets `connection` and refuses it.
    fn refuse_held(&mut self, connection: GuestConnection, refusal: GuestRefusal) -> RelayAction {
        self.forget(connection);
        RelayAction::Refuse {
            connection,
            refusal,
        }
    }

    fn forget(&mut self, connection: GuestConnection) {
        self.reading.remove(&connection);
        if self.waiting.remove(&connection) {
            for waiting in self.open.values_mut() {
                if *waiting == Some(connection) {
                    *waiting = None;
                }
            }
        }
    }

    /// Closes `exchange`; the guest connection still waiting for it, if any.
    fn answered(&mut self, exchange: ExchangeId) -> Option<GuestConnection> {
        let connection = self.open.remove(&exchange).flatten()?;
        self.waiting.remove(&connection).then_some(connection)
    }

    /// Forwards the complete request of `connection`.
    fn forward(&mut self, connection: GuestConnection) -> Vec<RelayAction> {
        let Some(reading) = self.reading.remove(&connection) else {
            return Vec::new();
        };
        let read = match reading.reader.into_outcome() {
            ReadOutcome::Complete(read) => read,
            ReadOutcome::NeedMore => {
                return vec![RelayAction::Refuse {
                    connection,
                    refusal: GuestRefusal::Incomplete,
                }]
            }
            ReadOutcome::Refused(refusal) => {
                return vec![RelayAction::Refuse {
                    connection,
                    refusal: GuestRefusal::Read(refusal),
                }]
            }
        };
        let request = match forward_bytes(&read) {
            Ok(request) => request,
            Err(refusal) => {
                return vec![RelayAction::Refuse {
                    connection,
                    refusal,
                }]
            }
        };
        let Some(exchange) = self.next else {
            return vec![RelayAction::Refuse {
                connection,
                refusal: GuestRefusal::ExchangesExhausted,
            }];
        };
        self.next = exchange.next();
        self.open.insert(exchange, Some(connection));
        self.waiting.insert(connection);
        vec![RelayAction::Forward(RelayMessage::Forward {
            exchange,
            route: reading.route,
            request: WireBytes::new(request),
        })]
    }
}

/// The origin-form target from V02's normalized path and query, as
/// [`BoundRequest::outbound_target`](crate::sandbox_contract::destinations::BoundRequest::outbound_target)
/// writes it: `/`-joined segments, then the query pairs in key order.
fn origin_target(path: &[String], query: &BTreeMap<String, String>) -> String {
    let mut target = format!("/{}", path.join("/"));
    let mut separator = '?';
    for (key, value) in query {
        target.push(separator);
        target.push_str(key);
        target.push('=');
        target.push_str(value);
        separator = '&';
    }
    target
}

/// The bytes the relay forwards for `read`, rebuilt from the parsed request and never
/// copied from the guest (see the module notes). The `host` field must name an authority
/// V02's parser accepts and the target must normalize under V02's rule; anything else is
/// refused here, before anything is forwarded.
pub fn forward_bytes(read: &ReadRequest) -> Result<Vec<u8>, GuestRefusal> {
    let request = read.request();
    let method =
        HttpMethod::parse(&request.method).ok_or_else(|| RequestRefusal::UnknownMethod {
            method: request.method.clone(),
        })?;
    let (path, query) = normalize_target(&request.target)?;
    // V02's framing rule refused duplicate fields, so there is at most one `host`.
    let host = request
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("host"))
        .map(|(_, value)| value)
        .ok_or(RequestRefusal::MissingAuthority)?;
    let authority =
        Authority::parse(host, DestinationPort::HTTPS).map_err(RequestRefusal::InvalidAuthority)?;
    let mut head = format!(
        "{} {} HTTP/1.1\r\nhost: ",
        method.as_str(),
        origin_target(&path, &query)
    );
    head.push_str(&authority.host.to_string());
    if authority.port != DestinationPort::HTTPS {
        head.push(':');
        head.push_str(&authority.port.to_string());
    }
    head.push_str("\r\n");
    for (name, value) in &request.headers {
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
    if read.framing() != BodyFraming::None || !method.forbids_body() {
        head.push_str("content-length: ");
        head.push_str(&read.body().len().to_string());
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    let mut bytes = head.into_bytes();
    bytes.extend_from_slice(read.body());
    Ok(bytes)
}
