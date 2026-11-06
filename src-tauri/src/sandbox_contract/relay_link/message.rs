//! What the link carries (M09C; VM part §3.1: the relay forwards typed requests and holds
//! no provider secret; VM-W11 "No vault values in the generic relay"; VM-W28 "No
//! credential in relay").
//!
//! The relay sends the bytes of a forward decision, the request already rebuilt from the
//! bound request by the relay step ([`ForwardDecision::bytes`]). The broker answers each
//! exchange once: with the response the guest gets ([`GuestResponse`]), or with a typed
//! refusal. Either side may close the link.
//!
//! No message type has a field that can hold a credential or a vault value: the fields are
//! numbers, identifiers checked by their own grammar, closed enums and two byte strings.
//! The request bytes are the relay step's output, written before the executor adds its
//! credential header; the response bytes are the response step's output, which the
//! broker sends only after the executor's credential-echo scan (outside this module).
//! Every message reads back strictly: unknown fields, unknown kinds and malformed byte
//! strings are refused.

use std::fmt;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::session::sealed::{Sealed, Step};
use crate::sandbox_contract::destinations::RouteId;
use crate::sandbox_contract::relay::{ForwardDecision, GuestResponse};

/// The most exchanges a link holds open at once: forwarded and not yet answered.
pub const MAX_OPEN_EXCHANGES: usize = 16;

/// One exchange of a link: a forwarded request and the broker's one answer. The relay
/// numbers them, each above the last.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ExchangeId(u64);

impl ExchangeId {
    pub const FIRST: Self = Self(0);

    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    /// The exchange after this one, if there is one.
    pub fn next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }
}

impl fmt::Display for ExchangeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "exchange {}", self.0)
    }
}

/// HTTP bytes as they travel on the link: standard padded base64 in the JSON body,
/// decoded strictly. `Debug` shows only the length.
#[derive(Clone, PartialEq, Eq)]
pub struct WireBytes(Vec<u8>);

impl WireBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for WireBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WireBytes({} bytes)", self.0.len())
    }
}

impl Serialize for WireBytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for WireBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        STANDARD
            .decode(text.as_bytes())
            .map(Self)
            .map_err(|_| serde::de::Error::custom("the bytes are not standard padded base64"))
    }
}

/// Why a side closed the link.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloseReason {
    /// The sender has nothing more to send.
    Finished,
    /// The sandbox's authority ended (the broker's side).
    Revoked,
    /// The sender is stopping.
    Stopping,
}

/// Why the broker refused an exchange, in the terms the relay may act on. It names the
/// stage that refused, never the policy, the destination's address or a credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExchangeRefusal {
    /// The request was refused on inspection or binding (V02).
    RequestRefused,
    /// The route, its authority or the destination is not permitted under the policy.
    NotPermitted,
    /// A byte, effect or release budget had no room.
    BudgetExhausted,
    /// The upstream could not be reached, or its response was refused.
    UpstreamFailed,
    /// The broker cannot take the exchange now.
    Unavailable,
}

/// What the relay sends the broker.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[serde(remote = "Self")]
pub enum RelayMessage {
    /// The exact bytes of one forward decision, for the broker to send on a connection
    /// it permits for `route`. They were rebuilt from the bound request and carry no
    /// credential: the executor adds its header after the relay.
    Forward {
        exchange: ExchangeId,
        route: RouteId,
        request: WireBytes,
    },
    /// The relay closes the link; nothing more moves on it either way.
    Close { reason: CloseReason },
}

crate::foundation::strict_serde::strict_tag!(RelayMessage, "kind");

impl RelayMessage {
    /// The message that forwards `decision`'s bytes as `exchange`. The decision keeps its
    /// reservations, which the caller settles as the relay step says.
    pub fn forward(exchange: ExchangeId, decision: &ForwardDecision) -> Self {
        Self::Forward {
            exchange,
            route: decision.bound().route.clone(),
            request: WireBytes::new(decision.bytes().to_vec()),
        }
    }
}

/// What the broker sends the relay.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[serde(remote = "Self")]
pub enum BrokerMessage {
    /// The response the guest gets for `exchange`: its status and the exact bytes, rebuilt
    /// by the response step.
    Response {
        exchange: ExchangeId,
        status: u16,
        response: WireBytes,
    },
    /// The broker refused `exchange`; nothing more comes for it.
    Refused {
        exchange: ExchangeId,
        refusal: ExchangeRefusal,
    },
    /// The broker closes the link; nothing more moves on it either way.
    Close { reason: CloseReason },
}

crate::foundation::strict_serde::strict_tag!(BrokerMessage, "kind");

impl BrokerMessage {
    /// The message that answers `exchange` with `response`.
    pub fn response(exchange: ExchangeId, response: GuestResponse) -> Self {
        Self::Response {
            exchange,
            status: response.status(),
            response: WireBytes::new(response.into_bytes()),
        }
    }
}

impl Sealed for RelayMessage {
    fn step(&self) -> Step {
        match self {
            Self::Forward { exchange, .. } => Step::Opens(*exchange),
            Self::Close { reason } => Step::Closes(*reason),
        }
    }
}

impl Sealed for BrokerMessage {
    fn step(&self) -> Step {
        match self {
            Self::Response { exchange, .. } | Self::Refused { exchange, .. } => {
                Step::Answers(*exchange)
            }
            Self::Close { reason } => Step::Closes(*reason),
        }
    }
}
