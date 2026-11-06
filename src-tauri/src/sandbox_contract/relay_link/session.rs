//! One end of the link (M09C; CORE-05 HMAC-SHA256 authentication; VM part §6.3 replay
//! protection; VM part §6.4: a process is its PID and creation time). Sans-IO: frames come
//! in as [`RawFrame`]s and go out as bytes.
//!
//! A session is opened for a [`LinkBinding`]: the sandbox, the relay process the broker
//! registered for it ([`ProcessIdentity`]) and the link session the broker chose at
//! launch. Every frame body names all three, its direction and its sequence number, and
//! the tag is HMAC-SHA256 under the session key ([`hmac_sha256`], compared with
//! [`tags_equal`]) over a digest of [`LINK_FRAME_DOMAIN`], the version and the exact body
//! bytes. [`LinkSession::accept`] checks, in order: the tag, before the body is parsed;
//! the body in strict serde; the direction (a frame reflected back to its sender is
//! refused); the sandbox, the relay process and the link session; the sequence, which must
//! be exactly the next one, so a replayed or reordered frame is refused; and the
//! exchange rules of [`MAX_OPEN_EXCHANGES`](super::MAX_OPEN_EXCHANGES).
//!
//! A refused inbound frame ends the session ([`LinkState::Failed`]): on an ordered private
//! channel such a frame means a fault or an attack, and nothing after it is read. A
//! `Close` either way ends it too ([`LinkState::Closed`]), and every frame after it, in or
//! out, is refused. A refused outbound message changes nothing.
//!
//! The frame layout follows the remote control session's sealed, sequenced frames
//! (`sandbox_contract/remote/control.rs`); the MAC and the key rule are CORE-05's
//! ([`hmac_sha256`], [`KeyError`]). A transfer envelope grants a bulk transfer of catalog
//! objects and has no part in an HTTP exchange, so none is carried here.

use std::collections::BTreeSet;
use std::fmt;
use std::marker::PhantomData;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::frame::{encode, RawFrame};
use super::message::{BrokerMessage, CloseReason, ExchangeId, RelayMessage, MAX_OPEN_EXCHANGES};
use super::LINK_PROTOCOL_VERSION;
use crate::foundation::ids::{digest, Digest, DigestBuilder, ExecutionId};
use crate::foundation::process::ProcessIdentity;
use crate::foundation::transfer::{hmac_sha256, tags_equal, KeyError, HMAC_SHA256_TAG_BYTES};

/// Domain of the digest the frame tag authenticates, which names the frame layout.
pub const LINK_FRAME_DOMAIN: &str = "yougori/sandbox/relay-link/frame/v1";

/// The session key both ends seal and verify frames with. It is fresh for every link and
/// handed to the relay at launch (outside this module). `Debug` never shows it.
#[derive(Clone)]
pub struct LinkKey(Vec<u8>);

impl LinkKey {
    /// The shortest accepted key: one HMAC-SHA256 output (CORE-05's rule).
    pub const MIN_BYTES: usize = HMAC_SHA256_TAG_BYTES;

    pub fn new(secret: Vec<u8>) -> Result<Self, KeyError> {
        if secret.len() < Self::MIN_BYTES {
            return Err(KeyError::TooShort {
                min_bytes: Self::MIN_BYTES,
                found_bytes: secret.len(),
            });
        }
        Ok(Self(secret))
    }

    fn tag(&self, body: &[u8]) -> [u8; HMAC_SHA256_TAG_BYTES] {
        let authenticated = DigestBuilder::new(LINK_FRAME_DOMAIN)
            .u64(u64::from(LINK_PROTOCOL_VERSION))
            .bytes(body)
            .finish();
        hmac_sha256(&self.0, authenticated.as_bytes())
    }

    /// Seals any body as a frame, for tests that forge frames no session would write.
    #[cfg(test)]
    pub(super) fn forge(&self, body: &[u8]) -> Result<Vec<u8>, LinkRefusal> {
        encode(body, &self.tag(body))
    }
}

impl fmt::Debug for LinkKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LinkKey(redacted)")
    }
}

impl Drop for LinkKey {
    /// Overwrites the key's bytes before they are freed (best effort: earlier copies,
    /// such as the ones the allocator or the handoff made, are not reached).
    fn drop(&mut self) {
        for byte in self.0.iter_mut() {
            // SAFETY: `byte` is a valid, aligned, exclusive reference into the buffer.
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

/// One link between a relay process and the broker, chosen by the broker at launch. A
/// reconnect is a new link session, so no frame of an earlier one is accepted again.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LinkSessionId(Digest);

impl LinkSessionId {
    /// Domain of [`LinkSessionId::generate`].
    pub const DOMAIN: &'static str = "yougori/sandbox/relay-link/session/v1";

    pub const fn from_digest(digest: Digest) -> Self {
        Self(digest)
    }

    /// A new random link session.
    pub fn generate() -> Self {
        Self(digest(Self::DOMAIN, &[uuid::Uuid::new_v4().as_bytes()]))
    }

    pub const fn digest(&self) -> &Digest {
        &self.0
    }
}

impl fmt::Display for LinkSessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "link session {}", self.0)
    }
}

/// What every frame of a link is bound to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkBinding {
    /// The sandbox the relay serves (its execution in the CORE-04 coordinator).
    pub sandbox: ExecutionId,
    /// The relay process the broker started and registered for the sandbox (PX1).
    pub relay: ProcessIdentity,
    pub session: LinkSessionId,
}

/// Which way a frame goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkDirection {
    RelayToBroker,
    BrokerToRelay,
}

/// The sealed parts of the link's ends and messages: what a message does to the session.
pub(super) mod sealed {
    use super::super::message::{CloseReason, ExchangeId};

    /// What a message does to the exchanges and the session.
    pub enum Step {
        Opens(ExchangeId),
        Answers(ExchangeId),
        Closes(CloseReason),
    }

    pub trait Sealed {
        fn step(&self) -> Step;
    }

    pub trait SealedEnd {}
}

use sealed::Step;

/// A message type of the link. Only [`RelayMessage`] and [`BrokerMessage`] are.
pub trait LinkMessage: Serialize + DeserializeOwned + sealed::Sealed {}

impl LinkMessage for RelayMessage {}
impl LinkMessage for BrokerMessage {}

/// One end of the link: what it sends and receives. Only [`RelaySide`] and
/// [`BrokerSide`] are.
pub trait LinkEnd: sealed::SealedEnd {
    type Sends: LinkMessage;
    type Receives: LinkMessage;
    const SENDS: LinkDirection;
    const RECEIVES: LinkDirection;
}

/// The relay's end: it sends [`RelayMessage`]s and receives [`BrokerMessage`]s.
#[derive(Debug)]
pub enum RelaySide {}

/// The broker's end: it sends [`BrokerMessage`]s and receives [`RelayMessage`]s.
#[derive(Debug)]
pub enum BrokerSide {}

impl sealed::SealedEnd for RelaySide {}
impl sealed::SealedEnd for BrokerSide {}

impl LinkEnd for RelaySide {
    type Sends = RelayMessage;
    type Receives = BrokerMessage;
    const SENDS: LinkDirection = LinkDirection::RelayToBroker;
    const RECEIVES: LinkDirection = LinkDirection::BrokerToRelay;
}

impl LinkEnd for BrokerSide {
    type Sends = BrokerMessage;
    type Receives = RelayMessage;
    const SENDS: LinkDirection = LinkDirection::BrokerToRelay;
    const RECEIVES: LinkDirection = LinkDirection::RelayToBroker;
}

/// Why the link refused a frame or a message. Nothing here echoes a body byte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkRefusal {
    /// The frame's version is not [`LINK_PROTOCOL_VERSION`](super::LINK_PROTOCOL_VERSION).
    UnknownVersion {
        found: u16,
    },
    /// The frame, whole, would take more than [`MAX_FRAME_BYTES`](super::MAX_FRAME_BYTES).
    Oversize {
        declared: u64,
        max: u64,
    },
    /// The frame declares an empty body.
    EmptyBody,
    /// The tag does not match: a byte changed, or another key sealed the frame.
    Tampered,
    /// The authenticated body is not a frame of this end in strict serde.
    Malformed,
    /// The frame goes the other way, such as one reflected back to its sender.
    WrongDirection {
        found: LinkDirection,
    },
    /// The frame is bound to another sandbox.
    OtherSandbox {
        found: ExecutionId,
    },
    /// The frame is bound to another relay process.
    OtherRelay {
        found: ProcessIdentity,
    },
    /// The frame belongs to another link session, such as one before a reconnect.
    OtherSession,
    /// A frame already accepted came again.
    Replayed {
        sequence: u64,
        expected: u64,
    },
    /// A frame came before the one expected next.
    OutOfOrder {
        sequence: u64,
        expected: u64,
    },
    /// An exchange was not numbered above the last one forwarded.
    ExchangeNotIncreasing {
        exchange: ExchangeId,
        last: ExchangeId,
    },
    /// An answer names an exchange that is not open.
    UnknownExchange {
        exchange: ExchangeId,
    },
    /// [`MAX_OPEN_EXCHANGES`](super::MAX_OPEN_EXCHANGES) exchanges are open already.
    TooManyOpenExchanges {
        max: usize,
    },
    /// A frame was cut short: the transport failed while it was sent or received.
    Interrupted,
    /// The link is closed; nothing moves on it either way.
    Closed,
    /// An earlier refusal ended the link.
    Failed,
    SequenceExhausted,
    /// The message could not be written as JSON.
    Encode,
}

impl fmt::Display for LinkRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownVersion { found } => write!(
                f,
                "link frame version {found} is not supported; this build reads only version \
                 {LINK_PROTOCOL_VERSION}"
            ),
            Self::Oversize { declared, max } => write!(
                f,
                "a {declared}-byte link frame is over the {max}-byte bound"
            ),
            Self::EmptyBody => f.write_str("the link frame declares an empty body"),
            Self::Tampered => f.write_str("the link frame's tag does not match its bytes"),
            Self::Malformed => f.write_str("the link frame's body is not a valid frame"),
            Self::WrongDirection { found } => {
                write!(f, "the link frame goes the other way ({found:?})")
            }
            Self::OtherSandbox { found } => {
                write!(f, "the link frame is bound to sandbox {found}")
            }
            Self::OtherRelay { found } => {
                write!(f, "the link frame is bound to another relay, {found}")
            }
            Self::OtherSession => f.write_str("the link frame belongs to another link session"),
            Self::Replayed { sequence, expected } => write!(
                f,
                "link frame {sequence} was replayed; the next is {expected}"
            ),
            Self::OutOfOrder { sequence, expected } => write!(
                f,
                "link frame {sequence} came out of order; the next is {expected}"
            ),
            Self::ExchangeNotIncreasing { exchange, last } => {
                write!(f, "{exchange} is not above the last forwarded, {last}")
            }
            Self::UnknownExchange { exchange } => write!(f, "{exchange} is not open"),
            Self::TooManyOpenExchanges { max } => {
                write!(f, "{max} exchanges are open already")
            }
            Self::Interrupted => f.write_str("a link frame was cut short"),
            Self::Closed => f.write_str("the link is closed"),
            Self::Failed => f.write_str("an earlier refusal ended the link"),
            Self::SequenceExhausted => f.write_str("the link used every sequence number"),
            Self::Encode => f.write_str("the link message could not be written"),
        }
    }
}

impl std::error::Error for LinkRefusal {}

/// Where a link session is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkState {
    Open,
    /// A `Close` went this way.
    Closed {
        by: LinkDirection,
        reason: CloseReason,
    },
    /// This refusal ended the session.
    Failed(LinkRefusal),
}

/// The body of a frame, as written and as read back strictly.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FrameBody<M> {
    sandbox: ExecutionId,
    relay: ProcessIdentity,
    session: LinkSessionId,
    direction: LinkDirection,
    sequence: u64,
    message: M,
}

/// The exchanges of one link: the last one forwarded and those not yet answered.
#[derive(Debug, Default)]
struct Exchanges {
    last: Option<ExchangeId>,
    open: BTreeSet<ExchangeId>,
}

impl Exchanges {
    fn check(&self, step: &Step) -> Result<(), LinkRefusal> {
        match step {
            Step::Opens(exchange) => {
                if let Some(last) = self.last {
                    if *exchange <= last {
                        return Err(LinkRefusal::ExchangeNotIncreasing {
                            exchange: *exchange,
                            last,
                        });
                    }
                }
                if self.open.len() >= MAX_OPEN_EXCHANGES {
                    return Err(LinkRefusal::TooManyOpenExchanges {
                        max: MAX_OPEN_EXCHANGES,
                    });
                }
                Ok(())
            }
            Step::Answers(exchange) if !self.open.contains(exchange) => {
                Err(LinkRefusal::UnknownExchange {
                    exchange: *exchange,
                })
            }
            Step::Answers(_) | Step::Closes(_) => Ok(()),
        }
    }

    fn apply(&mut self, step: &Step) {
        match step {
            Step::Opens(exchange) => {
                self.last = Some(*exchange);
                self.open.insert(*exchange);
            }
            Step::Answers(exchange) => {
                self.open.remove(exchange);
            }
            Step::Closes(_) => self.open.clear(),
        }
    }
}

/// One end of one link (see the module notes). [`RelayLink`] and [`BrokerLink`] name the
/// two ends.
#[derive(Debug)]
pub struct LinkSession<E: LinkEnd> {
    binding: LinkBinding,
    key: LinkKey,
    next_outbound: u64,
    next_inbound: u64,
    exchanges: Exchanges,
    state: LinkState,
    end: PhantomData<fn() -> E>,
}

/// The relay's end of a link.
pub type RelayLink = LinkSession<RelaySide>;

/// The broker's end of a link.
pub type BrokerLink = LinkSession<BrokerSide>;

impl<E: LinkEnd> LinkSession<E> {
    /// Opens this end of the link bound to `binding`, sealed under `key`.
    pub fn open(binding: LinkBinding, key: LinkKey) -> Self {
        Self {
            binding,
            key,
            next_outbound: 0,
            next_inbound: 0,
            exchanges: Exchanges::default(),
            state: LinkState::Open,
            end: PhantomData,
        }
    }

    pub fn binding(&self) -> &LinkBinding {
        &self.binding
    }

    pub fn state(&self) -> &LinkState {
        &self.state
    }

    /// Exchanges forwarded and not yet answered.
    pub fn open_exchanges(&self) -> usize {
        self.exchanges.open.len()
    }

    /// Seals `message` as the next frame of this end and returns its wire bytes. A
    /// refusal changes nothing; a message whose frame would exceed
    /// [`MAX_FRAME_BYTES`](super::MAX_FRAME_BYTES) is refused, never truncated.
    pub fn seal(&mut self, message: E::Sends) -> Result<Vec<u8>, LinkRefusal> {
        self.require_open()?;
        let step = sealed::Sealed::step(&message);
        self.exchanges.check(&step)?;
        let sequence = self.next_outbound;
        let next = sequence
            .checked_add(1)
            .ok_or(LinkRefusal::SequenceExhausted)?;
        let body = serde_json::to_vec(&FrameBody {
            sandbox: self.binding.sandbox.clone(),
            relay: self.binding.relay,
            session: self.binding.session,
            direction: E::SENDS,
            sequence,
            message: &message,
        })
        .map_err(|_| LinkRefusal::Encode)?;
        let bytes = encode(&body, &self.key.tag(&body))?;
        self.next_outbound = next;
        self.commit(&step, E::SENDS);
        Ok(bytes)
    }

    /// Verifies and reads one inbound frame (see the module notes). A refusal ends the
    /// session.
    pub fn accept(&mut self, frame: &RawFrame) -> Result<E::Receives, LinkRefusal> {
        self.require_open()?;
        match self.check(frame) {
            Ok((message, step)) => {
                self.next_inbound = self.next_inbound.saturating_add(1);
                self.commit(&step, E::RECEIVES);
                Ok(message)
            }
            Err(refusal) => {
                self.fail(refusal.clone());
                Err(refusal)
            }
        }
    }

    /// Ends the session with `refusal`, such as one from the frame decoder; nothing moves
    /// on it again.
    pub fn fail(&mut self, refusal: LinkRefusal) {
        if self.state == LinkState::Open {
            self.state = LinkState::Failed(refusal);
        }
    }

    fn check(&self, frame: &RawFrame) -> Result<(E::Receives, Step), LinkRefusal> {
        if !tags_equal(&self.key.tag(frame.body()), frame.tag()) {
            return Err(LinkRefusal::Tampered);
        }
        let body: FrameBody<E::Receives> =
            serde_json::from_slice(frame.body()).map_err(|_| LinkRefusal::Malformed)?;
        if body.direction != E::RECEIVES {
            return Err(LinkRefusal::WrongDirection {
                found: body.direction,
            });
        }
        if body.sandbox != self.binding.sandbox {
            return Err(LinkRefusal::OtherSandbox {
                found: body.sandbox,
            });
        }
        if body.relay != self.binding.relay {
            return Err(LinkRefusal::OtherRelay { found: body.relay });
        }
        if body.session != self.binding.session {
            return Err(LinkRefusal::OtherSession);
        }
        let expected = self.next_inbound;
        if body.sequence < expected {
            return Err(LinkRefusal::Replayed {
                sequence: body.sequence,
                expected,
            });
        }
        if body.sequence > expected {
            return Err(LinkRefusal::OutOfOrder {
                sequence: body.sequence,
                expected,
            });
        }
        if expected == u64::MAX {
            return Err(LinkRefusal::SequenceExhausted);
        }
        let step = sealed::Sealed::step(&body.message);
        self.exchanges.check(&step)?;
        Ok((body.message, step))
    }

    fn commit(&mut self, step: &Step, direction: LinkDirection) {
        self.exchanges.apply(step);
        if let Step::Closes(reason) = step {
            self.state = LinkState::Closed {
                by: direction,
                reason: *reason,
            };
        }
    }

    fn require_open(&self) -> Result<(), LinkRefusal> {
        match self.state {
            LinkState::Open => Ok(()),
            LinkState::Closed { .. } => Err(LinkRefusal::Closed),
            LinkState::Failed(_) => Err(LinkRefusal::Failed),
        }
    }
}
