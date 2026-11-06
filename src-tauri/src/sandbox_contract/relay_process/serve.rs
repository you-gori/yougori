//! The relay's loop between the guest and the link (M09E; VM part §3.1; VM-W11).
//!
//! [`serve`] drives a [`RelayCore`] with two ports: the guest side, a [`GuestPort`] of byte
//! streams, one per guest connection, which the guest transport (M06) will implement;
//! and the broker side, a [`RelayLinkPort`], which the link pipe implements on Windows.
//! It is single-threaded and every wait is bounded: while exchanges wait for the broker it
//! waits on the link and only looks at the guest, otherwise the other way round.
//!
//! The loop ends when the guest transport has ended and nothing is held (the relay then
//! closes the link with `Finished`), when the broker closes the link, or when either side
//! fails. Every guest connection still held then gets the fixed error.

use std::fmt;
use std::time::Duration;

use super::relay_core::{
    GuestConnection, GuestEndpoint, RelayAction, RelayCore, CONTINUE_RESPONSE, GUEST_ERROR_RESPONSE,
};
use crate::sandbox_contract::relay_link::{BrokerMessage, CloseReason, RelayMessage};

/// What the guest did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuestEvent {
    /// The guest opened `connection` to `endpoint`.
    Opened {
        connection: GuestConnection,
        endpoint: GuestEndpoint,
    },
    /// The next bytes the guest sent on `connection`.
    Data {
        connection: GuestConnection,
        bytes: Vec<u8>,
    },
    /// The guest ended its sending side of `connection`; it may still read the answer.
    Closed { connection: GuestConnection },
    /// Nothing happened within the wait.
    Idle,
    /// The guest transport ended: no more connections or bytes come.
    Ended,
}

/// Why a guest port failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestPortError {
    pub detail: String,
}

impl fmt::Display for GuestPortError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the guest port failed: {}", self.detail)
    }
}

impl std::error::Error for GuestPortError {}

/// The guest side of the relay: byte streams, one per guest connection, each to one
/// guest-facing endpoint. The real transport is M06's.
pub trait GuestPort {
    /// Waits at most `within` for what the guest does next.
    fn next_event(&mut self, within: Duration) -> Result<GuestEvent, GuestPortError>;

    /// Writes `bytes` to `connection`, which stays open.
    fn write(&mut self, connection: GuestConnection, bytes: &[u8]) -> Result<(), GuestPortError>;

    /// Ends `connection` after what was written to it.
    fn end(&mut self, connection: GuestConnection);
}

/// Why the relay's link failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkPortError {
    pub detail: String,
}

impl fmt::Display for LinkPortError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the link failed: {}", self.detail)
    }
}

impl std::error::Error for LinkPortError {}

/// The broker side of the relay: the relay's end of the link.
pub trait RelayLinkPort {
    /// Seals and sends `message`, waiting at most `within`.
    fn send(&mut self, message: RelayMessage, within: Duration) -> Result<(), LinkPortError>;

    /// The broker's next message, waiting at most `within`; `None` when none came.
    fn receive(&mut self, within: Duration) -> Result<Option<BrokerMessage>, LinkPortError>;
}

#[cfg(windows)]
impl RelayLinkPort
    for crate::sandbox_contract::relay_link::LinkPipe<
        crate::sandbox_contract::relay_link::RelaySide,
    >
{
    fn send(&mut self, message: RelayMessage, within: Duration) -> Result<(), LinkPortError> {
        crate::sandbox_contract::relay_link::LinkPipe::send(self, message, within).map_err(
            |error| LinkPortError {
                detail: error.to_string(),
            },
        )
    }

    fn receive(&mut self, within: Duration) -> Result<Option<BrokerMessage>, LinkPortError> {
        match crate::sandbox_contract::relay_link::LinkPipe::receive(self, within) {
            Ok(message) => Ok(Some(message)),
            Err(crate::sandbox_contract::relay_link::PipeError::TimedOut) => Ok(None),
            Err(error) => Err(LinkPortError {
                detail: error.to_string(),
            }),
        }
    }
}

/// The waits of the loop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServeTiming {
    /// How long one wait on a side lasts.
    pub poll: Duration,
    /// How long sending one message to the broker may take.
    pub send: Duration,
}

impl Default for ServeTiming {
    fn default() -> Self {
        Self {
            poll: Duration::from_millis(10),
            send: Duration::from_secs(30),
        }
    }
}

/// How the loop ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServeEnd {
    /// The guest transport ended with nothing held; the relay closed the link.
    GuestEnded,
    /// The broker closed the link.
    BrokerClosed {
        reason: CloseReason,
    },
    LinkFailed(LinkPortError),
    GuestFailed(GuestPortError),
}

impl ServeEnd {
    /// True for an orderly end.
    pub const fn is_orderly(&self) -> bool {
        matches!(self, Self::GuestEnded | Self::BrokerClosed { .. })
    }
}

/// Runs the relay between `guest` and `link` until one of the ends in the module notes.
pub fn serve(
    core: &mut RelayCore,
    guest: &mut impl GuestPort,
    link: &mut impl RelayLinkPort,
    timing: ServeTiming,
) -> ServeEnd {
    let mut guest_ended = false;
    loop {
        let link_wait = if core.awaits_broker() {
            timing.poll
        } else {
            Duration::ZERO
        };
        match link.receive(link_wait) {
            Ok(None) => {}
            Ok(Some(message)) => {
                let closed = match &message {
                    BrokerMessage::Close { reason } => Some(*reason),
                    _ => None,
                };
                let actions = core.broker(message);
                if let Some(end) = carry_out(core, guest, link, actions, timing) {
                    return end;
                }
                if let Some(reason) = closed {
                    return ServeEnd::BrokerClosed { reason };
                }
            }
            Err(error) => {
                let actions = core.link_ended();
                answer_only(guest, actions);
                return ServeEnd::LinkFailed(error);
            }
        }
        if guest_ended {
            if core.is_idle() {
                if let Some(message) = core.close(CloseReason::Finished) {
                    // The guest is done and nothing is open; a failed close changes
                    // nothing for it.
                    let _ = link.send(message, timing.send);
                }
                return ServeEnd::GuestEnded;
            }
            continue;
        }
        let guest_wait = if core.awaits_broker() {
            Duration::ZERO
        } else {
            timing.poll
        };
        let actions = match guest.next_event(guest_wait) {
            Ok(GuestEvent::Opened {
                connection,
                endpoint,
            }) => core.open(connection, &endpoint),
            Ok(GuestEvent::Data { connection, bytes }) => core.receive(connection, &bytes),
            Ok(GuestEvent::Closed { connection }) => core.guest_closed(connection),
            Ok(GuestEvent::Idle) => Vec::new(),
            Ok(GuestEvent::Ended) => {
                guest_ended = true;
                Vec::new()
            }
            Err(error) => {
                if let Some(message) = core.close(CloseReason::Stopping) {
                    let _ = link.send(message, timing.send);
                }
                return ServeEnd::GuestFailed(error);
            }
        };
        if let Some(end) = carry_out(core, guest, link, actions, timing) {
            return end;
        }
    }
}

/// Carries out `actions`; returns the loop's end if sending to the broker failed.
fn carry_out(
    core: &mut RelayCore,
    guest: &mut impl GuestPort,
    link: &mut impl RelayLinkPort,
    actions: Vec<RelayAction>,
    timing: ServeTiming,
) -> Option<ServeEnd> {
    let mut failed = None;
    let mut pending = actions;
    while !pending.is_empty() {
        let mut next = Vec::new();
        for action in pending {
            match action {
                RelayAction::Forward(message) => {
                    if failed.is_some() {
                        continue;
                    }
                    if let Err(error) = link.send(message, timing.send) {
                        next.extend(core.link_ended());
                        failed = Some(ServeEnd::LinkFailed(error));
                    }
                }
                other => answer(core, guest, other),
            }
        }
        pending = next;
    }
    failed
}

/// Writes one guest-facing action.
fn answer(core: &mut RelayCore, guest: &mut impl GuestPort, action: RelayAction) {
    let (connection, bytes, end): (GuestConnection, &[u8], bool) = match &action {
        RelayAction::Forward(_) => return,
        RelayAction::Continue { connection } => (*connection, CONTINUE_RESPONSE, false),
        RelayAction::Respond {
            connection,
            response,
        } => (*connection, response.as_slice(), true),
        RelayAction::Refuse { connection, .. } => (*connection, GUEST_ERROR_RESPONSE, true),
    };
    let written = guest.write(connection, bytes);
    if end || written.is_err() {
        guest.end(connection);
        core.guest_gone(connection);
    }
}

/// Writes guest-facing actions after the link ended; there is no broker to send to.
fn answer_only(guest: &mut impl GuestPort, actions: Vec<RelayAction>) {
    for action in actions {
        if let RelayAction::Refuse { connection, .. } = action {
            let _ = guest.write(connection, GUEST_ERROR_RESPONSE);
            guest.end(connection);
        }
    }
}
