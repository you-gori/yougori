//! The relay's entry point (M09E; VM part §3.1; VM-W11; VM-R17): [`relay_main`] runs the
//! relay against the guest port it is given. It inherits nothing and reads nothing from
//! argv or the environment.
//!
//! In order, on Windows: the relay refuses to run unless it is confined
//! ([`check_confined`]: an AppContainer token at low integrity with no capability SID)
//! before it opens anything; it reads its own PX1 identity and its creator's PID; it opens
//! its link pipe, named after its identity
//! ([`RelayPipeName::for_relay`](crate::sandbox_contract::relay_link::RelayPipeName::for_relay)),
//! and admits the server only if it is its creator; it reads the handoff the broker writes
//! ahead of the link; it checks that the handoff binds this very process and names its
//! creator as the broker; it opens the link on the same pipe; and it serves until the
//! guest ends, the broker closes or a side fails. Elsewhere it cannot tell whether it is
//! confined, so it refuses to run.

use std::fmt;
use std::time::Duration;

use super::handoff::{GuestPipeHandoff, HandoffError};
use super::serve::{GuestPort, ServeEnd};

/// How long the relay waits for its pipe to be created and for the broker's handoff.
pub const CONNECT_WITHIN: Duration = Duration::from_secs(30);

/// Why the relay judged itself not confined.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfinementError {
    /// The token is not an AppContainer token.
    NotAppContainer,
    /// The token holds capability SIDs.
    Capabilities { count: u32 },
    /// The token is above low integrity.
    IntegrityTooHigh { rid: u32 },
    /// The token could not be read.
    HostCall { os_error: u32 },
    /// This platform's confinement is not detected here (Unix and macOS are open), so the
    /// relay does not run.
    Unsupported,
}

impl fmt::Display for ConfinementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAppContainer => f.write_str("the relay is not in an AppContainer"),
            Self::Capabilities { count } => {
                write!(f, "the relay's token holds {count} capability SIDs")
            }
            Self::IntegrityTooHigh { rid } => {
                write!(f, "the relay runs above low integrity (RID {rid:#x})")
            }
            Self::HostCall { os_error } => {
                write!(f, "could not read the relay's token (OS error {os_error})")
            }
            Self::Unsupported => {
                f.write_str("the relay cannot detect its confinement on this platform")
            }
        }
    }
}

impl std::error::Error for ConfinementError {}

/// Whether this process is confined as a relay must be: on Windows, an AppContainer token
/// at low integrity or below with no capability SID.
#[cfg(windows)]
pub fn check_confined() -> Result<(), ConfinementError> {
    use super::token::{own_token_facts, LOW_INTEGRITY_RID};
    let facts = own_token_facts().map_err(|os_error| ConfinementError::HostCall { os_error })?;
    if !facts.app_container {
        return Err(ConfinementError::NotAppContainer);
    }
    if facts.capabilities != 0 {
        return Err(ConfinementError::Capabilities {
            count: facts.capabilities,
        });
    }
    if facts.integrity_rid > LOW_INTEGRITY_RID {
        return Err(ConfinementError::IntegrityTooHigh {
            rid: facts.integrity_rid,
        });
    }
    Ok(())
}

/// Whether this process is confined as a relay must be: not detected here, so never.
#[cfg(not(windows))]
pub fn check_confined() -> Result<(), ConfinementError> {
    Err(ConfinementError::Unsupported)
}

/// How a relay run ended.
#[derive(Debug)]
pub enum RelayExit {
    /// The relay served until this end.
    Served(ServeEnd),
    /// The relay is not confined; it opened nothing.
    NotConfined(ConfinementError),
    Handoff(HandoffError),
    /// The handoff's binding names another process, or its broker is not the relay's
    /// creator.
    NotThisProcess,
    /// The relay's own identity or creator could not be read, its pipe could not be
    /// opened, its server was refused or the handoff could not be read.
    Link {
        detail: String,
    },
    /// The guest port could not be opened from what the handoff named.
    Guest {
        detail: String,
    },
}

impl RelayExit {
    /// The process exit code: 0 for an orderly end.
    pub fn code(&self) -> i32 {
        match self {
            Self::Served(end) if end.is_orderly() => 0,
            Self::Served(_) => 2,
            Self::NotConfined(_) => 10,
            Self::Handoff(_) => 11,
            Self::NotThisProcess => 12,
            Self::Link { .. } => 13,
            Self::Guest { .. } => 14,
        }
    }
}

impl fmt::Display for RelayExit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Served(end) => write!(f, "the relay served until {end:?}"),
            Self::NotConfined(error) => write!(f, "the relay refused to run: {error}"),
            Self::Handoff(error) => fmt::Display::fmt(error, f),
            Self::NotThisProcess => f.write_str("the handoff is for another process"),
            Self::Link { detail } => write!(f, "the relay could not reach the broker: {detail}"),
            Self::Guest { detail } => write!(f, "the relay could not open its guest port: {detail}"),
        }
    }
}

/// Runs the relay (see the module notes), serving `guest`.
pub fn relay_main(guest: impl GuestPort) -> RelayExit {
    relay_main_with(move |_| Ok(guest))
}

/// Runs the relay (see the module notes), serving the guest port `open` makes once the
/// handoff is read and the link is open, from the guest pipe the handoff names (if any).
/// The production relay opens the engine's guest pipe here; a failure ends the relay with
/// [`RelayExit::Guest`], its link closed.
pub fn relay_main_with<G: GuestPort>(
    open: impl FnOnce(Option<&GuestPipeHandoff>) -> Result<G, String>,
) -> RelayExit {
    if let Err(error) = check_confined() {
        return RelayExit::NotConfined(error);
    }
    run(open)
}

#[cfg(windows)]
fn run<G: GuestPort>(
    open: impl FnOnce(Option<&GuestPipeHandoff>) -> Result<G, String>,
) -> RelayExit {
    use super::handoff::{decode_handoff, Secret, MAX_HANDOFF_BYTES};
    use super::relay_core::RelayCore;
    use super::serve::{serve, ServeTiming};
    use super::token::own_creator_pid;
    use crate::foundation::process::ProcessIdentity;
    use crate::sandbox_contract::relay_link::{open_confined_relay, RelayPipeName};

    let link_error = |detail: String| RelayExit::Link { detail };
    let me = match ProcessIdentity::holder_of(std::process::id()) {
        Ok(Some(me)) => me,
        Ok(None) => return link_error("this process has no identity".to_owned()),
        Err(error) => return link_error(error.to_string()),
    };
    let creator = match own_creator_pid() {
        Ok(creator) => creator,
        Err(os_error) => return link_error(format!("no creator found (OS error {os_error})")),
    };
    let mut handover =
        match open_confined_relay(&RelayPipeName::for_relay(&me), creator, CONNECT_WITHIN) {
            Ok(handover) => handover,
            Err(error) => return link_error(error.to_string()),
        };
    let body = match handover.read_handoff(MAX_HANDOFF_BYTES, CONNECT_WITHIN) {
        Ok(body) => Secret::new(body),
        Err(error) => return link_error(error.to_string()),
    };
    let handoff = match decode_handoff(body.as_slice()) {
        Ok(handoff) => handoff,
        Err(error) => return RelayExit::Handoff(error),
    };
    drop(body);
    if handoff.binding.relay != me || handoff.broker.pid != creator {
        return RelayExit::NotThisProcess;
    }
    let mut link = match handover.into_link(handoff.binding, handoff.key, &handoff.broker) {
        Ok(link) => link,
        Err(error) => return link_error(error.to_string()),
    };
    let mut guest = match open(handoff.guest.as_ref()) {
        Ok(guest) => guest,
        Err(detail) => return RelayExit::Guest { detail },
    };
    let mut core = RelayCore::new(handoff.routes, handoff.limits);
    RelayExit::Served(serve(&mut core, &mut guest, &mut link, ServeTiming::default()))
}

#[cfg(not(windows))]
fn run<G: GuestPort>(
    _open: impl FnOnce(Option<&GuestPipeHandoff>) -> Result<G, String>,
) -> RelayExit {
    RelayExit::NotConfined(ConfinementError::Unsupported)
}
