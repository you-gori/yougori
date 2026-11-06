//! The relay backend port and its Windows implementation (module docs in `mod.rs`).

use std::fmt;
use std::time::Duration;

use crate::foundation::ids::ExecutionId;
use crate::foundation::process::{Escalation, ProcessIdentity};
use crate::sandbox_contract::relay::ReaderLimits;
use crate::sandbox_contract::relay_broker::BlockingLink;
use crate::sandbox_contract::relay_process::RouteTable;

use super::host::StartError;

/// What ending a relay found: whether the host has proof the process ended, and whether
/// its grant and profile were removed. No value here names a key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndOutcome {
    pub proof: Result<(), String>,
    pub cleanup: Result<(), String>,
}

/// One launched relay as the host supervises it.
pub trait RelayHandle: Send {
    /// The relay's process identity, once known.
    fn identity(&self) -> Option<ProcessIdentity>;

    /// Waits at most `within` for the relay to connect, admits it and hands over; the
    /// broker's end of the link. Fails when another process came, the relay never came,
    /// or the handoff could not be written.
    fn accept(&mut self, within: Duration) -> Result<Box<dyn BlockingLink>, StartError>;

    /// Whether the host observed the relay's process end.
    fn exited(&self) -> bool;

    /// Ends the relay as `escalation` says and cleans up after it.
    fn end(self: Box<Self>, escalation: Escalation) -> EndOutcome;

    /// The relay's AppContainer SID, binary, once known (the engine's guest pipe grants it).
    fn container_sid(&self) -> Option<Vec<u8>> {
        None
    }

    /// The guest pipe the relay opens after its link, when its launch asked for one.
    fn guest_pipe(&self) -> Option<String> {
        None
    }

    /// The relay process's exit code, once the host observed its end.
    fn exit_code(&self) -> Option<u32> {
        None
    }
}

/// Launches relays. The production backend is [`WindowsRelayBackend`]; tests script one.
pub trait RelayBackend: Send {
    fn launch(
        &mut self,
        sandbox: &ExecutionId,
        routes: &RouteTable,
        limits: ReaderLimits,
    ) -> Result<Box<dyn RelayHandle>, StartError>;
}

/// A boxed blocking link, so the bridge can carry any backend's.
pub(super) struct BoxedLink(pub(super) Box<dyn BlockingLink>);

impl BlockingLink for BoxedLink {
    fn receive(
        &mut self,
        within: Duration,
    ) -> Result<
        Option<crate::sandbox_contract::relay_link::RelayMessage>,
        crate::sandbox_contract::relay_broker::LinkFailure,
    > {
        self.0.receive(within)
    }

    fn send(
        &mut self,
        message: crate::sandbox_contract::relay_link::BrokerMessage,
        within: Duration,
    ) -> Result<(), crate::sandbox_contract::relay_broker::LinkFailure> {
        self.0.send(message, within)
    }
}

/// The production backend: M09E's launch of the relay executable, confined in a
/// per-sandbox AppContainer with no capabilities (Windows).
#[cfg(windows)]
#[derive(Clone)]
pub struct WindowsRelayBackend {
    /// The relay executable, an absolute path (the engine binary in its relay mode).
    pub executable: std::path::PathBuf,
    /// Its arguments, carrying no secret.
    pub arguments: Vec<std::ffi::OsString>,
    /// The PID of the engine that serves every relay's guest pipe; `None` when the relays'
    /// guest ports come from elsewhere (tests).
    pub guest_engine_pid: Option<u32>,
}

#[cfg(windows)]
impl fmt::Debug for WindowsRelayBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WindowsRelayBackend")
            .field("executable", &self.executable)
            .field("arguments", &self.arguments.len())
            .finish()
    }
}

#[cfg(windows)]
impl RelayBackend for WindowsRelayBackend {
    fn launch(
        &mut self,
        sandbox: &ExecutionId,
        routes: &RouteTable,
        limits: ReaderLimits,
    ) -> Result<Box<dyn RelayHandle>, StartError> {
        let launched = crate::sandbox_contract::relay_process::launch_relay(
            crate::sandbox_contract::relay_process::RelayLaunch {
                sandbox: sandbox.clone(),
                executable: self.executable.clone(),
                arguments: self.arguments.clone(),
                routes: routes.clone(),
                limits,
                guest_engine_pid: self.guest_engine_pid,
            },
        )
        .map_err(|error| StartError::Launch {
            detail: error.to_string(),
        })?;
        Ok(Box::new(WindowsRelayHandle {
            launched: Some(launched),
        }))
    }
}

#[cfg(windows)]
struct WindowsRelayHandle {
    launched: Option<crate::sandbox_contract::relay_process::LaunchedRelay>,
}

#[cfg(windows)]
impl RelayHandle for WindowsRelayHandle {
    fn identity(&self) -> Option<ProcessIdentity> {
        self.launched.as_ref().map(|launched| launched.identity())
    }

    fn accept(&mut self, within: Duration) -> Result<Box<dyn BlockingLink>, StartError> {
        let launched = self.launched.as_mut().ok_or(StartError::Accept {
            detail: "the relay was ended".to_owned(),
        })?;
        let link = launched
            .accept(within)
            .map_err(|error| StartError::Accept {
                detail: error.to_string(),
            })?;
        Ok(Box::new(link))
    }

    fn exited(&self) -> bool {
        self.launched
            .as_ref()
            .is_some_and(|launched| launched.process().check_ended().is_ok())
    }

    fn container_sid(&self) -> Option<Vec<u8>> {
        self.launched
            .as_ref()
            .map(|launched| launched.container_sid().to_vec())
    }

    fn guest_pipe(&self) -> Option<String> {
        self.launched
            .as_ref()
            .and_then(|launched| launched.guest_pipe())
            .map(|name| name.as_str().to_owned())
    }

    fn exit_code(&self) -> Option<u32> {
        self.launched
            .as_ref()
            .and_then(|launched| launched.process().check_ended().ok())
            .map(|proof| proof.exit_code())
    }

    fn end(mut self: Box<Self>, escalation: Escalation) -> EndOutcome {
        let Some(launched) = self.launched.take() else {
            return EndOutcome {
                proof: Ok(()),
                cleanup: Ok(()),
            };
        };
        let end = launched.end(escalation);
        EndOutcome {
            proof: end.proof.map(|_| ()).map_err(|error| format!("{error:?}")),
            cleanup: end.cleanup.map_err(|error| error.to_string()),
        }
    }
}

impl fmt::Debug for dyn RelayHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayHandle")
            .field("identity", &self.identity())
            .finish()
    }
}
