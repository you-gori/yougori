//! One sandbox's relay from launch to its end (module docs in `mod.rs`).

use std::fmt;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::foundation::ids::{Clock, ExecutionId};
use crate::foundation::process::{Escalation, ProcessIdentity};
use crate::sandbox_contract::relay::ReaderLimits;
use crate::sandbox_contract::relay_broker::{
    BridgeTiming, BridgedLink, ExchangeOutcome, ExchangeRecord, LinkEnd, LinkFailure, LinkReport,
    RelayBroker,
};
use crate::sandbox_contract::relay_link::CloseReason;
use crate::sandbox_contract::relay_process::RouteTable;

use super::backend::{BoxedLink, EndOutcome, RelayBackend, RelayHandle};

/// How a host waits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayHostSettings {
    /// How long the launched relay may take to connect to its pipe and be admitted.
    pub accept_within: Duration,
    /// The bridge thread's waits.
    pub bridge: BridgeTiming,
    /// How long a stop waits for the serving thread to end before it is abandoned.
    pub stop_within: Duration,
    /// How the relay process is ended.
    pub escalation: Escalation,
}

impl Default for RelayHostSettings {
    fn default() -> Self {
        Self {
            accept_within: Duration::from_secs(10),
            bridge: BridgeTiming {
                poll: Duration::from_millis(50),
                send_within: Duration::from_secs(5),
            },
            stop_within: Duration::from_secs(5),
            escalation: Escalation {
                grace: Duration::ZERO,
                kill_wait: Duration::from_secs(10),
            },
        }
    }
}

/// Why a relay could not be started. Nothing here names a key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StartError {
    /// No confined relay exists on this platform.
    Unsupported,
    /// The sandbox has a running relay already; it is not replaced.
    AlreadyRunning,
    Launch {
        detail: String,
    },
    /// The relay was launched but never admitted on its pipe (or the handoff failed); it
    /// was ended and cleaned up.
    Accept {
        detail: String,
    },
    /// The bridge or the serving thread could not be started; the relay was ended.
    Thread {
        detail: String,
    },
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => f.write_str("no confined relay exists on this platform"),
            Self::AlreadyRunning => f.write_str("the sandbox has a running relay already"),
            Self::Launch { detail } => write!(f, "the relay could not be launched: {detail}"),
            Self::Accept { detail } => write!(f, "the relay was not admitted: {detail}"),
            Self::Thread { detail } => write!(f, "the relay could not be served: {detail}"),
        }
    }
}

impl std::error::Error for StartError {}

/// Why the host stopped a relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// The sandbox is torn down.
    Teardown,
    /// The sandbox's CORE-04 authority was revoked.
    Revoked,
}

impl StopReason {
    /// The close reason the broker sends the relay.
    pub const fn close_reason(self) -> CloseReason {
        match self {
            Self::Teardown => CloseReason::Stopping,
            Self::Revoked => CloseReason::Revoked,
        }
    }
}

/// How a relay's life ended.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "end", rename_all = "snake_case")]
pub enum RelayEndReason {
    /// The host stopped it.
    Stopped { reason: StopReason },
    /// The relay's process ended on its own; the host closed the link after it.
    Exited,
    /// The relay closed the link itself.
    ClosedByRelay { reason: String },
    /// The broker closed the link after the stop signal (its exchanges in flight answered).
    ClosedByBroker { reason: String },
    /// The link failed.
    LinkFailed { detail: String },
    /// The broker's book refused an exchange the link had accepted; nothing more was read.
    Inconsistent { detail: String },
    /// The serving thread panicked.
    ServingPanicked,
}

/// The record of one relay's life, for the audit sink (module notes).
#[derive(Clone, Debug)]
pub struct RelayLife {
    pub sandbox: ExecutionId,
    pub relay: Option<ProcessIdentity>,
    /// The relay was admitted on its pipe and served.
    pub admitted: bool,
    pub end: RelayEndReason,
    /// The broker's record of every exchange answered on the link.
    pub exchanges: Vec<ExchangeRecord>,
    /// Whether the serving thread was joined (`false`: abandoned after the bound).
    pub serving_joined: bool,
    /// Whether the host has proof the relay's process ended.
    pub ended_with_proof: bool,
    /// Whether the executable grant and the AppContainer profile were removed.
    pub cleanup_ok: bool,
}

impl RelayLife {
    /// The life as a serializable summary: counts, never bodies.
    pub fn summary(&self) -> RelayLifeSummary {
        let refused = self
            .exchanges
            .iter()
            .filter(|record| matches!(record.outcome, ExchangeOutcome::Refused(_)))
            .count();
        RelayLifeSummary {
            sandbox: self.sandbox.clone(),
            relay: self.relay,
            admitted: self.admitted,
            end: self.end.clone(),
            exchanges: self.exchanges.len(),
            exchanges_refused: refused,
            exchanges_undelivered: self
                .exchanges
                .iter()
                .filter(|record| !record.delivered)
                .count(),
            serving_joined: self.serving_joined,
            ended_with_proof: self.ended_with_proof,
            cleanup_ok: self.cleanup_ok,
        }
    }
}

/// [`RelayLife`] in counts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayLifeSummary {
    pub sandbox: ExecutionId,
    pub relay: Option<ProcessIdentity>,
    pub admitted: bool,
    pub end: RelayEndReason,
    pub exchanges: usize,
    pub exchanges_refused: usize,
    pub exchanges_undelivered: usize,
    pub serving_joined: bool,
    pub ended_with_proof: bool,
    pub cleanup_ok: bool,
}

/// What a host says about its relay.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "relay", rename_all = "snake_case")]
pub enum RelayStatus {
    Running { identity: Option<ProcessIdentity> },
    Ended(RelayLifeSummary),
}

/// What the engine needs of a running relay to serve its guest pipe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayFacts {
    pub identity: Option<ProcessIdentity>,
    /// The relay's AppContainer SID, binary.
    pub container_sid: Option<Vec<u8>>,
    /// The guest pipe the relay opens, when its launch asked for one.
    pub guest_pipe: Option<String>,
}

struct Running {
    handle: Box<dyn RelayHandle>,
    serving: JoinHandle<LinkReport>,
    stop: Option<oneshot::Sender<CloseReason>>,
    identity: Option<ProcessIdentity>,
}

enum State {
    Running(Running),
    Ended(RelayLife),
    /// Between two states, never observed.
    Changing,
}

/// One sandbox's relay (module notes).
pub struct RelayHost {
    sandbox: ExecutionId,
    settings: RelayHostSettings,
    state: State,
    /// Whether the registry has reported the end.
    pub(super) reported: bool,
}

impl fmt::Debug for RelayHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayHost")
            .field("sandbox", &self.sandbox)
            .field("running", &self.is_running())
            .finish_non_exhaustive()
    }
}

impl RelayHost {
    /// Launches, admits and serves one relay for `sandbox` (module notes). On any failure
    /// after the launch the relay is ended and cleaned up before the error returns.
    pub fn start<C: Clock + Send + Sync + 'static>(
        backend: &mut dyn RelayBackend,
        sandbox: ExecutionId,
        routes: &RouteTable,
        limits: ReaderLimits,
        broker: Arc<RelayBroker<C>>,
        settings: RelayHostSettings,
    ) -> Result<Self, StartError> {
        let mut handle = backend.launch(&sandbox, routes, limits)?;
        let identity = handle.identity();
        let link = match handle.accept(settings.accept_within) {
            Ok(link) => link,
            Err(error) => {
                // A relay that ended before it came names its exit code (RelayExit::code).
                let exited = handle.exit_code();
                let _ = handle.end(settings.escalation);
                return Err(match (error, exited) {
                    (StartError::Accept { detail }, Some(code)) => StartError::Accept {
                        detail: format!("{detail}; the relay had ended with exit code {code}"),
                    },
                    (error, _) => error,
                });
            }
        };
        let bridged = match BridgedLink::spawn(BoxedLink(link), settings.bridge) {
            Ok(bridged) => bridged,
            Err(error) => {
                let _ = handle.end(settings.escalation);
                return Err(StartError::Thread {
                    detail: error.to_string(),
                });
            }
        };
        let (stop_tx, stop_rx) = oneshot::channel::<CloseReason>();
        let serving = thread::Builder::new()
            .name(format!("relay-host-{sandbox}"))
            .spawn(move || serve_on_thread(broker, bridged, stop_rx));
        let serving = match serving {
            Ok(serving) => serving,
            Err(error) => {
                let _ = handle.end(settings.escalation);
                return Err(StartError::Thread {
                    detail: error.to_string(),
                });
            }
        };
        Ok(Self {
            sandbox,
            settings,
            state: State::Running(Running {
                handle,
                serving,
                stop: Some(stop_tx),
                identity,
            }),
            reported: false,
        })
    }

    pub fn sandbox(&self) -> &ExecutionId {
        &self.sandbox
    }

    pub fn is_running(&self) -> bool {
        matches!(self.state, State::Running(_))
    }

    /// The life, once the relay ended.
    pub fn life(&self) -> Option<&RelayLife> {
        match &self.state {
            State::Ended(life) => Some(life),
            _ => None,
        }
    }

    pub fn status(&self) -> RelayStatus {
        match &self.state {
            State::Running(running) => RelayStatus::Running {
                identity: running.identity,
            },
            State::Ended(life) => RelayStatus::Ended(life.summary()),
            State::Changing => RelayStatus::Running { identity: None },
        }
    }

    /// The running relay's facts for its guest pipe; `None` once it ended.
    pub fn facts(&self) -> Option<RelayFacts> {
        match &self.state {
            State::Running(running) => Some(RelayFacts {
                identity: running.identity,
                container_sid: running.handle.container_sid(),
                guest_pipe: running.handle.guest_pipe(),
            }),
            _ => None,
        }
    }

    /// Notices a relay that ended on its own or a link that ended; the life once it did.
    pub fn poll(&mut self) -> Option<&RelayLife> {
        let (serving_done, exited) = match &self.state {
            State::Running(running) => (running.serving.is_finished(), running.handle.exited()),
            _ => return self.life(),
        };
        if serving_done {
            self.finish(None);
        } else if exited {
            self.finish(Some(Ending::Exited));
        }
        self.life()
    }

    /// Stops the relay for `reason` (module notes); idempotent, bounded by the settings.
    pub fn stop(&mut self, reason: StopReason) -> &RelayLife {
        if self.is_running() {
            self.finish(Some(Ending::Stopped(reason)));
        }
        match &self.state {
            State::Ended(life) => life,
            _ => unreachable!("a stopped host has its life"),
        }
    }

    /// Ends the running relay: signals the broker's loop (with the stop's reason, or
    /// `Stopping` when the relay died), joins the serving thread within the bound, ends the
    /// process and records the life. `ending` is `None` when the serving thread ended on its
    /// own, in which case its report says why.
    fn finish(&mut self, ending: Option<Ending>) {
        let State::Running(mut running) = std::mem::replace(&mut self.state, State::Changing)
        else {
            return;
        };
        if let Some(stop) = running.stop.take() {
            let reason = match ending {
                Some(Ending::Stopped(reason)) => reason.close_reason(),
                _ => CloseReason::Stopping,
            };
            let _ = stop.send(reason);
        }
        let (report, serving_joined) = join_within(running.serving, self.settings.stop_within);
        let outcome = running.handle.end(self.settings.escalation);
        let (end, exchanges) = match (ending, report) {
            (Some(Ending::Stopped(reason)), report) => (
                RelayEndReason::Stopped { reason },
                report.map(|report| report.exchanges).unwrap_or_default(),
            ),
            (Some(Ending::Exited), report) => (
                RelayEndReason::Exited,
                report.map(|report| report.exchanges).unwrap_or_default(),
            ),
            (None, Some(report)) => (end_of(&report.end), report.exchanges),
            (None, None) => (RelayEndReason::ServingPanicked, Vec::new()),
        };
        self.state = State::Ended(RelayLife {
            sandbox: self.sandbox.clone(),
            relay: running.identity,
            admitted: true,
            end,
            exchanges,
            serving_joined,
            ended_with_proof: outcome.proof.is_ok(),
            cleanup_ok: outcome.cleanup.is_ok(),
        });
    }
}

enum Ending {
    Stopped(StopReason),
    Exited,
}

/// The end reason a link report says.
fn end_of(end: &LinkEnd) -> RelayEndReason {
    match end {
        LinkEnd::ClosedByRelay(reason) => RelayEndReason::ClosedByRelay {
            reason: format!("{reason:?}"),
        },
        LinkEnd::ClosedByBroker(reason) => RelayEndReason::ClosedByBroker {
            reason: format!("{reason:?}"),
        },
        LinkEnd::Failed(failure) => RelayEndReason::LinkFailed {
            detail: failure.to_string(),
        },
        LinkEnd::Inconsistent(refusal) => RelayEndReason::Inconsistent {
            detail: format!("{refusal:?}"),
        },
    }
}

/// Serves the link on a current-thread runtime until the relay closes it, it fails, or the
/// stop signal arrives.
fn serve_on_thread<C: Clock + Send + Sync + 'static>(
    broker: Arc<RelayBroker<C>>,
    mut bridged: BridgedLink,
    stop: oneshot::Receiver<CloseReason>,
) -> LinkReport {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            return LinkReport {
                end: LinkEnd::Failed(LinkFailure::Io(std::io::ErrorKind::Other)),
                exchanges: Vec::new(),
            }
        }
    };
    runtime.block_on(broker.serve(&mut bridged, async move {
        stop.await.unwrap_or(CloseReason::Stopping)
    }))
}

/// Joins the serving thread within `within`; `None` and `false` when it was abandoned (it
/// ends on its own once the relay's pipe is gone). A panicked thread counts as joined
/// without a report.
fn join_within(serving: JoinHandle<LinkReport>, within: Duration) -> (Option<LinkReport>, bool) {
    let deadline = Instant::now() + within;
    while !serving.is_finished() {
        if Instant::now() >= deadline {
            return (None, false);
        }
        thread::sleep(Duration::from_millis(10));
    }
    (serving.join().ok(), true)
}

impl EndOutcome {
    /// Nothing to end: a handle that was never launched.
    pub fn nothing() -> Self {
        Self {
            proof: Ok(()),
            cleanup: Ok(()),
        }
    }
}
