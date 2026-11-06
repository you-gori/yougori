//! The sandbox executor process (module docs in `mod.rs`): the engine binary started by the
//! engine as `--sandbox-executor PIPE ENGINE_PID`, in the engine's kill-on-close job. It
//! connects to the engine's control pipe, admits only the engine named by PID through PX1
//! identity, and serves the executor protocol until the engine says `Shutdown` or the pipe
//! closes (the engine is gone), when every relay is stopped before the process ends.
//!
//! What it holds and the engine does not: the sandbox vault's store (the OS credential
//! store under M11B's service name) and, per sandbox, the relay's broker with its own vault
//! granted exactly the declared routes' credentials. Between requests it polls its relays,
//! so one that ended on its own is cleaned up (grant revoked, profile deleted) whether or
//! not the engine asks.

#[cfg(feature = "acceptance")]
use std::collections::BTreeSet;
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{Clock, ExecutionId, SystemClock, TenantId};
use crate::foundation::process::ProcessIdentity;
use crate::foundation::transfer::CredentialRef;
use crate::sandbox_contract::provider::SecretValue;
use crate::sandbox_contract::relay_host::{
    RelayHostSettings, RelayHosts, RelayLifeSummary, StopReason, WindowsRelayBackend,
};
use crate::sandbox_contract::relay_broker::{ExchangeObserver, ExchangeOutcome, ExchangeRecord};
use crate::sandbox_contract::relay_link::control_pipe::ControlPipe;
use crate::sandbox_contract::relay_link::{PipeError, RelayPipeName};
#[cfg(feature = "acceptance")]
use crate::sandbox_contract::response::{HostObserver, ViolationKind};
use crate::sandbox_contract::signals::{classify_broker_refusal, BrokerRefusalClass};
use crate::sandbox_contract::vault::{KeyringStore, SandboxVault};

use super::broker_build::build_broker;
use super::protocol::{
    credential_reference, decode_line, encode_line, wipe, ExecutorReply, ExecutorRequest,
    RefusalClass, RefusedExchange, RouteDeclaration, MAX_REFUSALS_PER_POLL,
    MAX_REFUSAL_DETAIL_BYTES, PROTOCOL_VERSION,
};
use super::{EXECUTOR_MODE, RELAY_MODE};

/// How long the executor waits for the engine's control pipe to exist and admit it.
pub const CONNECT_WITHIN: Duration = Duration::from_secs(30);

/// One wait for a request; between waits the relays are polled.
pub const READ_WITHIN: Duration = Duration::from_millis(250);

/// How long one reply may take to reach the engine.
pub const SEND_WITHIN: Duration = Duration::from_secs(10);

/// The tenant every relay's policy is written for (the engine's launches use the same).
pub const TENANT: &str = "local";

/// Exit codes beyond 0 (an orderly end).
pub const EXIT_ARGUMENTS: i32 = 20;
pub const EXIT_CONNECT: i32 = 21;
pub const EXIT_PIPE: i32 = 22;
/// An acceptance build's executor started without its disposable engine's data folder.
pub const EXIT_ACCEPTANCE: i32 = 23;

/// The most refused exchanges the executor keeps between two polls (module notes on
/// [`Refusals`]).
pub const MAX_PENDING_REFUSALS: usize = 1024;

/// Runs this process as the sandbox executor; `arguments` follow the mode word.
pub fn run_executor(arguments: &[String]) -> i32 {
    // An acceptance build's executor serves only a disposable engine, whose data folder sets
    // its vault service apart below; without it the executor would name the product's
    // service, so it does not start (found 30 October 2026: the restricted start had cleared
    // the variable, and runs 5 to 8 used the product's service name for their fixture).
    if !may_start() {
        return EXIT_ACCEPTANCE;
    }
    let (name, engine_pid) = match arguments {
        [name, pid] => match (RelayPipeName::new(name.clone()), pid.parse::<u32>()) {
            (Ok(name), Ok(pid)) => (name, pid),
            _ => return EXIT_ARGUMENTS,
        },
        _ => return EXIT_ARGUMENTS,
    };
    let engine = match ProcessIdentity::holder_of(engine_pid) {
        Ok(Some(engine)) => engine,
        _ => return EXIT_CONNECT,
    };
    let mut pipe = match ControlPipe::connect(&name, &engine, CONNECT_WITHIN) {
        Ok(pipe) => pipe,
        Err(_) => return EXIT_CONNECT,
    };
    let executable = match std::env::current_exe() {
        Ok(executable) => executable,
        Err(_) => return EXIT_ARGUMENTS,
    };
    // The installed engine's executor uses the production vault service; a disposable
    // acceptance engine's uses one set apart by its data folder, so a validation run never
    // reads or writes the product's entries.
    let store = match crate::acceptance::lock_suffix().as_str() {
        "" => KeyringStore::production(),
        suffix => KeyringStore::with_service(format!(
            "{}{suffix}",
            crate::sandbox_contract::vault::SERVICE
        )),
    };
    let mut executor = Executor::new(engine, executable, store);
    match executor.serve(&mut pipe) {
        Ok(()) => 0,
        Err(_) => EXIT_PIPE,
    }
}

/// The executor's state (module notes).
pub struct Executor {
    engine: ProcessIdentity,
    session: ClockSession,
    clock: SystemClock,
    tenant: TenantId,
    store: KeyringStore,
    /// The store's administration (enroll, remove, holds); the per-sandbox vaults are the
    /// brokers' own.
    vault: SandboxVault<KeyringStore>,
    hosts: RelayHosts,
    /// Lives that ended on their own, until the engine polls.
    ended: Vec<RelayLifeSummary>,
    /// The refused exchanges of every relay, until the engine polls; each relay's broker
    /// holds it through its observer.
    refusals: Arc<Mutex<Refusals>>,
}

impl Executor {
    /// An executor serving `engine`, launching relays as `executable --sandbox-relay`.
    pub fn new(
        engine: ProcessIdentity,
        executable: std::path::PathBuf,
        store: KeyringStore,
    ) -> Self {
        let _ = EXECUTOR_MODE;
        Self::with_relay(engine, executable, vec![RELAY_MODE.into()], store)
    }

    /// An executor whose relays run `executable` with `arguments` (tests run this test
    /// executable's confined helper instead of the hidden mode).
    pub fn with_relay(
        engine: ProcessIdentity,
        executable: std::path::PathBuf,
        arguments: Vec<std::ffi::OsString>,
        store: KeyringStore,
    ) -> Self {
        let session = ClockSession::generate();
        Self {
            engine,
            session,
            clock: SystemClock::new(),
            tenant: TenantId::new(TENANT).expect("a fixed identifier"),
            vault: SandboxVault::new(store.clone(), session),
            store,
            hosts: RelayHosts::new(
                Box::new(WindowsRelayBackend {
                    executable,
                    arguments,
                    guest_engine_pid: Some(engine.pid),
                }),
                RelayHostSettings::default(),
            ),
            ended: Vec::new(),
            refusals: Arc::new(Mutex::new(Refusals::default())),
        }
    }

    /// Serves requests on `pipe` until `Shutdown` (Ok) or the pipe closes (Ok: the engine is
    /// gone) or fails (Err). Every relay is stopped before returning.
    pub fn serve(&mut self, pipe: &mut ControlPipe) -> Result<(), PipeError> {
        let outcome = loop {
            match pipe.read_line(READ_WITHIN) {
                Ok(Some(mut line)) => {
                    let request = decode_line::<ExecutorRequest>(&line);
                    wipe(&mut line);
                    let (reply, done) = match request {
                        Ok(request) => self.handle(request),
                        Err(error) => (
                            ExecutorReply::Refused {
                                detail: error.to_string(),
                            },
                            false,
                        ),
                    };
                    let encoded = match encode_line(&reply) {
                        Ok(encoded) => encoded,
                        Err(error) => encode_line(&ExecutorReply::Refused {
                            detail: error.to_string(),
                        })
                        .unwrap_or_default(),
                    };
                    if let Err(error) = pipe.send_line(&encoded, SEND_WITHIN) {
                        break Err(error);
                    }
                    if done {
                        break Ok(());
                    }
                }
                Ok(None) => self.tick(),
                Err(PipeError::Disconnected) => break Ok(()),
                Err(error) => break Err(error),
            }
        };
        self.hosts.stop_all(StopReason::Teardown);
        outcome
    }

    /// Notices relays that ended on their own (and cleans up after them).
    pub fn tick(&mut self) {
        let ended = self.hosts.poll();
        self.ended.extend(ended.iter().map(|life| life.summary()));
        self.hosts.forget_ended();
    }

    /// Answers one request; `true` when the executor is to end after the reply.
    pub fn handle(&mut self, request: ExecutorRequest) -> (ExecutorReply, bool) {
        match request {
            ExecutorRequest::Hello {
                version,
                engine_pid,
            } => {
                if version != PROTOCOL_VERSION {
                    return (
                        ExecutorReply::Refused {
                            detail: format!(
                                "the engine speaks protocol {version}; this executor speaks {PROTOCOL_VERSION}"
                            ),
                        },
                        true,
                    );
                }
                if engine_pid != self.engine.pid {
                    return (
                        ExecutorReply::Refused {
                            detail: "the hello names another engine".to_owned(),
                        },
                        true,
                    );
                }
                let executor = ProcessIdentity::holder_of(std::process::id())
                    .ok()
                    .flatten()
                    .unwrap_or(ProcessIdentity {
                        pid: std::process::id(),
                        start_time_ticks: 0,
                    });
                (
                    ExecutorReply::Hello {
                        version: PROTOCOL_VERSION,
                        executor,
                    },
                    false,
                )
            }
            ExecutorRequest::StartRelay { sandbox, routes } => {
                (self.start_relay(sandbox, &routes), false)
            }
            ExecutorRequest::StopRelay { sandbox, reason } => {
                let life = self.hosts.stop(&sandbox, reason).map(|life| life.summary());
                self.hosts.forget_ended();
                (ExecutorReply::RelayStopped { sandbox, life }, false)
            }
            ExecutorRequest::Poll => {
                self.tick();
                let (refusals, refusals_dropped) = self
                    .refusals
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take();
                (
                    ExecutorReply::Ended {
                        lives: std::mem::take(&mut self.ended),
                        refusals,
                        refusals_dropped,
                    },
                    false,
                )
            }
            ExecutorRequest::Status { sandbox } => {
                let relay = self.hosts.status(&sandbox);
                (ExecutorReply::Status { sandbox, relay }, false)
            }
            ExecutorRequest::Enroll {
                name,
                class,
                form,
                mut secret_hex,
            } => {
                let decoded = hex::decode(secret_hex.trim());
                // SAFETY: the bytes are overwritten with ASCII zeros, which keeps the
                // string valid UTF-8.
                wipe(unsafe { secret_hex.as_bytes_mut() });
                let reply = match decoded {
                    Ok(bytes) => match self.vault.enroll(
                        CredentialRef::from_digest(credential_reference(&name)),
                        class,
                        form,
                        SecretValue::new(bytes),
                    ) {
                        Ok(version) => ExecutorReply::Enrolled { name, version },
                        Err(error) => ExecutorReply::Refused {
                            detail: format!("the credential could not be stored: {error}"),
                        },
                    },
                    Err(_) => ExecutorReply::Refused {
                        detail: "the secret is not hex".to_owned(),
                    },
                };
                (reply, false)
            }
            ExecutorRequest::Remove { name } => {
                let reply = match self
                    .vault
                    .remove(CredentialRef::from_digest(credential_reference(&name)))
                {
                    Ok(existed) => ExecutorReply::Removed { name, existed },
                    Err(error) => ExecutorReply::Refused {
                        detail: format!("the credential could not be removed: {error}"),
                    },
                };
                (reply, false)
            }
            ExecutorRequest::Holds { name } => {
                let reply = match self
                    .vault
                    .holds(CredentialRef::from_digest(credential_reference(&name)))
                {
                    Ok(held) => ExecutorReply::Holds { name, held },
                    Err(error) => ExecutorReply::Refused {
                        detail: format!("the store could not be read: {error}"),
                    },
                };
                (reply, false)
            }
            ExecutorRequest::Shutdown => {
                let stopped = self.hosts.stop_all(StopReason::Teardown).len();
                (ExecutorReply::ShuttingDown { stopped }, true)
            }
            #[cfg(feature = "acceptance")]
            ExecutorRequest::MarkNextRefusal { sandbox, route } => {
                if crate::acceptance::data_directory().is_none() {
                    return (
                        ExecutorReply::Refused {
                            detail: "only a disposable acceptance engine's executor keeps marks"
                                .to_owned(),
                        },
                        false,
                    );
                }
                self.refusals
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .mark(sandbox.clone(), route.clone());
                (ExecutorReply::Marked { sandbox, route }, false)
            }
        }
    }

    /// Builds `sandbox`'s broker from `routes` and starts its relay (module notes).
    fn start_relay(&mut self, sandbox: ExecutionId, routes: &[RouteDeclaration]) -> ExecutorReply {
        let now = self.clock.now();
        let (owned, inventory) = host_addresses_and_report();
        // Every refused exchange of this relay is reported to the engine at its next poll.
        let observer: ExchangeObserver = {
            let refusals = Arc::clone(&self.refusals);
            let sandbox = sandbox.clone();
            Arc::new(move |record: &ExchangeRecord| {
                if let Some(refused) = refused_exchange(&sandbox, record) {
                    refusals
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push(refused);
                }
            })
        };
        let built = match build_broker(
            routes,
            &self.tenant,
            self.store.clone(),
            self.session,
            self.clock,
            Arc::new(self.clock) as Arc<dyn Clock>,
            now,
            &owned,
            Some(observer),
        ) {
            Ok(built) => built,
            Err(error) => {
                return ExecutorReply::Refused {
                    detail: error.to_string(),
                }
            }
        };
        if let Err(error) =
            self.hosts
                .start(sandbox.clone(), &built.routes, built.limits, built.broker)
        {
            return ExecutorReply::Refused {
                detail: error.to_string(),
            };
        }
        let facts = self.hosts.facts(&sandbox);
        let (relay, container_sid, guest_pipe) = match facts {
            Some(facts) => match (facts.identity, facts.container_sid, facts.guest_pipe) {
                (Some(identity), Some(sid), Some(pipe)) => (identity, hex::encode(sid), pipe),
                _ => {
                    self.hosts.stop(&sandbox, StopReason::Teardown);
                    return ExecutorReply::Refused {
                        detail:
                            "the relay started without an identity, a container or a guest pipe"
                                .to_owned(),
                    };
                }
            },
            None => {
                // It ended between the start and this look; its life says why.
                let life = self.hosts.status(&sandbox);
                return ExecutorReply::Refused {
                    detail: format!("the relay ended at once: {life:?}"),
                };
            }
        };
        ExecutorReply::RelayStarted {
            sandbox,
            relay,
            container_sid,
            guest_pipe,
            credentialed_routes: built
                .credentialed_routes
                .iter()
                .map(|route| route.as_str().to_owned())
                .collect(),
            host_addresses: owned.len(),
            host_inventory_error: inventory.err(),
        }
    }
}

/// This host's own addresses, which no route may reach: the loopback addresses and every
/// IPv4 address of the host's interfaces now (`runtime::host_ipv4_addresses`, the same
/// inventory the microVM network judges flows against), with the inventory's word:
/// `Ok(count)` of interface addresses, or the error that left only the loopback addresses
/// (the broker's own address classes still refuse the private ranges for resolved names,
/// and the relay's start reports the gap). The destination broker refuses loopback,
/// link-local, metadata and multicast space by class on top.
pub fn host_addresses_and_report() -> (Vec<IpAddr>, Result<usize, String>) {
    let mut addresses = vec![
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ];
    match crate::runtime::host_ipv4_addresses() {
        Ok(inventory) => {
            let count = inventory.len();
            let mut owned: Vec<IpAddr> = inventory
                .into_iter()
                .map(|octets| IpAddr::V4(Ipv4Addr::from(octets)))
                .collect();
            owned.sort();
            let new: Vec<IpAddr> = owned
                .into_iter()
                .filter(|address| !addresses.contains(address))
                .collect();
            addresses.extend(new);
            (addresses, Ok(count))
        }
        Err(error) => (addresses, Err(error)),
    }
}

/// Whether this executor may start: a product build always may; an acceptance build only
/// with its disposable engine's data folder, which sets its vault service apart.
fn may_start() -> bool {
    !cfg!(feature = "acceptance") || crate::acceptance::data_directory().is_some()
}

/// What the engine is told of one exchange record of `sandbox`'s relay: nothing for an
/// answered exchange; for a refused one its route, number, class and the broker's statement
/// (bounded; no request or response byte and no credential, which no refusal states).
pub fn refused_exchange(sandbox: &ExecutionId, record: &ExchangeRecord) -> Option<RefusedExchange> {
    let ExchangeOutcome::Refused(refusal) = &record.outcome else {
        return None;
    };
    let class = match classify_broker_refusal(refusal) {
        BrokerRefusalClass::Violation(violation) => RefusalClass::Violation {
            kind: violation.kind(),
            observer: violation.observer(),
        },
        BrokerRefusalClass::RelayProtocol => RefusalClass::RelayProtocol,
        BrokerRefusalClass::Ordinary(reason) => RefusalClass::Ordinary {
            reason: reason.label().to_owned(),
        },
    };
    Some(RefusedExchange {
        sandbox: sandbox.clone(),
        route: record.route.as_str().to_owned(),
        exchange: record.exchange.get(),
        class,
        detail: bounded_detail(&refusal.to_string()),
    })
}

/// `text` cut to [`MAX_REFUSAL_DETAIL_BYTES`] at a character boundary, marked when cut.
pub fn bounded_detail(text: &str) -> String {
    if text.len() <= MAX_REFUSAL_DETAIL_BYTES {
        return text.to_owned();
    }
    let mut end = MAX_REFUSAL_DETAIL_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

/// The refused exchanges of the executor's relays not yet polled. Bounded at
/// [`MAX_PENDING_REFUSALS`]: past it an ordinary refusal is dropped and a violation or a
/// relay protocol fault displaces the oldest ordinary one (every drop is counted and told
/// at the next poll); a poll takes at most [`MAX_REFUSALS_PER_POLL`], oldest first.
#[derive(Debug, Default)]
pub struct Refusals {
    pending: VecDeque<RefusedExchange>,
    dropped: u64,
    /// Acceptance builds: the (sandbox, route) pairs whose next refusal reads as a
    /// violation, once.
    #[cfg(feature = "acceptance")]
    marks: BTreeSet<(ExecutionId, String)>,
}

impl Refusals {
    /// Keeps one refusal (see the type's notes).
    pub fn push(&mut self, refused: RefusedExchange) {
        let refused = self.marked(refused);
        if self.pending.len() < MAX_PENDING_REFUSALS {
            self.pending.push_back(refused);
            return;
        }
        self.dropped = self.dropped.saturating_add(1);
        if matches!(refused.class, RefusalClass::Ordinary { .. }) {
            return;
        }
        if let Some(index) = self
            .pending
            .iter()
            .position(|held| matches!(held.class, RefusalClass::Ordinary { .. }))
        {
            self.pending.remove(index);
            self.pending.push_back(refused);
        }
    }

    /// The oldest refusals, at most [`MAX_REFUSALS_PER_POLL`], and the count dropped since
    /// the last take.
    pub fn take(&mut self) -> (Vec<RefusedExchange>, u64) {
        let count = self.pending.len().min(MAX_REFUSALS_PER_POLL);
        (
            self.pending.drain(..count).collect(),
            std::mem::take(&mut self.dropped),
        )
    }

    /// Acceptance builds: the next refusal on `route` of `sandbox` reads as a perimeter
    /// violation.
    #[cfg(feature = "acceptance")]
    pub fn mark(&mut self, sandbox: ExecutionId, route: String) {
        self.marks.insert((sandbox, route));
    }

    #[cfg(feature = "acceptance")]
    fn marked(&mut self, refused: RefusedExchange) -> RefusedExchange {
        if !self
            .marks
            .remove(&(refused.sandbox.clone(), refused.route.clone()))
        {
            return refused;
        }
        RefusedExchange {
            class: RefusalClass::Violation {
                kind: ViolationKind::PerimeterRule,
                observer: HostObserver::Perimeter,
            },
            detail: bounded_detail(&format!(
                "acceptance mark; the broker's own refusal: {}",
                refused.detail
            )),
            ..refused
        }
    }

    #[cfg(not(feature = "acceptance"))]
    fn marked(&mut self, refused: RefusedExchange) -> RefusedExchange {
        refused
    }
}
