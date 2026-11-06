//! What the lifetime supervisor decides (module docs in `mod.rs`), apart from the process it
//! runs in and the handles it holds, so every rule is tested without a VM.
//!
//! - **The engine's death** (its process handle signalled) and **its silence** (no request
//!   for the silence bound) count as the engine failing: a task sandbox's VM ends with it,
//!   a service sandbox's continues to its own limits (VM-D7, as
//!   `lifecycle::Supervisor::engine_died` splits the classes). A silent engine that speaks
//!   again is answered again; what ended stays ended.
//! - **The lease backstop.** Every request of the engine carries each held sandbox's lease
//!   terms; the supervisor keeps each limit as a deadline on its own monotonic clock, the
//!   grace added, and ends a VM whose deadline passed: the engine, which revokes at the
//!   limit itself, did not.
//! - **Remote delegation** is an absolute deadline on the same host's boot clock,
//!   converted conservatively to this process's clock. It gets no cleanup grace;
//!   transport, a paused receiver and omitted terms cannot extend it.
//! - **A gap in the supervisor's own ticks** longer than [`TICK_GAP`] means the computer
//!   slept or this process was not run. It is journaled, but never renews authority:
//!   overdue leases and engine silence are enforced on the first resumed tick.
//! - An end is reported only as observed: the VM's process ended and no process is left in
//!   its job. A kill whose end is not observed is tried again at the next tick and listed
//!   as unended meanwhile.

use std::collections::{BTreeMap, VecDeque};
use std::time::Duration;

use crate::foundation::ids::{ExecutionId, MonotonicTime};
use crate::foundation::process::{LifetimeEnded, ProcessIdentity};
use crate::sandbox::lifecycle::SandboxClass;

use super::protocol::{
    EndCause, HeldEnd, SandboxTerms, SupervisorSettings, Terms, MAX_ENDS_PER_REPLY, MAX_HELD,
};

/// A gap longer than this is journaled; it never changes deadlines (module notes).
pub const TICK_GAP: Duration = Duration::from_secs(10);

/// The most ends kept for the engine before the oldest is dropped (the journal keeps all).
const MAX_PENDING_ENDS: usize = 4 * MAX_HELD;

/// A VM as the supervisor holds it.
pub trait Lifetime {
    fn identity(&self) -> ProcessIdentity;
    /// The end, if the host observes it now without waiting.
    fn ended(&self) -> Option<LifetimeEnded>;
    /// Ends it, observing the end within bounded kill rounds, or says why there is no end.
    fn terminate(&self, kill_wait: Duration) -> Result<LifetimeEnded, String>;
}

#[cfg(any(windows, target_os = "linux"))]
impl Lifetime for crate::foundation::process::AdoptedLifetime {
    fn identity(&self) -> ProcessIdentity {
        crate::foundation::process::AdoptedLifetime::identity(self)
    }

    fn ended(&self) -> Option<LifetimeEnded> {
        crate::foundation::process::AdoptedLifetime::ended(self)
    }

    fn terminate(&self, kill_wait: Duration) -> Result<LifetimeEnded, String> {
        crate::foundation::process::AdoptedLifetime::terminate(self, kill_wait)
            .map_err(|no_proof| no_proof.to_string())
    }
}

/// Whether a sandbox of `class` ends when its engine fails (VM-D7: task sandboxes end with
/// the engine; service sandboxes continue under their limits).
pub fn ends_with_engine(class: SandboxClass) -> bool {
    class == SandboxClass::Task
}

/// The engine as the supervisor sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineState {
    Answering,
    /// No request for the silence bound since `since` (the last one heard).
    Silent {
        since: MonotonicTime,
    },
    /// Its process handle was signalled at `at` (as first seen).
    Died {
        at: MonotonicTime,
    },
}

/// A change of the engine's state, for the journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineChange {
    Died,
    Silent {
        quiet_for: Duration,
    },
    AnsweringAgain,
    /// The supervisor's own ticks stopped for this long (module notes).
    Gap {
        gap: Duration,
    },
}

struct Held<L> {
    class: SandboxClass,
    lifetime: L,
    idle_at: MonotonicTime,
    absolute_at: Option<MonotonicTime>,
    renewal_at: Option<MonotonicTime>,
    delegation_at: Option<MonotonicTime>,
    delegation_host_ns: Option<u64>,
    /// An end decided and not yet observed: its cause and when the cause arose.
    ending: Option<(EndCause, MonotonicTime)>,
}

impl<L> Held<L> {
    fn expired(&self, now: MonotonicTime) -> Option<(EndCause, MonotonicTime)> {
        [
            (EndCause::IdleLimit, Some(self.idle_at)),
            (EndCause::AbsoluteLimit, self.absolute_at),
            (EndCause::RenewalLimit, self.renewal_at),
            (EndCause::RenewalLimit, self.delegation_at),
        ]
        .into_iter()
        .filter_map(|(cause, deadline)| deadline.filter(|at| now >= *at).map(|at| (cause, at)))
        .min_by_key(|(_, at)| *at)
    }
}

/// The supervisor's state (module notes).
pub struct Supervision<L> {
    settings: SupervisorSettings,
    started: MonotonicTime,
    held: BTreeMap<ExecutionId, Held<L>>,
    engine: EngineState,
    last_heard: MonotonicTime,
    last_tick: MonotonicTime,
    ends: VecDeque<HeldEnd>,
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

impl<L: Lifetime> Supervision<L> {
    pub fn new(settings: SupervisorSettings, now: MonotonicTime) -> Self {
        Self {
            settings,
            started: now,
            held: BTreeMap::new(),
            engine: EngineState::Answering,
            last_heard: now,
            last_tick: now,
            ends: VecDeque::new(),
        }
    }

    #[cfg(test)]
    pub fn engine(&self) -> EngineState {
        self.engine
    }

    pub fn holding(&self) -> usize {
        self.held.len()
    }

    /// The supervisor's running time at `now`.
    pub fn at_ms(&self, now: MonotonicTime) -> u64 {
        millis(now.saturating_duration_since(self.started))
    }

    fn deadline(&self, now: MonotonicTime, left_ms: u64) -> MonotonicTime {
        let after = Duration::from_millis(left_ms.saturating_add(self.settings.grace_ms));
        now.saturating_add(after)
    }

    fn set_terms(&self, held: &mut Held<L>, terms: Terms, now: MonotonicTime, host_ns: u64) {
        held.idle_at = self.deadline(now, terms.idle_left_ms);
        held.absolute_at = terms.absolute_left_ms.map(|left| self.deadline(now, left));
        held.renewal_at = terms.renewal_left_ms.map(|left| self.deadline(now, left));
        if let Some(deadline) = terms.delegation_deadline_host_ns {
            // `now` was read BEFORE host_ns, so a scheduling delay here can only
            // shorten authority. No relative TTL is started at message receipt.
            held.delegation_at = Some(
                now.checked_add(Duration::from_nanos(deadline.saturating_sub(host_ns)))
                    .unwrap_or(now),
            );
            held.delegation_host_ns = Some(deadline);
        }
        // Omitting the field never removes an already installed deadline.
    }

    /// The engine spoke at `now`: its silence is counted again; a silent engine is answered
    /// again.
    pub fn heard(&mut self, now: MonotonicTime) -> Option<EngineChange> {
        self.last_heard = now;
        match self.engine {
            EngineState::Silent { .. } => {
                self.engine = EngineState::Answering;
                Some(EngineChange::AnsweringAgain)
            }
            _ => None,
        }
    }

    /// Holds `sandbox`'s VM. Refused past [`MAX_HELD`], for a sandbox held already, and
    /// while the engine is counted as failed; a refused lifetime is dropped, closing only the
    /// supervisor's handles.
    pub fn hold(
        &mut self,
        sandbox: ExecutionId,
        class: SandboxClass,
        lifetime: L,
        terms: Terms,
        now: MonotonicTime,
    ) -> Result<usize, String> {
        self.hold_at(
            sandbox,
            class,
            lifetime,
            terms,
            now,
            crate::foundation::elapsed_clock::nanos(),
        )
    }

    fn hold_at(
        &mut self,
        sandbox: ExecutionId,
        class: SandboxClass,
        lifetime: L,
        terms: Terms,
        now: MonotonicTime,
        host_ns: u64,
    ) -> Result<usize, String> {
        if self.engine != EngineState::Answering {
            return Err("the engine is counted as failed".to_owned());
        }
        if self.held.contains_key(&sandbox) {
            return Err(format!("{sandbox} is held already"));
        }
        if self.held.len() >= MAX_HELD {
            return Err(format!("the supervisor holds its most VMs ({MAX_HELD})"));
        }
        let mut held = Held {
            class,
            lifetime,
            idle_at: now,
            absolute_at: None,
            renewal_at: None,
            delegation_at: None,
            delegation_host_ns: None,
            ending: None,
        };
        self.set_terms(&mut held, terms, now, host_ns);
        self.held.insert(sandbox, held);
        Ok(self.held.len())
    }

    /// The engine's terms for the held sandboxes at `now`; a held sandbox they leave out
    /// keeps its deadlines.
    pub fn leases(&mut self, terms: &[SandboxTerms], now: MonotonicTime) {
        self.leases_at(terms, now, crate::foundation::elapsed_clock::nanos());
    }

    fn leases_at(&mut self, terms: &[SandboxTerms], now: MonotonicTime, host_ns: u64) {
        for each in terms {
            if let Some(mut held) = self.held.remove(&each.sandbox) {
                // A delayed renewal cannot revive a lease already past its backstop,
                // even if this API is called before the next periodic tick.
                if held.ending.is_none() {
                    held.ending = held.expired(now);
                    // The process could have paused after reading `now` and
                    // before this message. Check the old host deadline too,
                    // before any replacement can be installed.
                    if held.ending.is_none()
                        && held.delegation_host_ns.is_some_and(|at| host_ns >= at)
                    {
                        held.ending =
                            Some((EndCause::RenewalLimit, held.delegation_at.unwrap_or(now)));
                    }
                }
                if held.ending.is_none() {
                    let absolute = held.absolute_at;
                    self.set_terms(&mut held, each.terms, now, host_ns);
                    // Absolute lifetime is not renewable. Transport delay and a missing
                    // field may not push it later or remove it.
                    if let Some(previous) = absolute {
                        held.absolute_at =
                            Some(held.absolute_at.map_or(previous, |new| previous.min(new)));
                    }
                }
                self.held.insert(each.sandbox.clone(), held);
            }
        }
    }

    /// Lets `sandbox` go; its end when the VM was seen ended first.
    pub fn release(&mut self, sandbox: &ExecutionId, now: MonotonicTime) -> Option<HeldEnd> {
        let held = self.held.remove(sandbox)?;
        let ended = held.lifetime.ended()?;
        Some(HeldEnd::observed(
            sandbox.clone(),
            held.lifetime.identity(),
            EndCause::EndedWithoutSupervisor,
            None,
            ended,
            self.at_ms(now),
        ))
    }

    /// Lets every VM go (an orderly end of the engine); how many.
    pub fn release_all(&mut self) -> usize {
        let count = self.held.len();
        self.held.clear();
        count
    }

    /// The ends not reported yet, oldest first, at most [`MAX_ENDS_PER_REPLY`].
    pub fn take_ends(&mut self) -> Vec<HeldEnd> {
        let count = self.ends.len().min(MAX_ENDS_PER_REPLY);
        self.ends.drain(..count).collect()
    }

    /// The VMs whose end was decided and not yet observed.
    pub fn unended(&self) -> Vec<ExecutionId> {
        self.held
            .iter()
            .filter(|(_, held)| held.ending.is_some())
            .map(|(sandbox, _)| sandbox.clone())
            .collect()
    }

    /// Whether nothing is left to do: the engine died and no VM is held.
    pub fn finished(&self) -> bool {
        matches!(self.engine, EngineState::Died { .. }) && self.held.is_empty()
    }

    /// Applies the rules at `now` (module notes), `engine_alive` being whether the engine's
    /// process handle is still unsignalled. Returns what changed of the engine and the ends
    /// observed in this tick (also kept for the engine's next reply).
    pub fn tick(
        &mut self,
        now: MonotonicTime,
        engine_alive: bool,
    ) -> (Vec<EngineChange>, Vec<HeldEnd>) {
        let mut changes = Vec::new();
        let gap = now.saturating_duration_since(self.last_tick);
        self.last_tick = now;
        if gap > TICK_GAP {
            changes.push(EngineChange::Gap { gap });
        }
        match self.engine {
            EngineState::Died { .. } => {}
            _ if !engine_alive => {
                self.engine = EngineState::Died { at: now };
                changes.push(EngineChange::Died);
            }
            EngineState::Answering => {
                let quiet = now.saturating_duration_since(self.last_heard);
                if quiet >= Duration::from_millis(self.settings.silence_ms) {
                    self.engine = EngineState::Silent {
                        since: self.last_heard,
                    };
                    changes.push(EngineChange::Silent { quiet_for: quiet });
                }
            }
            EngineState::Silent { .. } => {}
        }
        let silence = Duration::from_millis(self.settings.silence_ms);
        let kill_wait = Duration::from_millis(self.settings.kill_wait_ms);
        let mut ends = Vec::new();
        let sandboxes: Vec<ExecutionId> = self.held.keys().cloned().collect();
        for sandbox in sandboxes {
            let Some(held) = self.held.get_mut(&sandbox) else {
                continue;
            };
            if held.ending.is_none() {
                held.ending = match self.engine {
                    EngineState::Died { at } if ends_with_engine(held.class) => {
                        Some((EndCause::EngineDied, at))
                    }
                    EngineState::Silent { since } if ends_with_engine(held.class) => {
                        Some((EndCause::EngineSilent, since.saturating_add(silence)))
                    }
                    _ => held.expired(now),
                };
            }
            let observed = match held.ending {
                Some((cause, arose)) => held.lifetime.terminate(kill_wait).ok().map(|ended| {
                    (
                        cause,
                        Some(millis(now.saturating_duration_since(arose))),
                        ended,
                    )
                }),
                None => held
                    .lifetime
                    .ended()
                    .map(|ended| (EndCause::EndedWithoutSupervisor, None, ended)),
            };
            if let Some((cause, decided_after_ms, ended)) = observed {
                let process = held.lifetime.identity();
                self.held.remove(&sandbox);
                let end = HeldEnd::observed(
                    sandbox,
                    process,
                    cause,
                    decided_after_ms,
                    ended,
                    self.at_ms(now),
                );
                ends.push(end.clone());
                self.ends.push_back(end);
                while self.ends.len() > MAX_PENDING_ENDS {
                    self.ends.pop_front();
                }
            }
        }
        (changes, ends)
    }
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;
