//! The control channel to the supervisor, with capacity reserved for revocation (S2
//! CORE-04; VM part §6.4: "Reserve CPU/memory and an IPC path for revocation under resource
//! exhaustion" and "bounded lifecycle messages"; §8.2: never block the revocation channel;
//! VM-W26: overload cases; docs/combined-plan-remaining-only.md §8, S04 / M13 / M17:
//! "reserve the resources and IPC needed for revocation under overload").
//!
//! Lifecycle messages to the supervisor share one bounded channel. Ordinary messages fill
//! at most `ordinary_capacity` places and are refused beyond it, so the sender sees the
//! overload and backs off. A revocation never takes one of those places: every execution
//! the supervisor admits holds one revocation slot, reserved with its admission
//! ([`ControlChannel::reserve`]) and refused when no slot is left, so the admission is
//! refused instead. The slot's memory, room for `grants_per_slot` grant revocations
//! included, is taken at reservation, so queueing a revocation allocates nothing and never
//! waits: under any load of ordinary messages, and whatever the host's ledger has left,
//! a revocation of an admitted execution is queued at once and drained before every
//! ordinary message.
//!
//! A slot holds at most one pending revocation per execution, so revocations coalesce: the
//! same grant revoked twice is queued once, and a revocation of the whole execution
//! subsumes its grant revocations and supersedes the ordinary messages still queued for it,
//! which would be refused anyway. Grant revocations beyond the slot's room widen to the
//! whole execution (fail closed), so a revocation is never refused for want of room. The
//! supervisor that drains the channel applies each revocation through the coordinator
//! ([`Coordinator::revoke`](super::Coordinator::revoke),
//! [`Coordinator::revoke_grant`](super::Coordinator::revoke_grant)), which needs no
//! reservation from the ledger.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::foundation::ids::{ExecutionId, GrantId, OperationId};

/// The bounds of a control channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlConfig {
    /// Ordinary messages queued at most.
    pub ordinary_capacity: usize,
    /// Executions with a revocation slot at most: the supervisor admits no more.
    pub revocation_slots: usize,
    /// Grant revocations one slot holds before they widen to the whole execution.
    pub grants_per_slot: usize,
}

impl ControlConfig {
    /// Refuses a zero bound.
    pub fn validate(&self) -> Result<(), ControlConfigError> {
        for (setting, value) in [
            ("ordinary_capacity", self.ordinary_capacity),
            ("revocation_slots", self.revocation_slots),
            ("grants_per_slot", self.grants_per_slot),
        ] {
            if value == 0 {
                return Err(ControlConfigError::Zero { setting });
            }
        }
        Ok(())
    }
}

/// Why a control channel configuration was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum ControlConfigError {
    Zero { setting: &'static str },
}

impl fmt::Display for ControlConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero { setting } => write!(f, "{setting} must be above zero"),
        }
    }
}

impl std::error::Error for ControlConfigError {}

/// A revocation sent to the supervisor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "revoke", rename_all = "snake_case", deny_unknown_fields)]
#[serde(remote = "Self")]
pub enum RevocationRequest {
    /// The whole execution, under `operation`.
    Execution { operation: OperationId },
    /// One grant under the execution, under `operation`.
    Grant {
        grant: GrantId,
        operation: OperationId,
    },
}

crate::foundation::strict_serde::strict_tag!(RevocationRequest, "revoke");

/// How a revocation was queued.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationQueued {
    /// It takes its own place in the execution's slot.
    Queued,
    /// What is already pending covers it.
    Coalesced,
    /// The slot's room for grant revocations was full: the whole execution is revoked.
    Widened,
}

/// The revocation pending for one execution, as the supervisor drains it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PendingRevocation {
    pub execution: ExecutionId,
    /// The whole execution is revoked, under this operation; it subsumes every grant
    /// revocation.
    pub whole: Option<OperationId>,
    /// Single grants revoked, each under its operation, when the whole execution is not.
    pub grants: Vec<(GrantId, OperationId)>,
    /// Grant revocations overflowed the slot and widened to the whole execution.
    pub widened: bool,
}

/// One item drained from the channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlItem<M> {
    Revocation(PendingRevocation),
    Message { execution: ExecutionId, message: M },
}

/// Why the channel refused a call.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum ControlRefusal {
    /// The ordinary messages fill their places: back off and send again later.
    Overloaded { capacity: usize },
    /// The execution is being revoked; no ordinary message for it is queued.
    Revoking { execution: ExecutionId },
    /// Every revocation slot is reserved: the execution is not admitted.
    SlotsExhausted { slots: usize },
    /// The execution holds no revocation slot, so the supervisor never admitted it.
    NoRevocationSlot { execution: ExecutionId },
    /// The slot still holds a pending revocation.
    SlotPending { execution: ExecutionId },
}

impl fmt::Display for ControlRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Overloaded { capacity } => write!(
                f,
                "the control channel holds its {capacity} ordinary messages; send again later"
            ),
            Self::Revoking { execution } => {
                write!(
                    f,
                    "{execution} is being revoked; no message for it is queued"
                )
            }
            Self::SlotsExhausted { slots } => write!(
                f,
                "all {slots} revocation slots are reserved; no further execution is admitted"
            ),
            Self::NoRevocationSlot { execution } => {
                write!(f, "{execution} holds no revocation slot")
            }
            Self::SlotPending { execution } => {
                write!(f, "a revocation of {execution} is still pending")
            }
        }
    }
}

impl std::error::Error for ControlRefusal {}

/// What the channel did so far.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ControlTotals {
    pub ordinary_queued: u64,
    pub ordinary_refused: u64,
    /// Ordinary messages dropped because their execution's revocation came first.
    pub superseded: u64,
    pub revocations_queued: u64,
    pub revocations_coalesced: u64,
    pub revocations_widened: u64,
}

/// One execution's reserved revocation slot.
#[derive(Debug)]
struct Slot {
    execution: ExecutionId,
    /// When its pending revocation arrived; `None` when none is pending.
    arrival: Option<u64>,
    whole: Option<OperationId>,
    /// Holds room for `grants_per_slot` entries from the reservation on.
    grants: Vec<(GrantId, OperationId)>,
    widened: bool,
}

/// The bounded control channel to the supervisor, with a revocation slot reserved per
/// admitted execution (VM part §6.4).
#[derive(Debug)]
pub struct ControlChannel<M> {
    config: ControlConfig,
    ordinary: VecDeque<(ExecutionId, M)>,
    slots: Vec<Slot>,
    index: BTreeMap<ExecutionId, usize>,
    next_arrival: u64,
    totals: ControlTotals,
}

impl<M> ControlChannel<M> {
    /// A channel with `config`'s bounds, its ordinary places and slot table allocated now.
    pub fn new(config: ControlConfig) -> Result<Self, ControlConfigError> {
        config.validate()?;
        Ok(Self {
            config,
            ordinary: VecDeque::with_capacity(config.ordinary_capacity),
            slots: Vec::with_capacity(config.revocation_slots),
            index: BTreeMap::new(),
            next_arrival: 0,
            totals: ControlTotals::default(),
        })
    }

    pub fn config(&self) -> ControlConfig {
        self.config
    }

    /// What the channel did so far.
    pub fn totals(&self) -> ControlTotals {
        self.totals
    }

    /// Ordinary messages queued now.
    pub fn ordinary_len(&self) -> usize {
        self.ordinary.len()
    }

    /// Executions with a revocation pending now.
    pub fn pending_revocations(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.arrival.is_some())
            .count()
    }

    /// Whether `execution` holds a revocation slot.
    pub fn is_reserved(&self, execution: &ExecutionId) -> bool {
        self.index.contains_key(execution)
    }

    /// Reserves `execution`'s revocation slot with its admission, before anything of it
    /// starts; reserving again changes nothing. Refused when every slot is reserved: then
    /// the execution must not be admitted.
    pub fn reserve(&mut self, execution: &ExecutionId) -> Result<(), ControlRefusal> {
        if self.index.contains_key(execution) {
            return Ok(());
        }
        if self.slots.len() >= self.config.revocation_slots {
            return Err(ControlRefusal::SlotsExhausted {
                slots: self.config.revocation_slots,
            });
        }
        self.index.insert(execution.clone(), self.slots.len());
        self.slots.push(Slot {
            execution: execution.clone(),
            arrival: None,
            whole: None,
            grants: Vec::with_capacity(self.config.grants_per_slot),
            widened: false,
        });
        Ok(())
    }

    /// Gives `execution`'s slot back once it has ended for good, such as at its
    /// retirement. Refused while a revocation of it is pending.
    pub fn release(&mut self, execution: &ExecutionId) -> Result<(), ControlRefusal> {
        let Some(&position) = self.index.get(execution) else {
            return Err(ControlRefusal::NoRevocationSlot {
                execution: execution.clone(),
            });
        };
        if self
            .slots
            .get(position)
            .is_some_and(|slot| slot.arrival.is_some())
        {
            return Err(ControlRefusal::SlotPending {
                execution: execution.clone(),
            });
        }
        self.index.remove(execution);
        self.slots.swap_remove(position);
        if let Some(moved) = self.slots.get(position) {
            self.index.insert(moved.execution.clone(), position);
        }
        Ok(())
    }

    /// Queues an ordinary message for `execution`. Refused when the ordinary places are
    /// full, and while a revocation of the whole execution is pending.
    pub fn send(&mut self, execution: &ExecutionId, message: M) -> Result<(), ControlRefusal> {
        let revoking = self
            .index
            .get(execution)
            .and_then(|position| self.slots.get(*position))
            .is_some_and(|slot| slot.whole.is_some());
        if revoking {
            self.totals.ordinary_refused = self.totals.ordinary_refused.saturating_add(1);
            return Err(ControlRefusal::Revoking {
                execution: execution.clone(),
            });
        }
        if self.ordinary.len() >= self.config.ordinary_capacity {
            self.totals.ordinary_refused = self.totals.ordinary_refused.saturating_add(1);
            return Err(ControlRefusal::Overloaded {
                capacity: self.config.ordinary_capacity,
            });
        }
        self.ordinary.push_back((execution.clone(), message));
        self.totals.ordinary_queued = self.totals.ordinary_queued.saturating_add(1);
        Ok(())
    }

    /// Queues a revocation of `execution` in its reserved slot, whatever the ordinary load:
    /// it allocates nothing and is refused only for an execution that holds no slot,
    /// which the supervisor never admitted.
    pub fn revoke(
        &mut self,
        execution: &ExecutionId,
        request: RevocationRequest,
    ) -> Result<RevocationQueued, ControlRefusal> {
        let Some(slot) = self
            .index
            .get(execution)
            .and_then(|position| self.slots.get_mut(*position))
        else {
            return Err(ControlRefusal::NoRevocationSlot {
                execution: execution.clone(),
            });
        };
        if slot.arrival.is_none() {
            slot.arrival = Some(self.next_arrival);
            self.next_arrival = self.next_arrival.saturating_add(1);
        }
        let queued = match request {
            RevocationRequest::Execution { operation } => {
                if slot.whole.is_some() {
                    RevocationQueued::Coalesced
                } else {
                    slot.whole = Some(operation);
                    slot.grants.clear();
                    RevocationQueued::Queued
                }
            }
            RevocationRequest::Grant { grant, operation } => {
                if slot.whole.is_some() || slot.grants.iter().any(|(held, _)| *held == grant) {
                    RevocationQueued::Coalesced
                } else if slot.grants.len() < self.config.grants_per_slot {
                    slot.grants.push((grant, operation));
                    RevocationQueued::Queued
                } else {
                    slot.whole = Some(operation);
                    slot.widened = true;
                    slot.grants.clear();
                    RevocationQueued::Widened
                }
            }
        };
        let whole = slot.whole.is_some();
        let totals = &mut self.totals;
        match queued {
            RevocationQueued::Queued => {
                totals.revocations_queued = totals.revocations_queued.saturating_add(1);
            }
            RevocationQueued::Coalesced => {
                totals.revocations_coalesced = totals.revocations_coalesced.saturating_add(1);
            }
            RevocationQueued::Widened => {
                totals.revocations_widened = totals.revocations_widened.saturating_add(1);
            }
        }
        if whole {
            let before = self.ordinary.len();
            self.ordinary.retain(|(owner, _)| owner != execution);
            let dropped = u64::try_from(before - self.ordinary.len()).unwrap_or(u64::MAX);
            self.totals.superseded = self.totals.superseded.saturating_add(dropped);
        }
        Ok(queued)
    }

    /// The next item: the revocation that arrived first, before every ordinary message;
    /// then the oldest ordinary message. Draining a revocation re-arms its slot, which the
    /// execution keeps.
    pub fn next_item(&mut self) -> Option<ControlItem<M>> {
        let first = self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(position, slot)| slot.arrival.map(|arrival| (arrival, position)))
            .min();
        if let Some((_, position)) = first {
            let room = self.config.grants_per_slot;
            if let Some(slot) = self.slots.get_mut(position) {
                slot.arrival = None;
                let grants = std::mem::replace(&mut slot.grants, Vec::with_capacity(room));
                let pending = PendingRevocation {
                    execution: slot.execution.clone(),
                    whole: slot.whole.take(),
                    grants,
                    widened: std::mem::take(&mut slot.widened),
                };
                return Some(ControlItem::Revocation(pending));
            }
        }
        self.ordinary
            .pop_front()
            .map(|(execution, message)| ControlItem::Message { execution, message })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::digest;

    fn config() -> ControlConfig {
        ControlConfig {
            ordinary_capacity: 2,
            revocation_slots: 2,
            grants_per_slot: 2,
        }
    }

    fn execution(name: &str) -> ExecutionId {
        ExecutionId::new(name).unwrap()
    }

    fn operation(name: &str) -> OperationId {
        OperationId::new(name).unwrap()
    }

    fn grant(name: &str) -> GrantId {
        GrantId::from_digest(digest("yougori/test/grant/v1", &[name.as_bytes()]))
    }

    #[test]
    fn configurations_are_checked() {
        assert_eq!(config().validate(), Ok(()));
        let mut bad = config();
        bad.grants_per_slot = 0;
        assert_eq!(
            bad.validate(),
            Err(ControlConfigError::Zero {
                setting: "grants_per_slot"
            })
        );
        assert!(ControlChannel::<u8>::new(bad).is_err());
    }

    #[test]
    fn admission_reserves_a_slot_and_release_gives_it_back() {
        let mut channel = ControlChannel::<u8>::new(config()).unwrap();
        let (a, b, c) = (execution("exe-a"), execution("exe-b"), execution("exe-c"));
        channel.reserve(&a).unwrap();
        channel.reserve(&a).unwrap();
        channel.reserve(&b).unwrap();
        assert_eq!(
            channel.reserve(&c),
            Err(ControlRefusal::SlotsExhausted { slots: 2 })
        );
        assert_eq!(
            channel.revoke(
                &c,
                RevocationRequest::Execution {
                    operation: operation("op-c")
                }
            ),
            Err(ControlRefusal::NoRevocationSlot {
                execution: c.clone()
            })
        );
        channel
            .revoke(
                &a,
                RevocationRequest::Execution {
                    operation: operation("op-a"),
                },
            )
            .unwrap();
        assert_eq!(
            channel.release(&a),
            Err(ControlRefusal::SlotPending {
                execution: a.clone()
            })
        );
        assert!(matches!(
            channel.next_item(),
            Some(ControlItem::Revocation(_))
        ));
        channel.release(&a).unwrap();
        assert!(!channel.is_reserved(&a));
        assert!(channel.is_reserved(&b));
        channel.reserve(&c).unwrap();
        // b's slot survived a's release and still takes its revocation.
        assert_eq!(
            channel.revoke(
                &b,
                RevocationRequest::Execution {
                    operation: operation("op-b")
                }
            ),
            Ok(RevocationQueued::Queued)
        );
    }

    #[test]
    fn grant_revocations_coalesce_and_widen_and_never_fail() {
        let mut channel = ControlChannel::<u8>::new(config()).unwrap();
        let a = execution("exe-a");
        channel.reserve(&a).unwrap();
        let revoke = |name: &str| RevocationRequest::Grant {
            grant: grant(name),
            operation: operation(&format!("op-{name}")),
        };
        let mut channel_revoke = |request| channel.revoke(&a, request).unwrap();
        assert_eq!(channel_revoke(revoke("one")), RevocationQueued::Queued);
        assert_eq!(channel_revoke(revoke("one")), RevocationQueued::Coalesced);
        assert_eq!(channel_revoke(revoke("two")), RevocationQueued::Queued);
        assert_eq!(channel_revoke(revoke("three")), RevocationQueued::Widened);
        assert_eq!(channel_revoke(revoke("four")), RevocationQueued::Coalesced);
        let Some(ControlItem::Revocation(pending)) = channel.next_item() else {
            panic!("a revocation is pending");
        };
        assert_eq!(pending.whole, Some(operation("op-three")));
        assert!(pending.widened);
        assert!(pending.grants.is_empty());
        assert_eq!(channel.pending_revocations(), 0);
        let totals = channel.totals();
        assert_eq!(
            (
                totals.revocations_queued,
                totals.revocations_coalesced,
                totals.revocations_widened
            ),
            (2, 2, 1)
        );
    }
}
