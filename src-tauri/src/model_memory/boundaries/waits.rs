//! First-in-first-out waits for capacity inside one activation (G06 of
//! docs/combined-plan-leftover-tasks.md: "a FIFO for KV waits" and "a FIFO for waiting
//! attaches"; GPU-W10 of docs/combined-gpu-memory-and-vm-sandbox-plan.md, line 1305:
//! "backend-supported dynamic KV growth and admission limits"; S10 line 179: bounded
//! queueing).
//!
//! Two things wait inside one serving activation rather than in the CORE-03 ledger's
//! queue: a request's KV, for room in the activation's KV pool ([`super::KvSpec`]), and an
//! unmerged adapter, for a slot and bytes under the backend's adapter limits
//! (`model_memory::adapters::active`). Both are retried by their caller once something is
//! released, so the order of the retries decides who gets what is freed. A
//! [`WaitQueue`] keeps that order:
//!
//! - whoever must wait joins at the back and keeps its place while it asks again;
//! - a later arrival is admitted only from what every waiter ahead of it leaves: the whole
//!   demand of each one ahead counts as taken, so a later, smaller request may backfill
//!   but never makes an earlier waiter's shortfall larger or its wait longer;
//! - the queue is bounded: at most [`WaitLimits::max_waiters`] wait, and a place is kept
//!   at most [`WaitLimits::max_wait`] after joining; an expired waiter that asks again
//!   joins at the back.
//!
//! The queue holds no capacity itself; the pool and the adapter registry admit, and the
//! ledger reserves. Pure and synchronous: time is passed in from the shared clock.

use std::collections::VecDeque;
use std::time::Duration;

use crate::foundation::ids::MonotonicTime;

/// How many may wait, and for how long each keeps its place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaitLimits {
    /// The most waiters at once; one more is refused rather than queued.
    pub max_waiters: usize,
    /// How long after joining a waiter keeps its place.
    pub max_wait: Duration,
}

impl WaitLimits {
    /// 64 waiters, each keeping its place for one minute.
    pub const DEFAULT: Self = Self {
        max_waiters: 64,
        max_wait: Duration::from_secs(60),
    };
}

impl Default for WaitLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// What a waiter needs, or what is free: bytes, and the slots an adapter takes. A KV
/// request needs no slot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct WaitDemand {
    pub bytes: u64,
    pub slots: u32,
}

impl WaitDemand {
    /// `bytes` and no slot.
    pub const fn bytes(bytes: u64) -> Self {
        Self { bytes, slots: 0 }
    }

    /// Whether `self` fits in `free`.
    pub fn fits_in(self, free: Self) -> bool {
        self.bytes <= free.bytes && self.slots <= free.slots
    }

    /// `self` and `other` together; `None` past 64 bits of bytes or 32 bits of slots.
    pub fn checked_add(self, other: Self) -> Option<Self> {
        Some(Self {
            bytes: self.bytes.checked_add(other.bytes)?,
            slots: self.slots.checked_add(other.slots)?,
        })
    }

    fn saturating_add(self, other: Self) -> Self {
        Self {
            bytes: self.bytes.saturating_add(other.bytes),
            slots: self.slots.saturating_add(other.slots),
        }
    }
}

/// One waiter, as the queue keeps it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Waiter<K> {
    pub key: K,
    /// What it asked for when it last asked.
    pub demand: WaitDemand,
    /// When it joined the queue.
    pub since: MonotonicTime,
}

/// Whether one asking may take what it needs now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitTurn {
    /// It may: what it needs fits in what the waiters ahead of it leave. It keeps its place
    /// until the caller admits it ([`WaitQueue::leave`]).
    Admit,
    /// It waits in the queue, behind `ahead` waiters whose demands claim `claimed`.
    /// `fits_now` says that what it needs is free, but taken by those ahead.
    Wait {
        ahead: usize,
        claimed: WaitDemand,
        fits_now: bool,
    },
    /// It would wait, but `waiting` already wait, the most the queue holds.
    Full { waiting: usize },
}

/// A bounded first-in-first-out queue of waiters, by key: a request's operation for KV,
/// an adapter's identity for attaches. See the module documentation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WaitQueue<K> {
    limits: WaitLimits,
    entries: VecDeque<Waiter<K>>,
}

impl<K: Clone + PartialEq> WaitQueue<K> {
    /// An empty queue under `limits`.
    pub fn new(limits: WaitLimits) -> Self {
        Self {
            limits,
            entries: VecDeque::new(),
        }
    }

    pub fn limits(&self) -> WaitLimits {
        self.limits
    }

    /// Changes the limits; waiters already in the queue keep their places, and the new
    /// bound applies to those who join from now on.
    pub fn set_limits(&mut self, limits: WaitLimits) {
        self.limits = limits;
    }

    /// The waiters, first in line first.
    pub fn waiters(&self) -> impl Iterator<Item = &Waiter<K>> {
        self.entries.iter()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// How many wait ahead of `key`, if it waits.
    pub fn position(&self, key: &K) -> Option<usize> {
        self.entries.iter().position(|waiter| waiter.key == *key)
    }

    /// Drops every waiter whose place expired by `now`, and returns them.
    pub fn expire(&mut self, now: MonotonicTime) -> Vec<Waiter<K>> {
        let max_wait = self.limits.max_wait;
        let mut expired = Vec::new();
        self.entries.retain(|waiter| {
            let kept = now < waiter.since.saturating_add(max_wait);
            if !kept {
                expired.push(waiter.clone());
            }
            kept
        });
        expired
    }

    /// Whether `key`, needing `demand`, may take it now out of `free`, at `now`. Expired
    /// places are dropped first. A waiter, or a new arrival, is admitted when `demand`
    /// fits in what the waiters ahead of it leave of `free`; otherwise it keeps or takes
    /// its place at the back, with `demand` as what it now needs.
    pub fn turn(
        &mut self,
        key: &K,
        demand: WaitDemand,
        free: WaitDemand,
        now: MonotonicTime,
    ) -> WaitTurn {
        self.expire(now);
        let position = self.position(key);
        let ahead = position.unwrap_or(self.entries.len());
        let claimed = self
            .entries
            .iter()
            .take(ahead)
            .fold(WaitDemand::default(), |total, waiter| {
                total.saturating_add(waiter.demand)
            });
        let fits_behind = claimed
            .checked_add(demand)
            .is_some_and(|wanted| wanted.fits_in(free));
        if fits_behind {
            return WaitTurn::Admit;
        }
        let waiting = self.entries.len();
        match position.and_then(|index| self.entries.get_mut(index)) {
            Some(waiter) => waiter.demand = demand,
            None if waiting >= self.limits.max_waiters => return WaitTurn::Full { waiting },
            None => self.entries.push_back(Waiter {
                key: key.clone(),
                demand,
                since: now,
            }),
        }
        WaitTurn::Wait {
            ahead,
            claimed,
            fits_now: demand.fits_in(free),
        }
    }

    /// `key` was admitted, refused for good or gave up: it leaves the queue, and those
    /// behind it move up. Returns its entry, if it waited.
    pub fn leave(&mut self, key: &K) -> Option<Waiter<K>> {
        let index = self.position(key)?;
        self.entries.remove(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: u64) -> MonotonicTime {
        MonotonicTime::from_nanos(seconds * 1_000_000_000)
    }

    #[test]
    fn a_later_arrival_never_takes_what_an_earlier_waiter_needs() {
        let mut queue = WaitQueue::new(WaitLimits::DEFAULT);
        let free = WaitDemand::bytes(100);
        // The first fits and is admitted without queueing.
        assert_eq!(
            queue.turn(&"a", WaitDemand::bytes(60), free, at(0)),
            WaitTurn::Admit
        );
        assert!(queue.is_empty());
        // With 40 free, b needs 80 and waits; c needs 30, which fits, but b claims it.
        let free = WaitDemand::bytes(40);
        assert_eq!(
            queue.turn(&"b", WaitDemand::bytes(80), free, at(1)),
            WaitTurn::Wait {
                ahead: 0,
                claimed: WaitDemand::default(),
                fits_now: false,
            }
        );
        assert_eq!(
            queue.turn(&"c", WaitDemand::bytes(30), free, at(2)),
            WaitTurn::Wait {
                ahead: 1,
                claimed: WaitDemand::bytes(80),
                fits_now: true,
            }
        );
        // Once 120 are free, c may backfill from what b leaves; b is still first in line.
        let free = WaitDemand::bytes(120);
        assert_eq!(
            queue.turn(&"c", WaitDemand::bytes(30), free, at(3)),
            WaitTurn::Admit
        );
        assert_eq!(queue.leave(&"c").map(|waiter| waiter.since), Some(at(2)));
        assert_eq!(
            queue.turn(&"b", WaitDemand::bytes(80), WaitDemand::bytes(90), at(4)),
            WaitTurn::Admit
        );
        queue.leave(&"b");
        assert!(queue.is_empty());
    }

    #[test]
    fn slots_are_claimed_like_bytes() {
        let mut queue = WaitQueue::new(WaitLimits::DEFAULT);
        let one = WaitDemand {
            bytes: 10,
            slots: 1,
        };
        let full = WaitDemand {
            bytes: 100,
            slots: 0,
        };
        assert!(matches!(
            queue.turn(&"x", one, full, at(0)),
            WaitTurn::Wait {
                fits_now: false,
                ..
            }
        ));
        // One slot frees: the first waiter takes it, the second still waits.
        let one_slot = WaitDemand {
            bytes: 100,
            slots: 1,
        };
        assert!(matches!(
            queue.turn(&"y", one, one_slot, at(1)),
            WaitTurn::Wait {
                ahead: 1,
                fits_now: true,
                ..
            }
        ));
        assert_eq!(queue.turn(&"x", one, one_slot, at(2)), WaitTurn::Admit);
        queue.leave(&"x");
        assert_eq!(queue.position(&"y"), Some(0));
    }

    #[test]
    fn the_queue_is_bounded_in_length_and_in_time() {
        let mut queue = WaitQueue::new(WaitLimits {
            max_waiters: 2,
            max_wait: Duration::from_secs(10),
        });
        let none = WaitDemand::default();
        let need = WaitDemand::bytes(1);
        queue.turn(&1, need, none, at(0));
        queue.turn(&2, need, none, at(5));
        assert_eq!(
            queue.turn(&3, need, none, at(6)),
            WaitTurn::Full { waiting: 2 }
        );
        // Asking again keeps a place and updates what it needs.
        queue.turn(&1, WaitDemand::bytes(7), none, at(9));
        assert_eq!(queue.waiters().next().map(|w| w.demand.bytes), Some(7));
        // The first place expires ten seconds after joining; asking again joins at the back.
        let expired = queue.expire(at(10));
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].key, 1);
        assert!(matches!(
            queue.turn(&1, need, none, at(11)),
            WaitTurn::Wait { ahead: 1, .. }
        ));
        assert_eq!(queue.position(&2), Some(0));
        assert_eq!(queue.leave(&4), None);
        queue.set_limits(WaitLimits {
            max_waiters: 0,
            max_wait: Duration::from_secs(10),
        });
        assert_eq!(
            queue.turn(&5, need, none, at(12)),
            WaitTurn::Full { waiting: 2 }
        );
        assert_eq!(queue.limits().max_waiters, 0);
    }

    #[test]
    fn demands_that_overflow_never_fit() {
        let mut queue = WaitQueue::new(WaitLimits::DEFAULT);
        let all = WaitDemand {
            bytes: u64::MAX,
            slots: u32::MAX,
        };
        queue.turn(&"big", all, WaitDemand::default(), at(0));
        assert!(matches!(
            queue.turn(&"small", WaitDemand::bytes(1), all, at(1)),
            WaitTurn::Wait { fits_now: true, .. }
        ));
        assert_eq!(WaitDemand::bytes(1).checked_add(all), None);
    }
}
