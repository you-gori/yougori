//! Bounded staging pools (§3.5 steps 2 and 8; GPU-W04 capped staging rings).
//!
//! A slot is held by the batch that took it and by every consumer whose completion
//! event has not been observed. It returns to the pool only when the last holder lets
//! go, so a buffer is never recycled after merely enqueueing its consumers.

use serde::{Deserialize, Serialize};

use super::backend::StagingBuffer;
use super::model::StagingPlace;
use super::ports::ReservationId;

/// How a staging pool is used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StagingUsage {
    pub slots: u32,
    pub slot_bytes: u64,
    pub in_use: u32,
    /// The most slots ever in use at once.
    pub peak_in_use: u32,
}

/// The holder count of a slot was not what the executor's bookkeeping expects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct NotHeld;

pub(super) struct StagingPool {
    place: StagingPlace,
    slot_bytes: u64,
    holders: Vec<u32>,
    reservation: ReservationId,
    peak_in_use: u32,
}

impl StagingPool {
    pub(super) fn new(
        place: StagingPlace,
        slots: u32,
        slot_bytes: u64,
        reservation: ReservationId,
    ) -> Self {
        Self {
            place,
            slot_bytes,
            holders: vec![0; slots as usize],
            reservation,
            peak_in_use: 0,
        }
    }

    pub(super) fn slot_bytes(&self) -> u64 {
        self.slot_bytes
    }

    pub(super) fn slots(&self) -> u32 {
        u32::try_from(self.holders.len()).unwrap_or(u32::MAX)
    }

    pub(super) fn reservation(&self) -> ReservationId {
        self.reservation
    }

    pub(super) fn in_use(&self) -> u32 {
        u32::try_from(self.holders.iter().filter(|holders| **holders > 0).count())
            .unwrap_or(u32::MAX)
    }

    pub(super) fn free(&self) -> u32 {
        self.slots().saturating_sub(self.in_use())
    }

    pub(super) fn usage(&self) -> StagingUsage {
        StagingUsage {
            slots: self.slots(),
            slot_bytes: self.slot_bytes,
            in_use: self.in_use(),
            peak_in_use: self.peak_in_use,
        }
    }

    /// Takes a free slot; the taker holds it until it lets go.
    pub(super) fn acquire(&mut self) -> Option<StagingBuffer> {
        let index = self.holders.iter().position(|holders| *holders == 0)?;
        let slot = u32::try_from(index).ok()?;
        *self.holders.get_mut(index)? = 1;
        self.peak_in_use = self.peak_in_use.max(self.in_use());
        Some(StagingBuffer {
            place: self.place,
            slot,
        })
    }

    /// Adds a holder to a held slot: a consumer whose completion is not yet observed.
    pub(super) fn hold(&mut self, slot: u32) -> Result<(), NotHeld> {
        let holders = self.holders.get_mut(slot as usize).ok_or(NotHeld)?;
        if *holders == 0 {
            return Err(NotHeld);
        }
        *holders = holders.checked_add(1).ok_or(NotHeld)?;
        Ok(())
    }

    /// Drops one holder; returns whether the slot is free again.
    pub(super) fn let_go(&mut self, slot: u32) -> Result<bool, NotHeld> {
        let holders = self.holders.get_mut(slot as usize).ok_or(NotHeld)?;
        *holders = holders.checked_sub(1).ok_or(NotHeld)?;
        Ok(*holders == 0)
    }
}
