//! The slow work, kept off everybody's request path.
//!
//! A realm has several things that have to happen regularly and that nobody is waiting for:
//! reservations that have run out, work past its deadline, requests nobody answered, allowances
//! and sign-ins that have lapsed, permissions that expired long ago and a history that has grown
//! past what it keeps. Before this they happened either on a timer the caller had to remember or
//! on the next request that happened to go through the right door, which meant one person's
//! request paid for everybody's tidying.
//!
//! This has no clock of its own. The caller supplies `now`, exactly as everywhere else in the
//! core, so a test can run a day of upkeep in a millisecond and nothing here can drift away from
//! the time the realm is being told it is.
//!
//! What runs when, and why each is on that cadence:
//!
//!   * every second: reservations and deadlines, because a reservation that has run out is holding
//!     room on a computer that could be taking other work. Both are index range scans.
//!   * every minute: requests nobody answered and sign-ins whose permission has run out. Neither
//!     weakens anything by waiting a minute: an expired request is already refused and a lapsed
//!     sign-in's permission is already refused.
//!   * every hour: permissions that expired long ago, and trimming the history. Both are pure
//!     tidying, and the history is trimmed only as far as it has been exported.
//!
//! Nothing here is a requirement for the realm to be correct. A realm nobody sweeps answers every
//! question the same way; what it does is keep rows that say nothing and hold room that nothing is
//! using. `Core::ready` is what says so out loud.
use super::Core;

/// What one pass of upkeep did.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Swept {
    pub leases_and_deadlines: usize,
    pub requests_lapsed: usize,
    pub sessions_ended: usize,
    pub capabilities_forgotten: usize,
    pub events_trimmed: usize,
    /// What the pass could not do, in sentences. One piece failing never stops the others.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub trouble: Vec<String>,
}

impl Swept {
    /// Whether this pass did anything at all.
    pub fn did_something(&self) -> bool {
        self.leases_and_deadlines + self.requests_lapsed + self.sessions_ended + self.capabilities_forgotten + self.events_trimmed > 0
    }
}

/// The three cadences, in seconds.
pub const EVERY_SECOND: i64 = 1;
pub const EVERY_MINUTE: i64 = 60;
pub const EVERY_HOUR: i64 = 60 * 60;

/// The names of the pieces, so a schedule can be read and tested without running it.
pub const PIECES: [(&str, i64); 3] = [("reservations and deadlines", EVERY_SECOND), ("requests and sign-ins", EVERY_MINUTE), ("old permissions and the history", EVERY_HOUR)];

/// A schedule, holding only when each piece last ran.
#[derive(Clone, Debug, Default)]
pub struct Upkeep {
    last: std::collections::BTreeMap<&'static str, i64>,
}

impl Upkeep {
    pub fn new() -> Upkeep {
        Upkeep::default()
    }

    /// What is due at `now`, without doing any of it, so the schedule itself can be read.
    ///
    /// Everything is due the first time, because a realm that has just been opened does not know
    /// how long it was shut.
    pub fn due(&self, now: i64) -> Vec<&'static str> {
        PIECES
            .iter()
            .filter(|(piece, every)| match self.last.get(piece) {
                Some(last) => now - last >= *every,
                None => true,
            })
            .map(|(piece, _)| *piece)
            .collect()
    }

    /// One pass. Each piece is independent: one that fails records why and the others still run.
    pub fn tick(&mut self, core: &mut Core, now: i64) -> Swept {
        let mut swept = Swept::default();
        for piece in self.due(now) {
            self.last.insert(piece, now);
            match piece {
                "reservations and deadlines" => swept.leases_and_deadlines = core.expire(now),
                "requests and sign-ins" => {
                    swept.requests_lapsed = core.expire_approvals(now);
                    swept.sessions_ended = core.expire_workspace_sessions(now);
                }
                "old permissions and the history" => {
                    match core.forget_old_permissions(now) {
                        Ok(gone) => swept.capabilities_forgotten = gone,
                        Err(said) => swept.trouble.push(said),
                    }
                    match core.tidy_history() {
                        Ok(gone) => swept.events_trimmed = gone,
                        Err(said) => swept.trouble.push(said),
                    }
                }
                _ => {}
            }
        }
        swept
    }
}

impl Core {
    /// Forgets permissions that expired long enough ago that nothing could still be presenting
    /// one. They are refused either way; what this buys is that the table does not grow for ever.
    pub fn forget_old_permissions(&self, now: i64) -> Result<usize, String> {
        self.store.forget_expired_capabilities(now - super::capability::KEEP_EXPIRED)
    }

    /// Drops the oldest events once there are more than the chain keeps, and only as far as they
    /// have been carried off this computer. Nothing unexported is ever dropped.
    pub fn tidy_history(&self) -> Result<usize, String> {
        self.store.trim()
    }
}

#[cfg(test)]
mod tests;
