//! The small formal models of VM part §12.3 (lines 2829–2841), items 3 and 5:
//!
//! - Lifecycle: no active authority before enforcement is ready; revocation is
//!   monotonic; cleanup retries cannot revive a generation.
//! - Snapshot/epoch interaction: older persisted state cannot resurrect a revoked
//!   identity.
//!
//! The model is an abstract state machine over one sandbox, enumerated exhaustively over
//! every operation sequence up to a stated depth. Its assumptions: one sandbox; the
//! authorization epoch is a counter that only rises; tombstones are durable and survive
//! every restore of persisted state; a restore brings back a copy of the state as it was
//! persisted and, as the implemented recovery does, revives no authority and advances
//! the epoch past the copy's. Its bounds: the alphabet below, sequences of at most
//! [`DEFAULT_DEPTH`] operations, and one persisted copy at a time. A pass of the model
//! proves nothing about the Rust code, the operating system, the hypervisor or hardware;
//! the tests of this module check the supervisor against it on the same sequences. Where
//! the supervisor's own persisted copy may predate a tombstone, it refuses every
//! capability of the earlier run by its clock session, which the model folds into the
//! durable tombstones.

use std::collections::BTreeSet;
use std::fmt;

use serde::Serialize;

/// The depth the tests enumerate to: every sequence of up to this many operations.
pub const DEFAULT_DEPTH: usize = 5;

/// The abstract operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    /// Resources reserved and the perimeter prepared.
    Reserve,
    /// The VM created and its boot evidence checked: enforcement is ready.
    EnforcementReady,
    /// Authority granted under the current epoch.
    Authorize,
    /// The durable revocation decision.
    Revoke,
    /// One cleanup attempt after a revocation; it may be retried any number of times.
    CleanupRetry,
    /// A new boot of a revoked and cleaned-up sandbox, under a fresh epoch.
    NewBoot,
    /// Persist the current state.
    Persist,
    /// Restore the persisted copy, keeping the durable tombstones.
    RestorePersisted,
}

impl Op {
    pub const ALL: [Self; 8] = [
        Self::Reserve,
        Self::EnforcementReady,
        Self::Authorize,
        Self::Revoke,
        Self::CleanupRetry,
        Self::NewBoot,
        Self::Persist,
        Self::RestorePersisted,
    ];
}

/// Where the modelled sandbox is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Planned,
    Reserved,
    EnforcementReady,
    Authorized,
    Revoked,
}

/// The persisted copy of a state: everything but the durable tombstones.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct Persisted {
    pub phase: Phase,
    pub epoch: u64,
    pub authority: Option<u64>,
}

/// The model state.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct ModelState {
    pub phase: Phase,
    /// The current authorization epoch.
    pub epoch: u64,
    /// The epoch authority is held under, if any.
    pub authority: Option<u64>,
    /// Every epoch ever revoked; durable, never shrinks.
    pub tombstones: BTreeSet<u64>,
    /// Whether enforcement was ready at some point of this boot.
    pub enforcement_was_ready: bool,
    pub cleanup_attempts: u32,
    pub persisted: Option<Persisted>,
}

impl ModelState {
    pub fn initial() -> Self {
        Self {
            phase: Phase::Planned,
            epoch: 1,
            authority: None,
            tombstones: BTreeSet::new(),
            enforcement_was_ready: false,
            cleanup_attempts: 0,
            persisted: None,
        }
    }

    /// Whether `op` is accepted in this state; a refused operation changes nothing.
    pub fn accepts(&self, op: Op) -> bool {
        match op {
            Op::Reserve => self.phase == Phase::Planned,
            Op::EnforcementReady => self.phase == Phase::Reserved,
            Op::Authorize => {
                self.phase == Phase::EnforcementReady && !self.tombstones.contains(&self.epoch)
            }
            Op::Revoke => self.phase == Phase::Authorized,
            Op::CleanupRetry => self.phase == Phase::Revoked,
            Op::NewBoot => self.phase == Phase::Revoked && self.cleanup_attempts >= 1,
            Op::Persist => true,
            Op::RestorePersisted => self.persisted.is_some(),
        }
    }

    /// Applies `op`; a refused operation returns the state unchanged.
    pub fn step(&self, op: Op) -> Self {
        let mut next = self.clone();
        if !self.accepts(op) {
            return next;
        }
        match op {
            Op::Reserve => next.phase = Phase::Reserved,
            Op::EnforcementReady => {
                next.phase = Phase::EnforcementReady;
                next.enforcement_was_ready = true;
            }
            Op::Authorize => {
                next.phase = Phase::Authorized;
                next.authority = Some(self.epoch);
            }
            Op::Revoke => {
                next.tombstones.insert(self.epoch);
                next.epoch = self.epoch.saturating_add(1);
                next.authority = None;
                next.phase = Phase::Revoked;
            }
            Op::CleanupRetry => next.cleanup_attempts = self.cleanup_attempts.saturating_add(1),
            Op::NewBoot => {
                next.phase = Phase::Planned;
                next.epoch = self.epoch.saturating_add(1);
                next.authority = None;
                next.enforcement_was_ready = false;
                next.cleanup_attempts = 0;
            }
            Op::Persist => {
                next.persisted = Some(Persisted {
                    phase: self.phase,
                    epoch: self.epoch,
                    authority: self.authority,
                });
            }
            Op::RestorePersisted => {
                if let Some(copy) = &self.persisted {
                    // Nothing is revived. The tombstones are durable and survive the
                    // restore. A copy whose epoch was revoked since comes back revoked and
                    // cleaned up; a copy of a live boot comes back with its VM kept and no
                    // authority, its epoch advanced past the copy's and the copy's epoch
                    // tombstoned, as the implemented recovery does; a copy before any VM
                    // comes back planned.
                    let highest = self.tombstones.iter().max().copied().unwrap_or(0);
                    next.authority = None;
                    if copy.epoch <= highest {
                        next.phase = Phase::Revoked;
                        next.epoch = highest.saturating_add(1).max(self.epoch);
                        next.cleanup_attempts = 1;
                        next.enforcement_was_ready = false;
                    } else {
                        match copy.phase {
                            Phase::Planned | Phase::Reserved => {
                                next.phase = Phase::Planned;
                                next.epoch = copy.epoch;
                                next.enforcement_was_ready = false;
                                next.cleanup_attempts = 0;
                            }
                            Phase::EnforcementReady | Phase::Authorized => {
                                next.tombstones.insert(copy.epoch);
                                next.phase = Phase::EnforcementReady;
                                next.epoch = copy.epoch.saturating_add(1);
                                next.enforcement_was_ready = true;
                                next.cleanup_attempts = 0;
                            }
                            Phase::Revoked => {
                                next.phase = Phase::Revoked;
                                next.epoch = copy.epoch;
                                next.cleanup_attempts = 1;
                                next.enforcement_was_ready = false;
                            }
                        }
                    }
                }
            }
        }
        next
    }
}

/// One invariant of §12.3 items 3 and 5.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Invariant {
    /// Authority is held only after enforcement was ready in this boot.
    NoAuthorityBeforeEnforcement,
    /// A revoked epoch stays revoked: the tombstone set never shrinks.
    RevocationMonotonic,
    /// Authority is never held under a revoked epoch.
    NoAuthorityUnderRevokedEpoch,
    /// A cleanup retry changes neither the epoch nor the authority.
    CleanupCannotRevive,
    /// A restore brings back no authority and never lowers the epoch to a tombstone.
    RestoreCannotResurrect,
}

/// A violation found during enumeration, with the sequence that led to it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Violation {
    pub invariant: Invariant,
    pub sequence: Vec<Op>,
}

/// Checks the invariants over one transition.
pub fn check(before: &ModelState, op: Op, after: &ModelState) -> Option<Invariant> {
    if after.authority.is_some() && !after.enforcement_was_ready {
        return Some(Invariant::NoAuthorityBeforeEnforcement);
    }
    if !before.tombstones.is_subset(&after.tombstones) {
        return Some(Invariant::RevocationMonotonic);
    }
    if after
        .authority
        .is_some_and(|epoch| after.tombstones.contains(&epoch))
    {
        return Some(Invariant::NoAuthorityUnderRevokedEpoch);
    }
    if op == Op::CleanupRetry
        && (after.epoch != before.epoch || after.authority != before.authority)
    {
        return Some(Invariant::CleanupCannotRevive);
    }
    if op == Op::RestorePersisted && before.persisted.is_some() {
        let highest = after.tombstones.iter().max().copied().unwrap_or(0);
        if after.authority.is_some() || after.epoch <= highest {
            return Some(Invariant::RestoreCannotResurrect);
        }
    }
    None
}

/// What an enumeration covered.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Enumeration {
    pub depth: usize,
    pub sequences: u64,
    pub distinct_states: u64,
    pub violations: Vec<Violation>,
}

impl fmt::Display for Enumeration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} sequences to depth {} over {} distinct states, {} violation(s)",
            self.sequences,
            self.depth,
            self.distinct_states,
            self.violations.len()
        )
    }
}

/// Enumerates every sequence of up to `depth` operations from the initial state and
/// checks the invariants on every transition.
pub fn enumerate(depth: usize) -> Enumeration {
    let mut report = Enumeration {
        depth,
        ..Enumeration::default()
    };
    let mut states: BTreeSet<String> = BTreeSet::new();
    let mut stack: Vec<(ModelState, Vec<Op>)> = vec![(ModelState::initial(), Vec::new())];
    while let Some((state, sequence)) = stack.pop() {
        if let Ok(key) = serde_json::to_string(&state) {
            states.insert(key);
        }
        if sequence.len() >= depth {
            continue;
        }
        for op in Op::ALL {
            let next = state.step(op);
            let mut sequence = sequence.clone();
            sequence.push(op);
            report.sequences = report.sequences.saturating_add(1);
            if let Some(invariant) = check(&state, op, &next) {
                report.violations.push(Violation {
                    invariant,
                    sequence: sequence.clone(),
                });
            }
            stack.push((next, sequence));
        }
    }
    report.distinct_states = states.len() as u64;
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_models_hold_on_every_sequence_to_the_default_depth() {
        let report = enumerate(DEFAULT_DEPTH);
        assert!(
            report.violations.is_empty(),
            "{report}: {:?}",
            report.violations
        );
        let expected: u64 = (1..=DEFAULT_DEPTH as u32)
            .map(|length| (Op::ALL.len() as u64).pow(length))
            .sum();
        assert_eq!(report.sequences, expected);
        assert!(report.distinct_states > 20, "{report}");
    }

    #[test]
    fn a_broken_model_would_be_caught() {
        let authorized = ModelState::initial()
            .step(Op::Reserve)
            .step(Op::EnforcementReady)
            .step(Op::Authorize);
        let mut revived = authorized.step(Op::Revoke);
        revived.authority = Some(1);
        assert_eq!(
            check(&authorized, Op::Revoke, &revived),
            Some(Invariant::NoAuthorityUnderRevokedEpoch)
        );
        let mut early = ModelState::initial();
        early.authority = Some(1);
        assert_eq!(
            check(&ModelState::initial(), Op::Reserve, &early),
            Some(Invariant::NoAuthorityBeforeEnforcement)
        );
        let revoked = authorized.step(Op::Revoke);
        let mut forgotten = revoked.clone();
        forgotten.tombstones.clear();
        assert_eq!(
            check(&revoked, Op::CleanupRetry, &forgotten),
            Some(Invariant::RevocationMonotonic)
        );
        let mut cleaned = revoked.step(Op::CleanupRetry);
        cleaned.epoch = revoked.epoch + 1;
        assert_eq!(
            check(&revoked, Op::CleanupRetry, &cleaned),
            Some(Invariant::CleanupCannotRevive)
        );
        let persisted = authorized.step(Op::Persist);
        let mut resurrected = persisted.step(Op::RestorePersisted);
        resurrected.authority = Some(resurrected.epoch);
        assert_eq!(
            check(&persisted, Op::RestorePersisted, &resurrected),
            Some(Invariant::RestoreCannotResurrect)
        );
    }

    #[test]
    fn an_older_persisted_copy_cannot_resurrect_a_revoked_identity() {
        let persisted = ModelState::initial()
            .step(Op::Reserve)
            .step(Op::EnforcementReady)
            .step(Op::Authorize)
            .step(Op::Persist);
        let revoked = persisted.step(Op::Revoke);
        let restored = revoked.step(Op::RestorePersisted);
        assert_eq!(restored.authority, None);
        assert_eq!(restored.phase, Phase::Revoked);
        assert_eq!(restored.epoch, 2);
        assert!(restored.tombstones.contains(&1));
        assert!(!restored.accepts(Op::Authorize));
        assert_eq!(check(&revoked, Op::RestorePersisted, &restored), None);
        // A copy of a live boot comes back without authority, under a new epoch.
        let kept = persisted.step(Op::RestorePersisted);
        assert_eq!(kept.authority, None);
        assert_eq!(kept.phase, Phase::EnforcementReady);
        assert_eq!(kept.epoch, 2);
        assert!(kept.tombstones.contains(&1));
        assert!(kept.accepts(Op::Authorize));
        // A new boot needs a cleanup attempt first and takes a fresh epoch.
        assert!(!revoked.accepts(Op::NewBoot));
        let booted = revoked.step(Op::CleanupRetry).step(Op::NewBoot);
        assert_eq!((booted.phase, booted.epoch), (Phase::Planned, 3));
    }
}
