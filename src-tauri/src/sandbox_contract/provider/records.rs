//! The executor's own view of the effect records (VM part §4.5 line 2004: the executor
//! independently verifies delegation, generation, object, payload and quota).
//!
//! The effect controller calls the executor while it holds the records, so the executor
//! reads them through this port instead, from the durable store the controller persists
//! before every dispatch: [`PersistedEffects`] implements the port, so a store reader
//! hands over the latest state it loaded. [`RecordsSnapshot`] is a detached copy.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{MonotonicTime, PolicyEpoch};
use crate::sandbox_contract::effects::{
    AuthorizationBasis, AuthorizationBook, BudgetHold, EffectDescription, EffectId, EffectRecord,
    ExecutorIdentity, PersistedEffects, ScopeViolation,
};

/// The effect records as an executor reads them.
pub trait EffectRecordsPort {
    /// The record of `effect` as last persisted.
    fn record(&self, effect: &EffectId) -> Option<EffectRecord>;

    /// The budget hold of `effect` under its authorization basis.
    fn hold(&self, effect: &EffectId) -> Option<BudgetHold>;

    /// Whether `basis` still covers `description` for `executor` now: not revoked, not
    /// expired, under the current policy epoch and within its scope.
    fn check_basis(
        &self,
        basis: &AuthorizationBasis,
        description: &EffectDescription,
        executor: &ExecutorIdentity,
        policy: PolicyEpoch,
        now: MonotonicTime,
        session: ClockSession,
    ) -> Result<(), ScopeViolation>;
}

/// The durable state itself, as the controller persisted it: a reader of the effect
/// store implements the port by loading the latest [`PersistedEffects`].
impl EffectRecordsPort for PersistedEffects {
    fn record(&self, effect: &EffectId) -> Option<EffectRecord> {
        PersistedEffects::record(self, effect).cloned()
    }

    fn hold(&self, effect: &EffectId) -> Option<BudgetHold> {
        self.authorizations().hold(effect).copied()
    }

    fn check_basis(
        &self,
        basis: &AuthorizationBasis,
        description: &EffectDescription,
        executor: &ExecutorIdentity,
        policy: PolicyEpoch,
        now: MonotonicTime,
        session: ClockSession,
    ) -> Result<(), ScopeViolation> {
        self.authorizations()
            .check(basis, description, executor, policy, now, session)
    }
}

/// A copy of the records and the authorization book.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecordsSnapshot {
    records: BTreeMap<EffectId, EffectRecord>,
    book: AuthorizationBook,
}

impl RecordsSnapshot {
    /// Copies the records and the authorization book of a persisted state.
    pub fn of(persisted: &PersistedEffects) -> Self {
        Self::capture(persisted.records(), persisted.authorizations())
    }

    /// Copies `records` and `book`.
    pub fn capture<'a>(
        records: impl IntoIterator<Item = &'a EffectRecord>,
        book: &AuthorizationBook,
    ) -> Self {
        Self {
            records: records
                .into_iter()
                .map(|record| (record.id(), record.clone()))
                .collect(),
            book: book.clone(),
        }
    }
}

impl EffectRecordsPort for RecordsSnapshot {
    fn record(&self, effect: &EffectId) -> Option<EffectRecord> {
        self.records.get(effect).cloned()
    }

    fn hold(&self, effect: &EffectId) -> Option<BudgetHold> {
        self.book.hold(effect).copied()
    }

    fn check_basis(
        &self,
        basis: &AuthorizationBasis,
        description: &EffectDescription,
        executor: &ExecutorIdentity,
        policy: PolicyEpoch,
        now: MonotonicTime,
        session: ClockSession,
    ) -> Result<(), ScopeViolation> {
        self.book
            .check(basis, description, executor, policy, now, session)
    }
}

/// A shared port; a poisoned lock reads as no record and an unknown basis.
impl<P: EffectRecordsPort> EffectRecordsPort for Arc<Mutex<P>> {
    fn record(&self, effect: &EffectId) -> Option<EffectRecord> {
        self.lock().ok()?.record(effect)
    }

    fn hold(&self, effect: &EffectId) -> Option<BudgetHold> {
        self.lock().ok()?.hold(effect)
    }

    fn check_basis(
        &self,
        basis: &AuthorizationBasis,
        description: &EffectDescription,
        executor: &ExecutorIdentity,
        policy: PolicyEpoch,
        now: MonotonicTime,
        session: ClockSession,
    ) -> Result<(), ScopeViolation> {
        self.lock()
            .map_err(|_| ScopeViolation::UnknownBasis)?
            .check_basis(basis, description, executor, policy, now, session)
    }
}
