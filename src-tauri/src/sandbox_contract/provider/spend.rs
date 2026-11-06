//! Central, conservative provider spend (VM part §2.5 line 1815; VM-W12 "concurrent
//! overspend fail"; VM-P32; line 57).
//!
//! Before dispatch, the maximum an operation can cost is reserved against its provider
//! account in one central ledger, so two concurrent operations cannot both spend the same
//! remaining budget. A dispatch consumes its reservation once. The outcome settles it: a
//! committed call is charged the provider-reported cost when one is known and the whole
//! reservation otherwise; a call that certainly did not commit is charged what the
//! provider reported, if anything; an unknown outcome stays fully spent until
//! reconciliation. A reported cost above the reservation is charged in full and freezes
//! the account until an operator acknowledges it.
//!
//! Money is counted in microunits here and nowhere else: the ledger takes no byte
//! counts, so it neither draws on nor feeds the wire-byte release budgets (effects'
//! `ReleaseLedger`) or the model-transfer budgets, and the VM-D12 general release budget
//! never moves because of provider spend (line 57).

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};

use crate::sandbox_contract::effects::{AccountRef, EffectId};

/// One provider account's money budget and its use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpendAccount {
    pub budget_microunits: u64,
    /// Held by reservations not yet settled.
    pub reserved_microunits: u64,
    /// Charged by settled calls.
    pub spent_microunits: u64,
    /// Held in full by calls whose outcome is unknown.
    pub unknown_microunits: u64,
    /// Charged above reservations, in total.
    pub overrun_microunits: u64,
    /// Overrun not yet acknowledged; while non-zero, nothing new is reserved.
    pub unacknowledged_overrun_microunits: u64,
}

impl SpendAccount {
    /// What a new reservation may still take:
    /// `budget − reserved − spent − unknown`, never below zero.
    pub fn available_microunits(&self) -> u64 {
        self.budget_microunits.saturating_sub(
            self.reserved_microunits
                .saturating_add(self.spent_microunits)
                .saturating_add(self.unknown_microunits),
        )
    }
}

/// Where a reservation is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpendHoldState {
    Reserved,
    /// Consumed by one dispatch.
    InFlight,
    /// The outcome is unknown; the whole amount counts as spent.
    Unknown,
}

/// One effect's reservation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpendHold {
    pub effect: EffectId,
    pub account: AccountRef,
    pub reserved_microunits: u64,
    pub state: SpendHoldState,
}

/// What an outcome says about commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpendStatus {
    Committed,
    NotCommitted,
    Unknown,
}

/// What a settlement charged and returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpendSettlement {
    pub effect: EffectId,
    pub status: SpendStatus,
    pub charged_microunits: u64,
    pub returned_microunits: u64,
    pub overrun_microunits: u64,
}

strict_provider_enum! {
    /// Why a spend step was refused.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum SpendRefusal tag "refusal" {
        UnknownAccount,
        AccountExists,
        Exhausted { requested_microunits: u64, available_microunits: u64 },
        AccountFrozen { overrun_microunits: u64 },
        AlreadyHeld,
        NotHeld,
        NotReserved,
        NotInFlight,
        NotUnknown,
        /// The reservation is below the cost the dispatch needs.
        BelowRequired { held_microunits: u64, required_microunits: u64 },
        /// An unknown outcome can only be reconciled to a definite one.
        StillUnknown,
        LedgerUnavailable,
    }
}

impl SpendRefusal {
    /// A stable short name, used in rejection codes.
    pub const fn tag(&self) -> &'static str {
        match self {
            Self::UnknownAccount => "unknown_account",
            Self::AccountExists => "account_exists",
            Self::Exhausted { .. } => "exhausted",
            Self::AccountFrozen { .. } => "account_frozen",
            Self::AlreadyHeld => "already_held",
            Self::NotHeld => "not_held",
            Self::NotReserved => "not_reserved",
            Self::NotInFlight => "not_in_flight",
            Self::NotUnknown => "not_unknown",
            Self::BelowRequired { .. } => "below_required",
            Self::StillUnknown => "still_unknown",
            Self::LedgerUnavailable => "ledger_unavailable",
        }
    }
}

impl fmt::Display for SpendRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownAccount => f.write_str("the provider account has no spend budget"),
            Self::AccountExists => f.write_str("the provider account already has a budget"),
            Self::Exhausted {
                requested_microunits,
                available_microunits,
            } => write!(
                f,
                "{requested_microunits} microunits requested, {available_microunits} available"
            ),
            Self::AccountFrozen { overrun_microunits } => write!(
                f,
                "the account was charged {overrun_microunits} microunits above its \
                 reservations; nothing is reserved until that is acknowledged"
            ),
            Self::AlreadyHeld => f.write_str("the effect already holds a reservation"),
            Self::NotHeld => f.write_str("the effect holds no reservation"),
            Self::NotReserved => f.write_str("the reservation is not waiting for dispatch"),
            Self::NotInFlight => f.write_str("the reservation is not in flight"),
            Self::NotUnknown => f.write_str("the reservation's outcome is not unknown"),
            Self::BelowRequired {
                held_microunits,
                required_microunits,
            } => write!(
                f,
                "{held_microunits} microunits are reserved; the dispatch needs \
                 {required_microunits}"
            ),
            Self::StillUnknown => f.write_str("reconciliation needs a definite outcome"),
            Self::LedgerUnavailable => f.write_str("the spend ledger is unavailable"),
        }
    }
}

impl std::error::Error for SpendRefusal {}

/// Every provider account's money budget and every reservation, kept centrally.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpendLedger {
    accounts: BTreeMap<AccountRef, SpendAccount>,
    holds: BTreeMap<EffectId, SpendHold>,
}

impl SpendLedger {
    /// A ledger with no accounts.
    pub fn new() -> Self {
        Self::default()
    }

    /// Gives `account` a money budget; an account's budget is set once.
    pub fn open_account(
        &mut self,
        account: AccountRef,
        budget_microunits: u64,
    ) -> Result<(), SpendRefusal> {
        if self.accounts.contains_key(&account) {
            return Err(SpendRefusal::AccountExists);
        }
        self.accounts.insert(
            account,
            SpendAccount {
                budget_microunits,
                reserved_microunits: 0,
                spent_microunits: 0,
                unknown_microunits: 0,
                overrun_microunits: 0,
                unacknowledged_overrun_microunits: 0,
            },
        );
        Ok(())
    }

    /// The account's budget and use.
    pub fn account(&self, account: &AccountRef) -> Option<&SpendAccount> {
        self.accounts.get(account)
    }

    /// The effect's reservation, if any.
    pub fn hold(&self, effect: &EffectId) -> Option<&SpendHold> {
        self.holds.get(effect)
    }

    /// Reserves `max_microunits` for `effect` against `account`, atomically: the amount
    /// must fit in what is still available.
    pub fn reserve(
        &mut self,
        effect: EffectId,
        account: AccountRef,
        max_microunits: u64,
    ) -> Result<SpendHold, SpendRefusal> {
        if self.holds.contains_key(&effect) {
            return Err(SpendRefusal::AlreadyHeld);
        }
        let entry = self
            .accounts
            .get_mut(&account)
            .ok_or(SpendRefusal::UnknownAccount)?;
        if entry.unacknowledged_overrun_microunits > 0 {
            return Err(SpendRefusal::AccountFrozen {
                overrun_microunits: entry.unacknowledged_overrun_microunits,
            });
        }
        let available = entry.available_microunits();
        if max_microunits > available {
            return Err(SpendRefusal::Exhausted {
                requested_microunits: max_microunits,
                available_microunits: available,
            });
        }
        entry.reserved_microunits = entry.reserved_microunits.saturating_add(max_microunits);
        let hold = SpendHold {
            effect,
            account,
            reserved_microunits: max_microunits,
            state: SpendHoldState::Reserved,
        };
        self.holds.insert(effect, hold);
        Ok(hold)
    }

    /// Consumes a reservation at the dispatch boundary; a second consume is refused, so
    /// one reservation backs one dispatch.
    pub fn consume(
        &mut self,
        effect: &EffectId,
        required_microunits: u64,
    ) -> Result<SpendHold, SpendRefusal> {
        let hold = self.holds.get_mut(effect).ok_or(SpendRefusal::NotHeld)?;
        if hold.state != SpendHoldState::Reserved {
            return Err(SpendRefusal::NotReserved);
        }
        if hold.reserved_microunits < required_microunits {
            return Err(SpendRefusal::BelowRequired {
                held_microunits: hold.reserved_microunits,
                required_microunits,
            });
        }
        hold.state = SpendHoldState::InFlight;
        Ok(*hold)
    }

    /// Returns a reservation whose attempt sent nothing, reserved or in flight.
    pub fn release(&mut self, effect: &EffectId) -> Result<u64, SpendRefusal> {
        let hold = *self.holds.get(effect).ok_or(SpendRefusal::NotHeld)?;
        if hold.state == SpendHoldState::Unknown {
            return Err(SpendRefusal::NotInFlight);
        }
        self.holds.remove(effect);
        if let Some(entry) = self.accounts.get_mut(&hold.account) {
            entry.reserved_microunits = entry
                .reserved_microunits
                .saturating_sub(hold.reserved_microunits);
        }
        Ok(hold.reserved_microunits)
    }

    fn charge(
        entry: &mut SpendAccount,
        hold: &SpendHold,
        status: SpendStatus,
        charged: u64,
    ) -> SpendSettlement {
        let overrun = charged.saturating_sub(hold.reserved_microunits);
        entry.spent_microunits = entry.spent_microunits.saturating_add(charged);
        entry.overrun_microunits = entry.overrun_microunits.saturating_add(overrun);
        entry.unacknowledged_overrun_microunits = entry
            .unacknowledged_overrun_microunits
            .saturating_add(overrun);
        SpendSettlement {
            effect: hold.effect,
            status,
            charged_microunits: charged,
            returned_microunits: hold.reserved_microunits.saturating_sub(charged),
            overrun_microunits: overrun,
        }
    }

    /// Settles an in-flight reservation by its outcome.
    pub fn settle(
        &mut self,
        effect: &EffectId,
        status: SpendStatus,
        reported_microunits: Option<u64>,
    ) -> Result<SpendSettlement, SpendRefusal> {
        let hold = *self.holds.get(effect).ok_or(SpendRefusal::NotHeld)?;
        if hold.state != SpendHoldState::InFlight {
            return Err(SpendRefusal::NotInFlight);
        }
        let entry = self
            .accounts
            .get_mut(&hold.account)
            .ok_or(SpendRefusal::UnknownAccount)?;
        entry.reserved_microunits = entry
            .reserved_microunits
            .saturating_sub(hold.reserved_microunits);
        if status == SpendStatus::Unknown {
            entry.unknown_microunits = entry
                .unknown_microunits
                .saturating_add(hold.reserved_microunits);
            if let Some(stored) = self.holds.get_mut(effect) {
                stored.state = SpendHoldState::Unknown;
            }
            return Ok(SpendSettlement {
                effect: *effect,
                status,
                charged_microunits: hold.reserved_microunits,
                returned_microunits: 0,
                overrun_microunits: 0,
            });
        }
        let charged = match status {
            SpendStatus::Committed => reported_microunits.unwrap_or(hold.reserved_microunits),
            _ => reported_microunits.unwrap_or(0),
        };
        let settlement = Self::charge(entry, &hold, status, charged);
        self.holds.remove(effect);
        Ok(settlement)
    }

    /// Reconciles an unknown outcome to a definite one.
    pub fn reconcile(
        &mut self,
        effect: &EffectId,
        status: SpendStatus,
        reported_microunits: Option<u64>,
    ) -> Result<SpendSettlement, SpendRefusal> {
        let hold = *self.holds.get(effect).ok_or(SpendRefusal::NotHeld)?;
        if hold.state != SpendHoldState::Unknown {
            return Err(SpendRefusal::NotUnknown);
        }
        if status == SpendStatus::Unknown {
            return Err(SpendRefusal::StillUnknown);
        }
        let entry = self
            .accounts
            .get_mut(&hold.account)
            .ok_or(SpendRefusal::UnknownAccount)?;
        entry.unknown_microunits = entry
            .unknown_microunits
            .saturating_sub(hold.reserved_microunits);
        let charged = match status {
            SpendStatus::Committed => reported_microunits.unwrap_or(hold.reserved_microunits),
            _ => reported_microunits.unwrap_or(0),
        };
        let settlement = Self::charge(entry, &hold, status, charged);
        self.holds.remove(effect);
        Ok(settlement)
    }

    /// Unfreezes an account after an operator reviewed its overrun; the overrun stays
    /// counted as spent.
    pub fn acknowledge_overrun(&mut self, account: &AccountRef) -> Result<u64, SpendRefusal> {
        let entry = self
            .accounts
            .get_mut(account)
            .ok_or(SpendRefusal::UnknownAccount)?;
        Ok(std::mem::take(&mut entry.unacknowledged_overrun_microunits))
    }

    /// The first broken accounting rule, if any: every account's reserved and unknown
    /// totals equal its holds, and `reserved + spent + unknown <= budget + overrun`.
    pub fn invariant_violation(&self) -> Option<String> {
        for (account, entry) in &self.accounts {
            let (mut reserved, mut unknown) = (0u64, 0u64);
            for hold in self.holds.values().filter(|hold| &hold.account == account) {
                match hold.state {
                    SpendHoldState::Unknown => {
                        unknown = unknown.saturating_add(hold.reserved_microunits)
                    }
                    _ => reserved = reserved.saturating_add(hold.reserved_microunits),
                }
            }
            if reserved != entry.reserved_microunits || unknown != entry.unknown_microunits {
                return Some(format!("account {account} totals differ from its holds"));
            }
            let used = entry
                .reserved_microunits
                .saturating_add(entry.spent_microunits)
                .saturating_add(entry.unknown_microunits);
            if used
                > entry
                    .budget_microunits
                    .saturating_add(entry.overrun_microunits)
            {
                return Some(format!("account {account} is over budget"));
            }
        }
        None
    }
}

/// The central ledger shared by every executor and dispatcher of one host.
#[derive(Clone, Debug, Default)]
pub struct SharedSpendLedger(Arc<Mutex<SpendLedger>>);

impl SharedSpendLedger {
    /// Shares `ledger`.
    pub fn new(ledger: SpendLedger) -> Self {
        Self(Arc::new(Mutex::new(ledger)))
    }

    fn lock(&self) -> Result<MutexGuard<'_, SpendLedger>, SpendRefusal> {
        self.0.lock().map_err(|_| SpendRefusal::LedgerUnavailable)
    }

    /// Runs `step` on the ledger under its lock.
    pub fn with<T>(
        &self,
        step: impl FnOnce(&mut SpendLedger) -> Result<T, SpendRefusal>,
    ) -> Result<T, SpendRefusal> {
        step(&mut *self.lock()?)
    }

    /// A copy of the ledger as it is now.
    pub fn snapshot(&self) -> Result<SpendLedger, SpendRefusal> {
        Ok(self.lock()?.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::digest;

    fn account(name: &str) -> AccountRef {
        AccountRef::new(digest("yougori/test/account/v1", &[name.as_bytes()]))
    }

    fn effect(n: u8) -> EffectId {
        EffectId::new(digest("yougori/test/effect/v1", &[&[n]]))
    }

    fn ledger(budget: u64) -> SpendLedger {
        let mut ledger = SpendLedger::new();
        ledger.open_account(account("a"), budget).unwrap();
        ledger
    }

    #[test]
    fn available_is_budget_minus_reserved_spent_and_unknown() {
        let mut ledger = ledger(100);
        ledger.reserve(effect(1), account("a"), 30).unwrap();
        ledger.reserve(effect(2), account("a"), 20).unwrap();
        ledger.consume(&effect(2), 20).unwrap();
        ledger
            .settle(&effect(2), SpendStatus::Committed, Some(5))
            .unwrap();
        ledger.reserve(effect(3), account("a"), 10).unwrap();
        ledger.consume(&effect(3), 10).unwrap();
        ledger
            .settle(&effect(3), SpendStatus::Unknown, None)
            .unwrap();
        // 100 − 30 reserved − 5 spent − 10 unknown = 55.
        assert_eq!(
            ledger
                .account(&account("a"))
                .unwrap()
                .available_microunits(),
            55
        );
        assert_eq!(ledger.invariant_violation(), None);
    }

    #[test]
    fn the_same_remaining_budget_cannot_be_reserved_twice() {
        let mut ledger = ledger(100);
        ledger.reserve(effect(1), account("a"), 60).unwrap();
        assert_eq!(
            ledger.reserve(effect(2), account("a"), 60),
            Err(SpendRefusal::Exhausted {
                requested_microunits: 60,
                available_microunits: 40
            })
        );
        assert_eq!(
            ledger.reserve(effect(1), account("a"), 1),
            Err(SpendRefusal::AlreadyHeld)
        );
        assert_eq!(
            ledger.reserve(effect(3), account("b"), 1),
            Err(SpendRefusal::UnknownAccount)
        );
        // Releasing an unused reservation recovers it.
        assert_eq!(ledger.release(&effect(1)), Ok(60));
        ledger.reserve(effect(2), account("a"), 60).unwrap();
        assert_eq!(ledger.invariant_violation(), None);
    }

    #[test]
    fn concurrent_reservations_cannot_overspend() {
        let shared = SharedSpendLedger::new(ledger(100));
        let handles: Vec<_> = (0..8u8)
            .map(|n| {
                let shared = shared.clone();
                std::thread::spawn(move || {
                    shared.with(|ledger| ledger.reserve(effect(n), account("a"), 60))
                })
            })
            .collect();
        let successes = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .filter(Result::is_ok)
            .count();
        assert_eq!(successes, 1);
        let snapshot = shared.snapshot().unwrap();
        assert_eq!(
            snapshot.account(&account("a")).unwrap().reserved_microunits,
            60
        );
        assert_eq!(snapshot.invariant_violation(), None);
    }

    #[test]
    fn one_reservation_backs_one_dispatch() {
        let mut ledger = ledger(100);
        ledger.reserve(effect(1), account("a"), 50).unwrap();
        assert_eq!(
            ledger.consume(&effect(1), 51),
            Err(SpendRefusal::BelowRequired {
                held_microunits: 50,
                required_microunits: 51
            })
        );
        ledger.consume(&effect(1), 50).unwrap();
        assert_eq!(
            ledger.consume(&effect(1), 50),
            Err(SpendRefusal::NotReserved)
        );
        assert_eq!(ledger.consume(&effect(9), 1), Err(SpendRefusal::NotHeld));
    }

    #[test]
    fn settlement_follows_the_outcome() {
        let mut ledger = ledger(1_000);
        let mut run = |n: u8, status: SpendStatus, reported: Option<u64>| {
            ledger.reserve(effect(n), account("a"), 100).unwrap();
            ledger.consume(&effect(n), 100).unwrap();
            ledger.settle(&effect(n), status, reported).unwrap()
        };
        // Committed with a reported cost: charged that, the rest returned.
        let settled = run(1, SpendStatus::Committed, Some(37));
        assert_eq!(
            (settled.charged_microunits, settled.returned_microunits),
            (37, 63)
        );
        // Committed without a report: the whole reservation is charged.
        let settled = run(2, SpendStatus::Committed, None);
        assert_eq!(
            (settled.charged_microunits, settled.returned_microunits),
            (100, 0)
        );
        // Certainly not committed: only a reported charge, else nothing.
        let settled = run(3, SpendStatus::NotCommitted, None);
        assert_eq!(
            (settled.charged_microunits, settled.returned_microunits),
            (0, 100)
        );
        let settled = run(4, SpendStatus::NotCommitted, Some(2));
        assert_eq!(settled.charged_microunits, 2);
        // Unknown: fully spent, held until reconciliation.
        let settled = run(5, SpendStatus::Unknown, Some(10));
        assert_eq!(
            (settled.charged_microunits, settled.returned_microunits),
            (100, 0)
        );
        let account_state = *ledger.account(&account("a")).unwrap();
        assert_eq!(account_state.unknown_microunits, 100);
        assert_eq!(account_state.spent_microunits, 37 + 100 + 2);
        assert_eq!(
            ledger.hold(&effect(5)).unwrap().state,
            SpendHoldState::Unknown
        );
        assert_eq!(ledger.release(&effect(5)), Err(SpendRefusal::NotInFlight));
        assert_eq!(
            ledger.reconcile(&effect(5), SpendStatus::Unknown, None),
            Err(SpendRefusal::StillUnknown)
        );
        let reconciled = ledger
            .reconcile(&effect(5), SpendStatus::Committed, Some(40))
            .unwrap();
        assert_eq!(
            (
                reconciled.charged_microunits,
                reconciled.returned_microunits
            ),
            (40, 60)
        );
        assert_eq!(ledger.account(&account("a")).unwrap().unknown_microunits, 0);
        assert_eq!(ledger.invariant_violation(), None);
    }

    #[test]
    fn a_reported_cost_above_the_reservation_freezes_the_account() {
        let mut ledger = ledger(100);
        ledger.reserve(effect(1), account("a"), 100).unwrap();
        ledger.consume(&effect(1), 100).unwrap();
        let settled = ledger
            .settle(&effect(1), SpendStatus::Committed, Some(130))
            .unwrap();
        assert_eq!(settled.overrun_microunits, 30);
        assert_eq!(
            ledger.reserve(effect(2), account("a"), 1),
            Err(SpendRefusal::AccountFrozen {
                overrun_microunits: 30
            })
        );
        assert_eq!(ledger.invariant_violation(), None);
        assert_eq!(ledger.acknowledge_overrun(&account("a")), Ok(30));
        // Unfrozen, but the overrun stays spent: nothing is left of the 100.
        assert_eq!(
            ledger.reserve(effect(2), account("a"), 1),
            Err(SpendRefusal::Exhausted {
                requested_microunits: 1,
                available_microunits: 0
            })
        );
        assert_eq!(
            ledger.account(&account("a")).unwrap().overrun_microunits,
            30
        );
        assert_eq!(ledger.invariant_violation(), None);
    }

    #[test]
    fn the_ledger_round_trips_and_refusals_are_strict() {
        let mut ledger = ledger(10);
        ledger.reserve(effect(1), account("a"), 4).unwrap();
        let json = serde_json::to_string(&ledger).unwrap();
        assert_eq!(serde_json::from_str::<SpendLedger>(&json).unwrap(), ledger);
        assert!(serde_json::from_str::<SpendRefusal>(r#"{"refusal":"not_held","x":1}"#).is_err());
    }
}
