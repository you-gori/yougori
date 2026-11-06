//! §12.3 model 4: release-budget reservation for concurrent operations (VM §2.5).
//!
//! One channel has a byte budget of [`CHANNEL_BUDGET`] units and a documented reserved
//! in-flight allowance of [`IN_FLIGHT_ALLOWANCE`] units, so the ceiling is
//! `counted_bytes_out <= sum(channel_budget) + documented_reserved_in_flight_allowance`.
//! Each operation reserves its payload plus a header unit (headers and framing count where
//! they leave the trust domain), then sends; the guest may try one unit beyond its
//! reservation, and transport may retransmit sent units. Reservation is two steps (read
//! the remaining budget, then commit) so a check-then-act defect is expressible.
//!
//! Bounds: two operations of 3+1 and 1+1 units, at most [`MAX_RETRANSMITS`] retransmitted
//! units per operation. Assumptions: a retransmitted unit is the only unreserved in-flight
//! byte; this is not a bound on all information leakage (timing, packet behaviour and
//! shared hardware are outside it, §2.5).

use std::fmt;

use super::contract::{Defect, Guard, Injection, InvariantId, ModelConfig, ModelKind};
use super::explore::TransitionSystem;

/// The channel budget in units.
pub(super) const CHANNEL_BUDGET: u8 = 4;
/// The documented reserved in-flight allowance in units.
pub(super) const IN_FLIGHT_ALLOWANCE: u8 = 1;
/// Payload units of each operation; each also sends one header unit.
const PAYLOAD: [u8; 2] = [3, 1];
const HEADER: u8 = 1;
/// Units the guest may try to send beyond its payload.
const EXTRA_UNITS: u8 = 1;
/// Retransmitted units per operation.
pub(super) const MAX_RETRANSMITS: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Stage {
    Idle,
    Read(u8),
    Reserved,
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Operation {
    stage: Stage,
    reserved: u8,
    header_sent: bool,
    payload_sent: u8,
    accounted: u8,
    retransmits: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct BudgetState {
    operations: [Operation; 2],
    reserved_total: u8,
    counted: u8,
    allowance_used: u8,
    revoked: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BudgetAction {
    BeginReservation(usize),
    CommitReservation(usize),
    RefuseReservation(usize),
    SendHeader(usize),
    SendPayload(usize),
    Retransmit(usize),
    Close(usize),
    Revoke,
}

impl fmt::Display for BudgetAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BeginReservation(op) => write!(f, "begin reservation for op {op}"),
            Self::CommitReservation(op) => write!(f, "commit reservation for op {op}"),
            Self::RefuseReservation(op) => write!(f, "reservation refused for op {op}"),
            Self::SendHeader(op) => write!(f, "send header for op {op}"),
            Self::SendPayload(op) => write!(f, "send payload for op {op}"),
            Self::Retransmit(op) => write!(f, "retransmit for op {op}"),
            Self::Close(op) => write!(f, "close op {op}"),
            Self::Revoke => f.write_str("revoke"),
        }
    }
}

pub(super) struct BudgetModel<'c> {
    config: &'c ModelConfig,
}

impl<'c> BudgetModel<'c> {
    pub(super) fn new(config: &'c ModelConfig) -> Self {
        Self { config }
    }

    fn header_charge(&self) -> u8 {
        if self.config.defect(Defect::HeaderNotCounted) {
            0
        } else {
            HEADER
        }
    }

    fn need(&self, op: usize) -> u8 {
        PAYLOAD[op] + self.header_charge()
    }

    fn sender_allows(&self, operation: &Operation, charge: u8) -> bool {
        !self.config.enforces(Guard::SenderEnforcesReservation)
            || operation.accounted + charge <= operation.reserved
    }

    fn operation_successors(
        &self,
        state: &BudgetState,
        op: usize,
        out: &mut Vec<(BudgetAction, BudgetState)>,
    ) {
        let operation = state.operations[op];
        let mut with = |action: BudgetAction, change: &dyn Fn(&mut BudgetState)| {
            let mut next = state.clone();
            change(&mut next);
            out.push((action, next));
        };
        match operation.stage {
            Stage::Idle if !state.revoked => {
                let remaining = CHANNEL_BUDGET.saturating_sub(state.reserved_total);
                with(BudgetAction::BeginReservation(op), &|next| {
                    next.operations[op].stage = Stage::Read(remaining)
                });
            }
            Stage::Read(snapshot) => {
                let need = self.need(op);
                let available = if !self.config.enforces(Guard::CentralReservation) {
                    CHANNEL_BUDGET
                } else if self.config.defect(Defect::NonAtomicReservation) {
                    snapshot
                } else {
                    CHANNEL_BUDGET.saturating_sub(state.reserved_total)
                };
                if need <= available && !state.revoked {
                    with(BudgetAction::CommitReservation(op), &|next| {
                        next.operations[op].stage = Stage::Reserved;
                        next.operations[op].reserved = need;
                        next.reserved_total += need;
                    });
                } else {
                    with(BudgetAction::RefuseReservation(op), &|next| {
                        next.operations[op].stage = Stage::Closed
                    });
                }
            }
            Stage::Reserved => {
                let header = self.header_charge();
                if !state.revoked
                    && !operation.header_sent
                    && self.sender_allows(&operation, header)
                {
                    with(BudgetAction::SendHeader(op), &|next| {
                        let target = &mut next.operations[op];
                        target.header_sent = true;
                        target.accounted += header;
                        next.counted += HEADER;
                    });
                }
                if !state.revoked
                    && operation.payload_sent < PAYLOAD[op] + EXTRA_UNITS
                    && self.sender_allows(&operation, 1)
                {
                    with(BudgetAction::SendPayload(op), &|next| {
                        let target = &mut next.operations[op];
                        target.payload_sent += 1;
                        target.accounted += 1;
                        next.counted += 1;
                    });
                }
                with(BudgetAction::Close(op), &|next| {
                    let target = &mut next.operations[op];
                    let unused = target.reserved.saturating_sub(target.accounted);
                    next.reserved_total = next.reserved_total.saturating_sub(unused);
                    target.stage = Stage::Closed;
                });
            }
            _ => {}
        }
        let sent_any = operation.header_sent || operation.payload_sent > 0;
        if self.config.has(Injection::Retransmission)
            && sent_any
            && operation.retransmits < MAX_RETRANSMITS
        {
            let from_allowance = self.config.enforces(Guard::RetransmitFromAllowance);
            if !from_allowance || state.allowance_used < IN_FLIGHT_ALLOWANCE {
                let mut next = state.clone();
                next.operations[op].retransmits += 1;
                next.counted += 1;
                if from_allowance {
                    next.allowance_used += 1;
                }
                out.push((BudgetAction::Retransmit(op), next));
            }
        }
    }
}

impl TransitionSystem for BudgetModel<'_> {
    type State = BudgetState;
    type Action = BudgetAction;

    fn kind(&self) -> ModelKind {
        ModelKind::Budget
    }

    fn initial_states(&self) -> Vec<BudgetState> {
        let idle = Operation {
            stage: Stage::Idle,
            reserved: 0,
            header_sent: false,
            payload_sent: 0,
            accounted: 0,
            retransmits: 0,
        };
        let second = if self.config.has(Injection::ConcurrentRequests) {
            idle
        } else {
            Operation {
                stage: Stage::Closed,
                ..idle
            }
        };
        vec![BudgetState {
            operations: [idle, second],
            reserved_total: 0,
            counted: 0,
            allowance_used: 0,
            revoked: false,
        }]
    }

    fn successors(&self, state: &BudgetState) -> Vec<(BudgetAction, BudgetState)> {
        let mut out = Vec::new();
        for op in 0..state.operations.len() {
            self.operation_successors(state, op, &mut out);
        }
        if !state.revoked {
            let mut next = state.clone();
            next.revoked = true;
            out.push((BudgetAction::Revoke, next));
        }
        out
    }

    fn holds(&self, invariant: InvariantId, state: &BudgetState) -> bool {
        match invariant {
            InvariantId::ReleaseWithinCeiling => {
                state.counted <= CHANNEL_BUDGET + IN_FLIGHT_ALLOWANCE
            }
            InvariantId::ReservationsWithinBudget => state.reserved_total <= CHANNEL_BUDGET,
            _ => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox_contract::models::contract::check_model;
    use crate::sandbox_contract::models::explore::{Bounds, Exploration};
    use crate::sandbox_contract::models::objectives::release_ceiling;

    fn check(config: &ModelConfig) -> Exploration {
        check_model(ModelKind::Budget, config, Bounds::DEFAULT).unwrap()
    }

    #[test]
    fn the_ceiling_is_the_channel_budget_plus_the_allowance() {
        assert_eq!(
            release_ceiling(&[u64::from(CHANNEL_BUDGET)], u64::from(IN_FLIGHT_ALLOWANCE)).unwrap(),
            5
        );
    }

    #[test]
    fn concurrent_operations_stay_within_the_ceiling() {
        for config in [ModelConfig::correct(), ModelConfig::threat_model()] {
            let result = check(&config);
            assert!(result.complete);
            assert!(result.is_clean(), "{:?}", result.violations);
        }
    }

    #[test]
    fn a_check_then_act_reservation_over_commits() {
        let concurrent = ModelConfig::correct().with_injections([Injection::ConcurrentRequests]);
        let result = check(&concurrent.with_defects([Defect::NonAtomicReservation]));
        let violation = result
            .violation(InvariantId::ReservationsWithinBudget)
            .unwrap();
        assert_eq!(violation.trace.steps.len(), 4);
        assert!(violation.trace.steps[..2]
            .iter()
            .all(|step| step.starts_with("begin reservation")));
    }

    #[test]
    fn uncounted_headers_exceed_the_ceiling() {
        let concurrent = ModelConfig::correct().with_injections([Injection::ConcurrentRequests]);
        let result = check(&concurrent.with_defects([Defect::HeaderNotCounted]));
        assert!(result.holds(InvariantId::ReservationsWithinBudget));
        assert!(!result.holds(InvariantId::ReleaseWithinCeiling));
        // A single operation stays within the ceiling even with the defect.
        assert!(check(&ModelConfig::correct().with_defects([Defect::HeaderNotCounted])).is_clean());
    }

    #[test]
    fn each_budget_guard_is_a_single_point_under_the_threat_model() {
        for guard in [
            Guard::CentralReservation,
            Guard::SenderEnforcesReservation,
            Guard::RetransmitFromAllowance,
        ] {
            let result = check(&ModelConfig::threat_model().without_guards([guard]));
            assert!(!result.is_clean(), "{guard:?}");
        }
    }
}
