//! §12.3 model 2: the effect state machine of one external operation.
//!
//! One operation is authorized (a ticket bound to tenant, resource, payload digest, epoch
//! and a nonce), reserved, dispatched by a broker and settled by a provider. The adversary
//! may change the presented payload, tenant or resource after approval and replay a
//! consumed ticket; the environment may lose a response (uncertain outcome), make the
//! authorization service unavailable and revoke (advance the epoch).
//!
//! Bounds: one operation, at most [`MAX_DISPATCHES`] dispatches (a first attempt plus a
//! retry or a replay), epochs 1–2, nonces below 3. Assumptions: the policy permits exactly
//! the intended request, so tenant, resource and payload are the intended values at issue;
//! a replayed request reaches the provider directly; a revoked generation is never
//! authorized again (the lifecycle model checks that).

use std::fmt;

use super::contract::{Defect, Guard, Injection, InvariantId, ModelConfig, ModelKind};
use super::explore::TransitionSystem;

/// Dispatches per operation: a first attempt plus one retry or replay.
pub(super) const MAX_DISPATCHES: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Phase {
    Idle,
    Authorized,
    Reserved,
    InFlight,
    Committed,
    Failed,
    Uncertain,
}

/// The exact tuple a ticket was issued for; tenant, resource and payload are always the
/// intended values at issue, so only the epoch and nonce vary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Ticket {
    epoch: u8,
    nonce: u8,
}

/// Fields of the presented request changed since authorization.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
struct Tampered {
    tenant: bool,
    resource: bool,
    payload: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct EffectState {
    phase: Phase,
    ticket: Option<Ticket>,
    tampered: Tampered,
    epoch: u8,
    next_nonce: u8,
    auth_up: bool,
    granted_without_service: bool,
    reserved: bool,
    consumed: u8,
    last_dispatched: Option<Ticket>,
    hidden_committed: bool,
    effects: u8,
    dispatches: u8,
    // History fields, set on the offending transition.
    unauthorized_or_unreserved: bool,
    binding_changed: bool,
    scope_exceeded: bool,
    blind_retry: bool,
    effect_without_authorization: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum EffectAction {
    Authorize,
    Reserve,
    Dispatch,
    ReplayTicket,
    ProviderCommits,
    ProviderFails,
    ResponseLost { committed: bool },
    Reconcile,
    Retry,
    Revoke,
    AuthorizationOutage,
    ChangePayload,
    SpoofTenant,
    RetargetResource,
}

impl fmt::Display for EffectAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Authorize => "authorize",
            Self::Reserve => "reserve",
            Self::Dispatch => "dispatch",
            Self::ReplayTicket => "replay consumed ticket",
            Self::ProviderCommits => "provider commits",
            Self::ProviderFails => "provider fails",
            Self::ResponseLost { committed: true } => "response lost after provider committed",
            Self::ResponseLost { committed: false } => "response lost, provider did not commit",
            Self::Reconcile => "reconcile with provider",
            Self::Retry => "retry",
            Self::Revoke => "revoke",
            Self::AuthorizationOutage => "authorization service unavailable",
            Self::ChangePayload => "change payload after approval",
            Self::SpoofTenant => "spoof tenant identity",
            Self::RetargetResource => "retarget resource",
        })
    }
}

pub(super) struct EffectModel<'c> {
    config: &'c ModelConfig,
}

fn bit(nonce: u8) -> u8 {
    1u8 << nonce
}

impl<'c> EffectModel<'c> {
    pub(super) fn new(config: &'c ModelConfig) -> Self {
        Self { config }
    }

    fn authorize(&self, state: &EffectState) -> Option<EffectState> {
        let fail_open = !self.config.enforces(Guard::FailClosedAuthorization)
            || self.config.defect(Defect::FailOpenOnOutage);
        if !state.auth_up && !fail_open {
            return None;
        }
        let mut next = state.clone();
        next.ticket = Some(Ticket {
            epoch: state.epoch,
            nonce: state.next_nonce,
        });
        next.next_nonce += 1;
        next.tampered = Tampered::default();
        next.granted_without_service = !state.auth_up;
        next.phase = Phase::Authorized;
        Some(next)
    }

    /// A dispatch of the current request, or of a replayed consumed ticket.
    fn dispatch(&self, state: &EffectState, replayed: Option<Ticket>) -> Option<EffectState> {
        let config = self.config;
        let presented = replayed.or(state.ticket);
        let tampered = if replayed.is_some() {
            Tampered::default()
        } else {
            state.tampered
        };
        if config.enforces(Guard::TicketBinding) {
            let current = state.ticket?;
            let shown = presented?;
            let tenant_ok = !tampered.tenant || config.defect(Defect::BindingOmitsTenant);
            let payload_ok = !tampered.payload || config.defect(Defect::BindingOmitsPayload);
            if !(tenant_ok
                && payload_ok
                && !tampered.resource
                && shown == current
                && current.epoch == state.epoch)
            {
                return None;
            }
        }
        let was_consumed = presented.is_some_and(|ticket| state.consumed & bit(ticket.nonce) != 0);
        if config.enforces(Guard::SingleUseTicket) && was_consumed {
            return None;
        }
        if config.enforces(Guard::DispatchRequiresReservation) && !state.reserved {
            return None;
        }
        let mut next = state.clone();
        next.dispatches += 1;
        if let Some(ticket) = presented {
            next.consumed |= bit(ticket.nonce);
            next.last_dispatched = Some(ticket);
        }
        next.reserved = false;
        let authorized = state.ticket;
        next.unauthorized_or_unreserved |= authorized.is_none() || !state.reserved;
        let differs = match (authorized, presented) {
            (Some(issued), Some(shown)) => {
                issued != shown
                    || issued.epoch != state.epoch
                    || tampered.tenant
                    || tampered.payload
            }
            _ => true,
        };
        next.binding_changed |= differs;
        next.scope_exceeded |= differs || tampered.resource || was_consumed;
        next.effect_without_authorization |= authorized.is_none() || state.granted_without_service;
        if replayed.is_some() {
            next.effects += 1;
        } else {
            next.phase = Phase::InFlight;
        }
        Some(next)
    }
}

impl TransitionSystem for EffectModel<'_> {
    type State = EffectState;
    type Action = EffectAction;

    fn kind(&self) -> ModelKind {
        ModelKind::Effect
    }

    fn initial_states(&self) -> Vec<EffectState> {
        vec![EffectState {
            phase: Phase::Idle,
            ticket: None,
            tampered: Tampered::default(),
            epoch: 1,
            next_nonce: 0,
            auth_up: true,
            granted_without_service: false,
            reserved: false,
            consumed: 0,
            last_dispatched: None,
            hidden_committed: false,
            effects: 0,
            dispatches: 0,
            unauthorized_or_unreserved: false,
            binding_changed: false,
            scope_exceeded: false,
            blind_retry: false,
            effect_without_authorization: false,
        }]
    }

    fn successors(&self, state: &EffectState) -> Vec<(EffectAction, EffectState)> {
        let config = self.config;
        let mut out = Vec::new();
        let mut with = |action: EffectAction, change: &dyn Fn(&mut EffectState)| {
            let mut next = state.clone();
            change(&mut next);
            out.push((action, next));
        };
        if matches!(state.phase, Phase::Authorized | Phase::Reserved) {
            if config.has(Injection::ApprovalPayloadChanged) && !state.tampered.payload {
                with(EffectAction::ChangePayload, &|next| {
                    next.tampered.payload = true
                });
            }
            if config.has(Injection::RelayIdentitySpoofed) && !state.tampered.tenant {
                with(EffectAction::SpoofTenant, &|next| {
                    next.tampered.tenant = true
                });
            }
            if config.has(Injection::TicketRetargeted) && !state.tampered.resource {
                with(EffectAction::RetargetResource, &|next| {
                    next.tampered.resource = true
                });
            }
        }
        if config.has(Injection::AuthorizationUnavailable) && state.auth_up {
            with(EffectAction::AuthorizationOutage, &|next| {
                next.auth_up = false
            });
        }
        if state.epoch == 1 {
            with(EffectAction::Revoke, &|next| next.epoch = 2);
        }
        let room = state.dispatches < MAX_DISPATCHES;
        match state.phase {
            Phase::Idle if room && state.epoch == 1 => {
                if let Some(next) = self.authorize(state) {
                    out.push((EffectAction::Authorize, next));
                }
            }
            Phase::Authorized => {
                with(EffectAction::Reserve, &|next| {
                    next.reserved = true;
                    next.phase = Phase::Reserved;
                });
                if let Some(next) = self.dispatch(state, None) {
                    out.push((EffectAction::Dispatch, next));
                }
            }
            Phase::Reserved => {
                if let Some(next) = self.dispatch(state, None) {
                    out.push((EffectAction::Dispatch, next));
                }
            }
            Phase::InFlight => {
                with(EffectAction::ProviderCommits, &|next| {
                    next.effects += 1;
                    next.phase = Phase::Committed;
                });
                with(EffectAction::ProviderFails, &|next| {
                    next.phase = Phase::Failed
                });
                if config.has(Injection::ResponseLost) {
                    for committed in [true, false] {
                        with(EffectAction::ResponseLost { committed }, &|next| {
                            next.effects += u8::from(committed);
                            next.hidden_committed = committed;
                            next.phase = Phase::Uncertain;
                        });
                    }
                }
            }
            Phase::Uncertain => {
                with(EffectAction::Reconcile, &|next| {
                    next.phase = if next.hidden_committed {
                        Phase::Committed
                    } else {
                        Phase::Failed
                    };
                    next.hidden_committed = false;
                });
                let blind_allowed = !config.enforces(Guard::NoBlindRetry)
                    || config.defect(Defect::RetryIgnoresUncertainty);
                if room && blind_allowed {
                    with(EffectAction::Retry, &|next| {
                        next.dispatches += 1;
                        next.blind_retry = true;
                        next.hidden_committed = false;
                        next.phase = Phase::InFlight;
                    });
                }
            }
            Phase::Failed if room => {
                // A definite failure had no effect: retrying needs a new authorization.
                with(EffectAction::Retry, &|next| {
                    next.phase = Phase::Idle;
                    next.ticket = None;
                    next.reserved = false;
                    next.tampered = Tampered::default();
                    next.granted_without_service = false;
                });
            }
            _ => {}
        }
        if config.has(Injection::TicketReplayed) && room {
            if let Some(ticket) = state.last_dispatched {
                if let Some(next) = self.dispatch(state, Some(ticket)) {
                    out.push((EffectAction::ReplayTicket, next));
                }
            }
        }
        out
    }

    fn holds(&self, invariant: InvariantId, state: &EffectState) -> bool {
        match invariant {
            InvariantId::TicketExactScope => !state.scope_exceeded,
            InvariantId::FailedAuthorizationDenies => !state.effect_without_authorization,
            InvariantId::AuthorizationAndReservationPrecedeDispatch => {
                !state.unauthorized_or_unreserved
            }
            InvariantId::EffectBindingFixed => !state.binding_changed,
            InvariantId::UncertainOutcomeNotBlindlyRetried => !state.blind_retry,
            _ => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox_contract::models::contract::check_model;
    use crate::sandbox_contract::models::explore::Bounds;

    fn check(config: &ModelConfig) -> crate::sandbox_contract::models::Exploration {
        check_model(ModelKind::Effect, config, Bounds::DEFAULT).unwrap()
    }

    #[test]
    fn the_correct_effect_model_holds_under_the_whole_threat_model() {
        for config in [ModelConfig::correct(), ModelConfig::threat_model()] {
            let result = check(&config);
            assert!(result.complete);
            assert!(result.is_clean(), "{:?}", result.violations);
        }
    }

    #[test]
    fn dispatch_without_a_reservation_is_the_shortest_counterexample() {
        let config =
            ModelConfig::threat_model().without_guards([Guard::DispatchRequiresReservation]);
        let result = check(&config);
        let violation = result
            .violation(InvariantId::AuthorizationAndReservationPrecedeDispatch)
            .unwrap();
        assert_eq!(violation.trace.steps, vec!["authorize", "dispatch"]);
    }

    #[test]
    fn a_changed_payload_or_tenant_cannot_be_dispatched() {
        let tampering = ModelConfig::correct().with_injections([
            Injection::ApprovalPayloadChanged,
            Injection::RelayIdentitySpoofed,
        ]);
        assert!(check(&tampering).is_clean());
        // The seeded partial checks break exact scope with a four-step trace.
        for (defect, tamper) in [
            (Defect::BindingOmitsPayload, "change payload after approval"),
            (Defect::BindingOmitsTenant, "spoof tenant identity"),
        ] {
            let result = check(&tampering.clone().with_defects([defect]));
            let steps = &result
                .violation(InvariantId::TicketExactScope)
                .unwrap()
                .trace
                .steps;
            assert_eq!(steps.len(), 4, "{steps:?}");
            assert_eq!(steps.first().map(String::as_str), Some("authorize"));
            assert_eq!(steps.last().map(String::as_str), Some("dispatch"));
            assert!(steps.iter().any(|step| step == tamper), "{steps:?}");
            assert!(!result.holds(InvariantId::EffectBindingFixed));
        }
    }

    #[test]
    fn an_uncertain_outcome_is_never_blindly_retried() {
        let lossy = ModelConfig::correct().with_injections([Injection::ResponseLost]);
        assert!(check(&lossy).is_clean());
        let broken = lossy.with_defects([Defect::RetryIgnoresUncertainty]);
        let violation = check(&broken)
            .violation(InvariantId::UncertainOutcomeNotBlindlyRetried)
            .cloned()
            .unwrap();
        assert_eq!(
            violation.trace.steps,
            vec![
                "authorize",
                "reserve",
                "dispatch",
                "response lost after provider committed",
                "retry"
            ]
        );
    }

    #[test]
    fn an_unavailable_authorization_service_denies_new_effects() {
        let outage = ModelConfig::correct().with_injections([Injection::AuthorizationUnavailable]);
        assert!(check(&outage).is_clean());
        let violation = check(&outage.with_defects([Defect::FailOpenOnOutage]))
            .violation(InvariantId::FailedAuthorizationDenies)
            .cloned()
            .unwrap();
        assert_eq!(
            violation.trace.steps,
            vec![
                "authorization service unavailable",
                "authorize",
                "reserve",
                "dispatch"
            ]
        );
    }

    #[test]
    fn replay_is_contained_by_two_guards_and_breaks_scope_without_both() {
        let replay = ModelConfig::correct().with_injections([Injection::TicketReplayed]);
        assert!(check(&replay.clone().without_guards([Guard::SingleUseTicket])).is_clean());
        let both =
            replay.without_guards([Guard::SingleUseTicket, Guard::DispatchRequiresReservation]);
        let result = check(&both);
        let violation = result.violation(InvariantId::TicketExactScope).unwrap();
        // Without the reservation check the shortest replay skips the reservation too.
        assert_eq!(
            violation.trace.steps,
            vec!["authorize", "dispatch", "replay consumed ticket"]
        );
    }

    #[test]
    fn a_revoked_epoch_cannot_dispatch_an_earlier_ticket() {
        let config = ModelConfig::correct().without_guards([Guard::TicketBinding]);
        let violation = check(&config)
            .violation(InvariantId::EffectBindingFixed)
            .cloned()
            .unwrap();
        assert_eq!(
            violation.trace.steps,
            vec!["authorize", "revoke", "reserve", "dispatch"]
        );
    }
}
