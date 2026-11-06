//! §12.3 model 3: the launch transaction and revocation protocol of one sandbox
//! (VM §6.1 states, §6.3 revocation steps 1–5).
//!
//! The supervisor's durable record holds the authority generation, the revocation
//! tombstone (`revoked_through`) and a pending incident revocation; an enforcement point
//! keeps a cached view of authority that the supervisor propagates. The linearization
//! point of a revocation is the durable tombstone write; the acknowledgment ("new
//! authorizations denied") is a separate, later step.
//!
//! Bounds: one sandbox, at most one cleanup failure, one engine crash and one relaunch,
//! so generations 1–3. Assumptions: recovery reconciles a live VM back to `VmCreated`
//! under a new generation with no authority (or continues an incident revocation to
//! termination); a failure before authority activation exposes nothing; the journal
//! keeps the last activation record, which a cleanup retry or a queue may redeliver.

use std::fmt;

use super::contract::{Defect, Guard, Injection, InvariantId, ModelConfig, ModelKind};
use super::explore::TransitionSystem;

/// The §6.1 states.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Phase {
    Planned,
    ResourcesReserved,
    PerimeterReady,
    VmCreated,
    BootEvidenceChecked,
    AuthorityActive,
    Running,
    Revoking,
    Terminating,
    CleanupPending,
    Stopped,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct LifecycleState {
    phase: Phase,
    generation: u8,
    perimeter_ok: bool,
    evidence_ok: bool,
    policy_ok: bool,
    authority: Option<u8>,
    enforcer_authority: Option<u8>,
    revoked_through: u8,
    revocation_pending: bool,
    acknowledged: bool,
    journal: Option<u8>,
    cleanup_failed: bool,
    crashed: bool,
    relaunched: bool,
    // History fields.
    revoke_requested: bool,
    entrypoint_before_checks: bool,
    revocation_undone: bool,
    authorized_after_ack: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LifecycleAction {
    ReserveResources,
    ReadyPerimeter,
    CreateVm,
    CheckBootEvidence,
    FailLaunch,
    ActivateAuthority,
    StartWorkload,
    Authorize,
    Revoke,
    PropagateRevocation,
    AcknowledgeRevocation,
    Terminate,
    FinishTermination,
    Cleanup,
    CleanupFails,
    RetryCleanup,
    RedeliverActivation,
    Crash,
    Relaunch,
}

impl fmt::Display for LifecycleAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ReserveResources => "reserve resources",
            Self::ReadyPerimeter => "ready perimeter",
            Self::CreateVm => "create VM",
            Self::CheckBootEvidence => "check boot evidence",
            Self::FailLaunch => "fail launch",
            Self::ActivateAuthority => "activate authority",
            Self::StartWorkload => "start workload",
            Self::Authorize => "authorize new operation",
            Self::Revoke => "revoke",
            Self::PropagateRevocation => "propagate revocation",
            Self::AcknowledgeRevocation => "acknowledge revocation",
            Self::Terminate => "terminate VM",
            Self::FinishTermination => "finish termination",
            Self::Cleanup => "clean up",
            Self::CleanupFails => "cleanup fails",
            Self::RetryCleanup => "retry cleanup",
            Self::RedeliverActivation => "redeliver activation record",
            Self::Crash => "engine crash and recovery",
            Self::Relaunch => "relaunch",
        })
    }
}

pub(super) struct LifecycleModel<'c> {
    config: &'c ModelConfig,
}

impl<'c> LifecycleModel<'c> {
    pub(super) fn new(config: &'c ModelConfig) -> Self {
        Self { config }
    }

    fn order_checked(&self) -> bool {
        self.config.enforces(Guard::LaunchOrderCheck)
            && !self.config.defect(Defect::AuthorityBeforeEvidence)
    }

    /// Activation of authority for generation `generation`, normally or from a
    /// redelivered record; both pass the same guards.
    fn activate(
        &self,
        state: &LifecycleState,
        generation: u8,
        redelivered: bool,
    ) -> Option<LifecycleState> {
        let ready = state.phase == Phase::BootEvidenceChecked
            && state.perimeter_ok
            && state.evidence_ok
            && state.policy_ok;
        let phase_allowed = if self.order_checked() {
            ready
        } else if redelivered {
            !matches!(
                state.phase,
                Phase::Planned | Phase::ResourcesReserved | Phase::PerimeterReady | Phase::Stopped
            )
        } else {
            matches!(state.phase, Phase::VmCreated | Phase::BootEvidenceChecked)
                && state.perimeter_ok
        };
        if !phase_allowed {
            return None;
        }
        if self.config.enforces(Guard::TransitionGenerationCheck)
            && (generation != state.generation
                || generation <= state.revoked_through
                || state.revocation_pending)
        {
            return None;
        }
        let mut next = state.clone();
        next.authority = Some(generation);
        next.enforcer_authority = Some(generation);
        if !redelivered {
            next.journal = Some(generation);
        }
        next.phase = Phase::AuthorityActive;
        next.revocation_undone |= state.revoke_requested;
        Some(next)
    }

    fn crash(&self, state: &LifecycleState) -> LifecycleState {
        let mut next = state.clone();
        next.crashed = true;
        next.authority = None;
        next.enforcer_authority = None;
        let durable = self.config.enforces(Guard::DurableRevocation)
            && !self.config.defect(Defect::RevocationNotDurable);
        if !durable {
            next.revoked_through = 0;
            next.revocation_pending = false;
            next.revocation_undone |= state.revoked_through > 0;
        }
        if next.revocation_pending {
            next.phase = Phase::Terminating;
        } else {
            // A new generation with no authority; the old one is tombstoned.
            next.revoked_through = next.revoked_through.max(state.generation);
            next.generation = state.generation + 1;
            next.evidence_ok = false;
            next.policy_ok = false;
            next.phase = Phase::VmCreated;
        }
        next
    }
}

impl TransitionSystem for LifecycleModel<'_> {
    type State = LifecycleState;
    type Action = LifecycleAction;

    fn kind(&self) -> ModelKind {
        ModelKind::Lifecycle
    }

    fn initial_states(&self) -> Vec<LifecycleState> {
        vec![LifecycleState {
            phase: Phase::Planned,
            generation: 1,
            perimeter_ok: false,
            evidence_ok: false,
            policy_ok: false,
            authority: None,
            enforcer_authority: None,
            revoked_through: 0,
            revocation_pending: false,
            acknowledged: false,
            journal: None,
            cleanup_failed: false,
            crashed: false,
            relaunched: false,
            revoke_requested: false,
            entrypoint_before_checks: false,
            revocation_undone: false,
            authorized_after_ack: false,
        }]
    }

    fn successors(&self, state: &LifecycleState) -> Vec<(LifecycleAction, LifecycleState)> {
        use LifecycleAction as A;
        let config = self.config;
        let mut out = Vec::new();
        let mut with = |action: LifecycleAction, change: &dyn Fn(&mut LifecycleState)| {
            let mut next = state.clone();
            change(&mut next);
            out.push((action, next));
        };
        let pre_authority = matches!(
            state.phase,
            Phase::ResourcesReserved
                | Phase::PerimeterReady
                | Phase::VmCreated
                | Phase::BootEvidenceChecked
        );
        if pre_authority {
            with(A::FailLaunch, &|next| next.phase = Phase::CleanupPending);
        }
        match state.phase {
            Phase::Planned => with(A::ReserveResources, &|next| {
                next.phase = Phase::ResourcesReserved
            }),
            Phase::ResourcesReserved => with(A::ReadyPerimeter, &|next| {
                next.perimeter_ok = true;
                next.phase = Phase::PerimeterReady;
            }),
            Phase::PerimeterReady => with(A::CreateVm, &|next| next.phase = Phase::VmCreated),
            Phase::VmCreated => with(A::CheckBootEvidence, &|next| {
                next.evidence_ok = true;
                next.policy_ok = true;
                next.phase = Phase::BootEvidenceChecked;
            }),
            Phase::AuthorityActive => with(A::StartWorkload, &|next| {
                next.entrypoint_before_checks |= !(next.evidence_ok && next.policy_ok);
                next.phase = Phase::Running;
            }),
            Phase::Revoking => {
                let must_confirm = config.enforces(Guard::AckAfterEnforcerConfirms)
                    && !config.defect(Defect::AckBeforeEnforcerConfirms);
                if !state.acknowledged
                    && (!must_confirm || state.enforcer_authority != Some(state.generation))
                {
                    with(A::AcknowledgeRevocation, &|next| next.acknowledged = true);
                }
                if state.acknowledged {
                    with(A::Terminate, &|next| {
                        next.authority = None;
                        next.enforcer_authority = None;
                        next.phase = Phase::Terminating;
                    });
                }
            }
            Phase::Terminating => with(A::FinishTermination, &|next| {
                next.phase = Phase::CleanupPending
            }),
            Phase::CleanupPending => {
                let stop = |next: &mut LifecycleState| {
                    next.revocation_pending = false;
                    next.phase = Phase::Stopped;
                };
                if !state.cleanup_failed {
                    with(A::Cleanup, &stop);
                    with(A::CleanupFails, &|next| next.cleanup_failed = true);
                } else if config.defect(Defect::CleanupRetryRevivesGeneration) {
                    // The seeded defect replays the journal on the retry path, bypassing
                    // the activation guards.
                    match state.journal {
                        Some(generation) => with(A::RetryCleanup, &|next| {
                            next.authority = Some(generation);
                            next.enforcer_authority = Some(generation);
                            next.phase = Phase::AuthorityActive;
                            next.revocation_undone |= next.revoke_requested;
                        }),
                        None => with(A::RetryCleanup, &stop),
                    }
                } else {
                    with(A::RetryCleanup, &stop);
                }
            }
            Phase::Stopped if !state.relaunched => with(A::Relaunch, &|next| {
                next.phase = Phase::Planned;
                next.generation += 1;
                next.perimeter_ok = false;
                next.evidence_ok = false;
                next.policy_ok = false;
                next.authority = None;
                next.enforcer_authority = None;
                next.acknowledged = false;
                next.revocation_pending = false;
                next.revoke_requested = false;
                next.cleanup_failed = false;
                next.relaunched = true;
            }),
            _ => {}
        }
        if let Some(next) = self.activate(state, state.generation, false) {
            out.push((A::ActivateAuthority, next));
        }
        if matches!(state.phase, Phase::AuthorityActive | Phase::Running) {
            let generation = state.generation;
            out.push((A::Revoke, {
                let mut next = state.clone();
                next.revoked_through = next.revoked_through.max(generation);
                next.revocation_pending = true;
                next.authority = None;
                next.revoke_requested = true;
                next.phase = Phase::Revoking;
                next
            }));
        }
        let alive = matches!(
            state.phase,
            Phase::AuthorityActive | Phase::Running | Phase::Revoking | Phase::Terminating
        );
        if alive && state.acknowledged && !state.authorized_after_ack {
            let granted = if config.enforces(Guard::AuthoritativeEpochCheck) {
                state.authority == Some(state.generation)
                    && state.generation > state.revoked_through
            } else {
                state.enforcer_authority == Some(state.generation)
            };
            if granted {
                let mut next = state.clone();
                next.authorized_after_ack = true;
                out.push((A::Authorize, next));
            }
        }
        if !config.has(Injection::SupervisorDelayed)
            && state.enforcer_authority.is_some()
            && state.enforcer_authority != state.authority
        {
            let mut next = state.clone();
            next.enforcer_authority = state.authority;
            out.push((A::PropagateRevocation, next));
        }
        if config.has(Injection::RedeliveredTransition) {
            if let Some(generation) = state.journal {
                if let Some(next) = self.activate(state, generation, true) {
                    out.push((A::RedeliverActivation, next));
                }
            }
        }
        let crashable = matches!(
            state.phase,
            Phase::VmCreated
                | Phase::BootEvidenceChecked
                | Phase::AuthorityActive
                | Phase::Running
                | Phase::Revoking
                | Phase::Terminating
        );
        if config.has(Injection::EngineCrash) && !state.crashed && crashable {
            out.push((A::Crash, self.crash(state)));
        }
        out
    }

    fn holds(&self, invariant: InvariantId, state: &LifecycleState) -> bool {
        match invariant {
            InvariantId::EntrypointAfterChecks => !state.entrypoint_before_checks,
            InvariantId::NoAuthorizationAfterRevocationAck => !state.authorized_after_ack,
            InvariantId::NoAuthorityBeforeEnforcement => {
                state.authority.is_none()
                    || (state.perimeter_ok && state.evidence_ok && state.policy_ok)
            }
            InvariantId::RevocationMonotonic => !state.revocation_undone,
            InvariantId::CleanupNeverRevivesGeneration => {
                state.authority.is_none_or(|generation| {
                    generation == state.generation && generation > state.revoked_through
                })
            }
            _ => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox_contract::models::contract::check_model;
    use crate::sandbox_contract::models::explore::{Bounds, Exploration};

    fn check(config: &ModelConfig) -> Exploration {
        check_model(ModelKind::Lifecycle, config, Bounds::DEFAULT).unwrap()
    }

    const LAUNCH: [&str; 6] = [
        "reserve resources",
        "ready perimeter",
        "create VM",
        "check boot evidence",
        "activate authority",
        "start workload",
    ];

    #[test]
    fn the_correct_lifecycle_holds_under_the_threat_model_and_a_delayed_supervisor() {
        for config in [
            ModelConfig::correct(),
            ModelConfig::threat_model(),
            ModelConfig::threat_model().with_injections([Injection::SupervisorDelayed]),
        ] {
            let result = check(&config);
            assert!(result.complete);
            assert!(result.is_clean(), "{:?}", result.violations);
        }
    }

    #[test]
    fn authority_before_boot_evidence_is_refused_and_found_when_seeded() {
        let result = check(&ModelConfig::correct().with_defects([Defect::AuthorityBeforeEvidence]));
        let violation = result
            .violation(InvariantId::NoAuthorityBeforeEnforcement)
            .unwrap();
        assert_eq!(
            violation.trace.steps,
            vec![
                "reserve resources",
                "ready perimeter",
                "create VM",
                "activate authority"
            ]
        );
        // Without the order check the workload entrypoint also runs before the checks.
        let unchecked = check(&ModelConfig::correct().without_guards([Guard::LaunchOrderCheck]));
        let entry = unchecked
            .violation(InvariantId::EntrypointAfterChecks)
            .unwrap();
        assert_eq!(
            entry.trace.steps.last().map(String::as_str),
            Some("start workload")
        );
    }

    #[test]
    fn no_authorization_after_the_acknowledgment_needs_one_of_two_guards() {
        // Either guard alone contains it; the seeded early acknowledgment is masked.
        for disabled in [
            Guard::AuthoritativeEpochCheck,
            Guard::AckAfterEnforcerConfirms,
        ] {
            assert!(check(&ModelConfig::threat_model().without_guards([disabled])).is_clean());
        }
        assert!(check(
            &ModelConfig::threat_model().with_defects([Defect::AckBeforeEnforcerConfirms])
        )
        .is_clean());
        let both = ModelConfig::correct().without_guards([
            Guard::AuthoritativeEpochCheck,
            Guard::AckAfterEnforcerConfirms,
        ]);
        let violation = check(&both)
            .violation(InvariantId::NoAuthorizationAfterRevocationAck)
            .cloned()
            .unwrap();
        let mut expected: Vec<&str> = LAUNCH[..5].to_vec();
        expected.extend([
            "revoke",
            "acknowledge revocation",
            "authorize new operation",
        ]);
        assert_eq!(violation.trace.steps, expected);
    }

    #[test]
    fn cleanup_retries_and_redelivered_records_never_revive_a_generation() {
        let threat = ModelConfig::threat_model();
        let revived = check(
            &threat
                .clone()
                .with_defects([Defect::CleanupRetryRevivesGeneration]),
        );
        let violation = revived
            .violation(InvariantId::CleanupNeverRevivesGeneration)
            .unwrap();
        assert_eq!(
            violation.trace.steps.last().map(String::as_str),
            Some("retry cleanup")
        );
        assert!(!revived.holds(InvariantId::RevocationMonotonic));
        let unguarded = check(&threat.without_guards([Guard::TransitionGenerationCheck]));
        let redelivered = unguarded
            .violation(InvariantId::CleanupNeverRevivesGeneration)
            .unwrap();
        assert!(redelivered
            .trace
            .steps
            .iter()
            .any(|step| step == "redeliver activation record"));
    }

    #[test]
    fn revocation_survives_a_crash_only_while_it_is_durable() {
        let crash = ModelConfig::correct().with_injections([Injection::EngineCrash]);
        assert!(check(&crash).is_clean());
        let result = check(&crash.with_defects([Defect::RevocationNotDurable]));
        let violation = result.violation(InvariantId::RevocationMonotonic).unwrap();
        let mut expected: Vec<&str> = LAUNCH[..5].to_vec();
        expected.extend(["revoke", "engine crash and recovery"]);
        assert_eq!(violation.trace.steps, expected);
    }
}
