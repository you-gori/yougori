//! The host-boundary model for the §2.6 invariants outside models 2–5: guest messages
//! that try to select host targets, executor widening and credential reads, artifact
//! promotion after review, cleanup through guest-created links, and compatibility
//! fallbacks (VM-P16, VM-P42, VM-P47, VM-P49).
//!
//! Five independent sub-machines share no variable, so they run in a fixed order (each
//! starts once the previous one has finished); for invariants over one sub-machine each,
//! a fixed order reaches every combination of their final states.
//!
//! Bounds: one message, one executor request, one promotion, one cleanup and one launch
//! per run. Assumptions: the provider-side credential scope is an external assumption;
//! a launch with an available backend uses it.

use std::fmt;

use super::contract::{Guard, Injection, InvariantId, ModelConfig, ModelKind};
use super::explore::TransitionSystem;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum MessageTarget {
    DeclaredOperation,
    HostExecutable,
    HostPath,
    PrivilegedEndpoint,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum ExecutorRequest {
    FixedOperation,
    WidenedOperation,
    ReadCredential,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum FallbackChoice {
    OtherVmSameAuthority,
    OtherVmBroaderAuthority,
    Container,
    Refuse,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Stage<T> {
    Idle,
    Done(T),
    Refused,
}

impl<T> Stage<T> {
    fn finished(&self) -> bool {
        !matches!(self, Self::Idle)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Promotion {
    Idle,
    Reviewed { staged: bool, modified: bool },
    Applied { reviewed_bytes: bool },
    Refused,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Cleanup {
    Idle,
    Linked,
    Done { outside_roots: bool },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Launch {
    Idle,
    BackendUnavailable,
    Done(FallbackChoice),
    Refused,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct BoundaryState {
    message: Stage<MessageTarget>,
    executor: Stage<ExecutorRequest>,
    promotion: Promotion,
    cleanup: Cleanup,
    launch: Launch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BoundaryAction {
    Message(MessageTarget),
    Executor(ExecutorRequest),
    Review,
    ModifyArtifact,
    Apply,
    CreateLink,
    Cleanup,
    BackendFails,
    Launch,
    Fallback(FallbackChoice),
}

impl fmt::Display for BoundaryAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Message(MessageTarget::DeclaredOperation) => "message a declared operation",
            Self::Message(MessageTarget::HostExecutable) => "message naming a host executable",
            Self::Message(MessageTarget::HostPath) => "message naming a host path",
            Self::Message(MessageTarget::PrivilegedEndpoint) => {
                "message naming a privileged endpoint"
            }
            Self::Executor(ExecutorRequest::FixedOperation) => "request the fixed operation",
            Self::Executor(ExecutorRequest::WidenedOperation) => "request a widened operation",
            Self::Executor(ExecutorRequest::ReadCredential) => "request the credential",
            Self::Review => "review artifact",
            Self::ModifyArtifact => "modify artifact after review",
            Self::Apply => "apply promotion",
            Self::CreateLink => "create link out of managed root",
            Self::Cleanup => "clean up managed root",
            Self::BackendFails => "backend unavailable",
            Self::Launch => "launch on the requested backend",
            Self::Fallback(FallbackChoice::OtherVmSameAuthority) => {
                "fall back to another VM backend"
            }
            Self::Fallback(FallbackChoice::OtherVmBroaderAuthority) => {
                "fall back to another VM backend with broader authority"
            }
            Self::Fallback(FallbackChoice::Container) => "fall back to a container",
            Self::Fallback(FallbackChoice::Refuse) => "refuse the launch",
        })
    }
}

pub(super) struct BoundaryModel<'c> {
    config: &'c ModelConfig,
}

impl<'c> BoundaryModel<'c> {
    pub(super) fn new(config: &'c ModelConfig) -> Self {
        Self { config }
    }

    fn message(&self, target: MessageTarget) -> Stage<MessageTarget> {
        if target != MessageTarget::DeclaredOperation
            && self.config.enforces(Guard::ClosedMessageSchema)
        {
            Stage::Refused
        } else {
            Stage::Done(target)
        }
    }

    fn executor(&self, request: ExecutorRequest) -> Stage<ExecutorRequest> {
        let config = self.config;
        let refused = match request {
            ExecutorRequest::FixedOperation => false,
            ExecutorRequest::WidenedOperation => {
                config.enforces(Guard::ExecutorFixedOperation)
                    || config.enforces(Guard::ProviderScopedCredential)
            }
            ExecutorRequest::ReadCredential => config.enforces(Guard::CredentialSealed),
        };
        if refused {
            Stage::Refused
        } else {
            Stage::Done(request)
        }
    }

    fn fallback(&self, choice: FallbackChoice) -> Launch {
        let weakening = matches!(
            choice,
            FallbackChoice::OtherVmBroaderAuthority | FallbackChoice::Container
        );
        if choice == FallbackChoice::Refuse
            || (weakening && self.config.enforces(Guard::FallbackKeepsVmBoundary))
        {
            Launch::Refused
        } else {
            Launch::Done(choice)
        }
    }
}

impl TransitionSystem for BoundaryModel<'_> {
    type State = BoundaryState;
    type Action = BoundaryAction;

    fn kind(&self) -> ModelKind {
        ModelKind::Boundary
    }

    fn initial_states(&self) -> Vec<BoundaryState> {
        vec![BoundaryState {
            message: Stage::Idle,
            executor: Stage::Idle,
            promotion: Promotion::Idle,
            cleanup: Cleanup::Idle,
            launch: Launch::Idle,
        }]
    }

    fn successors(&self, state: &BoundaryState) -> Vec<(BoundaryAction, BoundaryState)> {
        let config = self.config;
        let hostile = config.has(Injection::HostileGuest);
        let mut out = Vec::new();
        let mut with = |action: BoundaryAction, change: &dyn Fn(&mut BoundaryState)| {
            let mut next = *state;
            change(&mut next);
            out.push((action, next));
        };
        if !state.message.finished() {
            let mut targets = vec![MessageTarget::DeclaredOperation];
            if hostile {
                targets.extend([
                    MessageTarget::HostExecutable,
                    MessageTarget::HostPath,
                    MessageTarget::PrivilegedEndpoint,
                ]);
            }
            for target in targets {
                let outcome = self.message(target);
                with(BoundaryAction::Message(target), &|next| {
                    next.message = outcome
                });
            }
            return out;
        }
        if !state.executor.finished() {
            let mut requests = vec![ExecutorRequest::FixedOperation];
            if hostile {
                requests.extend([
                    ExecutorRequest::WidenedOperation,
                    ExecutorRequest::ReadCredential,
                ]);
            }
            for request in requests {
                let outcome = self.executor(request);
                with(BoundaryAction::Executor(request), &|next| {
                    next.executor = outcome
                });
            }
            return out;
        }
        match state.promotion {
            Promotion::Idle => {
                let staged = config.enforces(Guard::PromotionHostStaging);
                with(BoundaryAction::Review, &|next| {
                    next.promotion = Promotion::Reviewed {
                        staged,
                        modified: false,
                    }
                });
                return out;
            }
            Promotion::Reviewed { staged, modified } => {
                if config.has(Injection::ArtifactChangedAfterReview) && !modified {
                    with(BoundaryAction::ModifyArtifact, &|next| {
                        next.promotion = Promotion::Reviewed {
                            staged,
                            modified: true,
                        }
                    });
                }
                let differs = modified && !staged;
                let outcome = if differs && config.enforces(Guard::PromotionDigestRecheck) {
                    Promotion::Refused
                } else {
                    Promotion::Applied {
                        reviewed_bytes: !differs,
                    }
                };
                with(BoundaryAction::Apply, &|next| next.promotion = outcome);
                return out;
            }
            Promotion::Applied { .. } | Promotion::Refused => {}
        }
        match state.cleanup {
            Cleanup::Idle => {
                if config.has(Injection::GuestCreatedLink) {
                    with(BoundaryAction::CreateLink, &|next| {
                        next.cleanup = Cleanup::Linked
                    });
                }
                with(BoundaryAction::Cleanup, &|next| {
                    next.cleanup = Cleanup::Done {
                        outside_roots: false,
                    }
                });
                return out;
            }
            Cleanup::Linked => {
                let outside = !config.enforces(Guard::HandleBasedCleanup);
                with(BoundaryAction::Cleanup, &|next| {
                    next.cleanup = Cleanup::Done {
                        outside_roots: outside,
                    }
                });
                return out;
            }
            Cleanup::Done { .. } => {}
        }
        match state.launch {
            Launch::Idle => {
                if config.has(Injection::BackendUnavailable) {
                    with(BoundaryAction::BackendFails, &|next| {
                        next.launch = Launch::BackendUnavailable
                    });
                }
                with(BoundaryAction::Launch, &|next| {
                    next.launch = Launch::Done(FallbackChoice::OtherVmSameAuthority)
                });
            }
            Launch::BackendUnavailable => {
                for choice in [
                    FallbackChoice::OtherVmSameAuthority,
                    FallbackChoice::OtherVmBroaderAuthority,
                    FallbackChoice::Container,
                    FallbackChoice::Refuse,
                ] {
                    let outcome = self.fallback(choice);
                    with(BoundaryAction::Fallback(choice), &|next| {
                        next.launch = outcome
                    });
                }
            }
            Launch::Done(_) | Launch::Refused => {}
        }
        out
    }

    fn holds(&self, invariant: InvariantId, state: &BoundaryState) -> bool {
        match invariant {
            InvariantId::GuestCannotSelectHostTarget => matches!(
                state.message,
                Stage::Idle | Stage::Refused | Stage::Done(MessageTarget::DeclaredOperation)
            ),
            InvariantId::ExecutorCannotWiden => matches!(
                state.executor,
                Stage::Idle | Stage::Refused | Stage::Done(ExecutorRequest::FixedOperation)
            ),
            InvariantId::PromotionAppliesReviewedBytes => !matches!(
                state.promotion,
                Promotion::Applied {
                    reviewed_bytes: false
                }
            ),
            InvariantId::CleanupWithinManagedRoots => !matches!(
                state.cleanup,
                Cleanup::Done {
                    outside_roots: true
                }
            ),
            InvariantId::NoFallbackWeakening => !matches!(
                state.launch,
                Launch::Done(FallbackChoice::OtherVmBroaderAuthority | FallbackChoice::Container)
            ),
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
        check_model(ModelKind::Boundary, config, Bounds::DEFAULT).unwrap()
    }

    fn last_step(result: &Exploration, invariant: InvariantId) -> Option<String> {
        result
            .violation(invariant)
            .and_then(|violation| violation.trace.steps.last().cloned())
    }

    #[test]
    fn the_host_boundary_holds_under_the_threat_model() {
        for config in [ModelConfig::correct(), ModelConfig::threat_model()] {
            let result = check(&config);
            assert!(result.complete);
            assert!(result.is_clean(), "{:?}", result.violations);
        }
    }

    #[test]
    fn each_boundary_rule_fails_with_its_guard_removed() {
        let threat = ModelConfig::threat_model();
        let cases = [
            (
                Guard::ClosedMessageSchema,
                InvariantId::GuestCannotSelectHostTarget,
                "message naming a host executable",
            ),
            (
                Guard::CredentialSealed,
                InvariantId::ExecutorCannotWiden,
                "request the credential",
            ),
            (
                Guard::HandleBasedCleanup,
                InvariantId::CleanupWithinManagedRoots,
                "clean up managed root",
            ),
            (
                Guard::FallbackKeepsVmBoundary,
                InvariantId::NoFallbackWeakening,
                "fall back to another VM backend with broader authority",
            ),
        ];
        for (guard, invariant, step) in cases {
            let result = check(&threat.clone().without_guards([guard]));
            assert_eq!(
                last_step(&result, invariant).as_deref(),
                Some(step),
                "{guard:?}"
            );
        }
    }

    #[test]
    fn widening_and_changed_artifacts_need_two_guards_to_fail() {
        let threat = ModelConfig::threat_model();
        for guard in [
            Guard::ExecutorFixedOperation,
            Guard::ProviderScopedCredential,
        ] {
            assert!(check(&threat.clone().without_guards([guard])).is_clean());
        }
        let widened = check(&threat.clone().without_guards([
            Guard::ExecutorFixedOperation,
            Guard::ProviderScopedCredential,
        ]));
        assert_eq!(
            last_step(&widened, InvariantId::ExecutorCannotWiden).as_deref(),
            Some("request a widened operation")
        );
        for guard in [Guard::PromotionDigestRecheck, Guard::PromotionHostStaging] {
            assert!(check(&threat.clone().without_guards([guard])).is_clean());
        }
        let changed = check(
            &threat.without_guards([Guard::PromotionDigestRecheck, Guard::PromotionHostStaging]),
        );
        assert_eq!(
            last_step(&changed, InvariantId::PromotionAppliesReviewedBytes).as_deref(),
            Some("apply promotion")
        );
    }
}
