//! Labelled runtimes' authority records (S1, S3.5, INT-07; T13 decision 4).
//!
//! A labelled runtime runs in a non-VM execution category kept by a recorded decision:
//! the shared-kernel GPU runtime (VM-D4), a provider container (VM-D5) or the host-process
//! model runtime (VM-D6). It never gets the VM sandbox lifecycle and is never presented as
//! a sandbox. The coordination authority still records what it was authorized to run: its
//! exact runtime, an authority grant under its own authorization epoch, the network
//! grants and verified artifacts its models may use, the loader the gate enabled for it,
//! and the settings each model was authorized with. Fallbacks such as a profile revert are
//! judged against that record ([`Coordinator::authorized_settings`]), never against a
//! caller's settings. Like every authority, it is granted afresh and never revived: the
//! records are not persisted, so recovery holds none.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::Serialize;

use super::capacity::CapacityPort;
use super::coordinator::{admitted_category, settings_within, CoordinationError, Coordinator};
use super::identity::ModelId;
use super::lease::LeaseRefusal;
use super::model::ModelRefusal;
use super::sandbox::{
    GenerationName, LaunchFailure, LoaderGrant, SettingsGrant, TransitionRefusal,
};
use crate::foundation::evidence::{
    AdmittedRuntime, AuthorityGrant, ClockSession, NetworkGrant, ProbeRegistry, RuntimeOffer,
    RuntimeRequirement, RuntimeSettings, RuntimeSubject,
};
use crate::foundation::ids::{AuthorizationEpoch, Clock, ExecutionId, MonotonicTime, TenantId};

/// What to authorize for a labelled runtime (INT-07).
#[derive(Clone, Debug)]
pub struct LabelledAuthorization {
    pub execution: ExecutionId,
    pub tenant: TenantId,
    /// The runtime CORE-01 evidence admitted, in a labelled category.
    pub runtime: AdmittedRuntime,
    /// How long granted authority lasts.
    pub authority_lifetime: Duration,
    /// How old the runtime's category evidence may be when it is rechecked before
    /// authority is granted.
    pub runtime_evidence_max_age: Duration,
    /// What the runtime's models may use (S3.5).
    pub settings: SettingsGrant,
}

/// The authority record of one labelled runtime: the actual runtime its models are
/// authorized in, under its own authorization epoch (S3.1, INT-07).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LabelledRuntime {
    execution: ExecutionId,
    tenant: TenantId,
    runtime: RuntimeSubject,
    epoch: AuthorizationEpoch,
    authority: AuthorityGrant,
    settings: SettingsGrant,
    loader: Option<LoaderGrant>,
    models: BTreeMap<ModelId, RuntimeSettings>,
}

impl LabelledRuntime {
    /// The execution the runtime serves.
    pub fn execution(&self) -> &ExecutionId {
        &self.execution
    }

    /// The tenant whose grants apply.
    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// The exact runtime, with its labelled execution category.
    pub fn runtime(&self) -> &RuntimeSubject {
        &self.runtime
    }

    /// The authorization epoch in force; revocation raises it.
    pub fn epoch(&self) -> AuthorizationEpoch {
        self.epoch
    }

    /// The latest authority granted; honoured only under the epoch in force and before
    /// it expires.
    pub fn authority(&self) -> AuthorityGrant {
        self.authority
    }

    /// What the runtime's models may use (S3.5).
    pub fn settings_grant(&self) -> &SettingsGrant {
        &self.settings
    }

    /// The loader optimizations granted with the authority, if any (INT-06).
    pub fn loader_grant(&self) -> Option<&LoaderGrant> {
        self.loader.as_ref()
    }

    /// The settings `model` was authorized with under the authority in force.
    pub fn model_settings(&self, model: ModelId) -> Option<&RuntimeSettings> {
        self.models.get(&model)
    }

    /// Withdraws the network grants `named` picks from what the authority grants the
    /// runtime's models, as for a sandbox (CORE-04 per-grant revocation). Returns one of
    /// them, if any was granted.
    pub(super) fn withdraw_network(
        &mut self,
        named: impl Fn(&NetworkGrant) -> bool,
    ) -> Option<NetworkGrant> {
        self.settings.withdraw_network(named)
    }

    /// The authority honoured at `now` on `session`, or why none is.
    pub(super) fn current_authority(
        &self,
        now: MonotonicTime,
        session: ClockSession,
    ) -> Result<AuthorityGrant, LeaseRefusal> {
        if self.authority.clock != session {
            return Err(LeaseRefusal::OtherClock);
        }
        if self.authority.epoch != self.epoch {
            return Err(LeaseRefusal::RevokedAuthorization {
                bound: self.authority.epoch,
                current: self.epoch,
            });
        }
        if now >= self.authority.expires_at {
            return Err(LeaseRefusal::AuthorityExpired {
                expired_at: self.authority.expires_at,
            });
        }
        Ok(self.authority)
    }
}

/// Rechecks, on the registry's evidence now, that the admitted runtime is still in its
/// labelled category (INT-07), before authority is granted.
fn recheck_labelled<R: Clock>(
    runtime: &AdmittedRuntime,
    registry: &ProbeRegistry<R>,
    max_age: Duration,
) -> Result<(), CoordinationError> {
    let category = admitted_category(runtime);
    let requirement = RuntimeRequirement::explicit([category])
        .map_err(|_| CoordinationError::NotALabelledRuntime { category })?;
    let offer = RuntimeOffer::observe(
        registry,
        runtime.runtime().clone(),
        max_age,
        runtime.evidence().configuration(),
    )
    .map_err(|refusal| CoordinationError::NotAdmitted {
        failure: LaunchFailure::RuntimeEvidence { refusal },
    })?;
    requirement
        .admit(&offer)
        .map(|_| ())
        .map_err(|refusal| CoordinationError::NotAdmitted {
            failure: LaunchFailure::RuntimeCategory { refusal },
        })
}

impl<C: Clock, P: CapacityPort> Coordinator<C, P> {
    /// Grants authority to a labelled runtime (INT-07: it never gets the VM sandbox
    /// lifecycle): its category evidence is rechecked on `registry` first, and its models
    /// may use what `authorization.settings` grants, less any network grant revoked under
    /// the execution, which is never granted again ([`Coordinator::revoke_grant`]).
    /// Authorizing a runtime that still holds authority changes nothing; after a
    /// revocation or an expiry the grant comes under a new authorization epoch, and the
    /// loader and the models' settings are authorized again. A VM sandbox, or an execution
    /// recorded as one, is refused: it is launched.
    pub fn authorize_labelled<R: Clock>(
        &mut self,
        authorization: LabelledAuthorization,
        registry: &ProbeRegistry<R>,
    ) -> Result<AuthorityGrant, CoordinationError> {
        let category = admitted_category(&authorization.runtime);
        if category.is_vm_sandbox() || self.sandboxes.contains_key(&authorization.execution) {
            return Err(CoordinationError::NotALabelledRuntime { category });
        }
        let now = self.monotonic_now();
        let session = self.session;
        let epoch = match self.labelled.get(&authorization.execution) {
            None => AuthorizationEpoch::FIRST,
            Some(record) if record.tenant != authorization.tenant => {
                return Err(CoordinationError::TenantMismatch {
                    execution: authorization.execution,
                })
            }
            Some(record) if &record.runtime != authorization.runtime.runtime() => {
                return Err(CoordinationError::RuntimeMismatch {
                    execution: authorization.execution,
                })
            }
            Some(record) => match record.current_authority(now, session) {
                Ok(grant) => return Ok(grant),
                Err(_) if record.authority.epoch == record.epoch => {
                    record.epoch.next().ok_or(CoordinationError::Transition {
                        refusal: TransitionRefusal::GenerationExhausted {
                            generation: GenerationName::Authorization,
                        },
                    })?
                }
                Err(_) => record.epoch,
            },
        };
        recheck_labelled(
            &authorization.runtime,
            registry,
            authorization.runtime_evidence_max_age,
        )?;
        let grant = AuthorityGrant {
            epoch,
            clock: session,
            expires_at: now.saturating_add(authorization.authority_lifetime),
        };
        let settings = self.without_revoked(&authorization.execution, authorization.settings);
        self.labelled.insert(
            authorization.execution.clone(),
            LabelledRuntime {
                execution: authorization.execution,
                tenant: authorization.tenant,
                runtime: authorization.runtime.runtime().clone(),
                epoch,
                authority: grant,
                settings,
                loader: None,
                models: BTreeMap::new(),
            },
        );
        Ok(grant)
    }

    /// Records `settings` as the settings `model` was authorized with in the labelled
    /// runtime `execution`: its category, within the authority it holds now, and within
    /// what that authority grants its models (S3.5). The record is the baseline its
    /// fallbacks are judged against ([`Coordinator::authorized_settings`]).
    pub fn authorize_labelled_model(
        &mut self,
        execution: &ExecutionId,
        model: ModelId,
        settings: RuntimeSettings,
    ) -> Result<(), ModelRefusal> {
        let parent = |refusal| ModelRefusal::Parent { refusal };
        let now = self.monotonic_now();
        let session = self.session;
        let record = self
            .labelled
            .get_mut(execution)
            .ok_or_else(|| ModelRefusal::Parent {
                refusal: LeaseRefusal::UnknownExecution {
                    execution: execution.clone(),
                },
            })?;
        let grant = record.current_authority(now, session).map_err(parent)?;
        if settings.execution_category != record.runtime.category {
            return Err(ModelRefusal::CategoryMismatch {
                parent: record.runtime.category,
                settings: settings.execution_category,
            });
        }
        if settings.authority.epoch != grant.epoch
            || settings.authority.clock != grant.clock
            || settings.authority.expires_at > grant.expires_at
        {
            return Err(ModelRefusal::AuthorityExceedsParent {
                parent: grant,
                settings: settings.authority,
            });
        }
        settings_within(&settings, &record.settings, record.loader.as_ref())?;
        record.models.insert(model, settings);
        Ok(())
    }

    /// Revokes a labelled runtime's authority (INT-02): its authorization epoch advances,
    /// so the grant and every model's settings under it are never honoured again, and its
    /// loader grant ends. Revoking again changes nothing. Returns the epoch now in force.
    pub fn revoke_labelled(
        &mut self,
        execution: &ExecutionId,
    ) -> Result<AuthorizationEpoch, CoordinationError> {
        let record = self.labelled.get_mut(execution).ok_or_else(|| {
            CoordinationError::UnknownExecution {
                execution: execution.clone(),
            }
        })?;
        if record.authority.epoch == record.epoch {
            record.epoch = record.epoch.next().ok_or(CoordinationError::Transition {
                refusal: TransitionRefusal::GenerationExhausted {
                    generation: GenerationName::Authorization,
                },
            })?;
            record.loader = None;
            record.models.clear();
        }
        Ok(record.epoch)
    }

    /// The authority record of the labelled runtime `execution`, if it has one.
    pub fn labelled_runtime(&self, execution: &ExecutionId) -> Option<&LabelledRuntime> {
        self.labelled.get(execution)
    }

    /// The authority the labelled runtime `execution` holds now, or why none is honoured:
    /// an unknown execution, a revoked epoch, an expired grant, another clock session, or
    /// a clock reading behind its high-water mark. For adapters that act under a labelled
    /// record, such as a provider container's (V12), so they never mirror the check.
    pub fn labelled_authority(
        &self,
        execution: &ExecutionId,
    ) -> Result<AuthorityGrant, LeaseRefusal> {
        let now = self.lease_time()?;
        let record =
            self.labelled
                .get(execution)
                .ok_or_else(|| LeaseRefusal::UnknownExecution {
                    execution: execution.clone(),
                })?;
        record.current_authority(now, self.session)
    }

    /// Grants the labelled runtime `execution` the loader `plan` enabled, as
    /// [`Coordinator::grant_loader`] does for a sandbox.
    pub(super) fn grant_labelled_loader(
        &mut self,
        execution: &ExecutionId,
        plan: &crate::foundation::evidence::LoaderPlan,
    ) -> Result<(), ModelRefusal> {
        let now = self.monotonic_now();
        let session = self.session;
        let record = self
            .labelled
            .get_mut(execution)
            .ok_or_else(|| ModelRefusal::Parent {
                refusal: LeaseRefusal::UnknownExecution {
                    execution: execution.clone(),
                },
            })?;
        if plan.runtime() != &record.runtime {
            return Err(ModelRefusal::PlanForOtherRuntime {
                plan: plan.runtime().clone(),
                runtime: record.runtime.clone(),
            });
        }
        record
            .current_authority(now, session)
            .map_err(|refusal| ModelRefusal::Parent { refusal })?;
        record.loader = Some(LoaderGrant::from_plan(plan));
        Ok(())
    }

    /// The settings the labelled runtime's record authorizes for `model` now: its
    /// category, grants and current authority, with the loader, batch size and residency
    /// `model` was authorized with.
    pub(super) fn labelled_settings(
        &self,
        execution: &ExecutionId,
        model: ModelId,
    ) -> Option<Result<RuntimeSettings, ModelRefusal>> {
        let record = self.labelled.get(execution)?;
        let settings = record
            .current_authority(self.monotonic_now(), self.session)
            .map_err(|refusal| ModelRefusal::Parent { refusal })
            .and_then(|grant| {
                let recorded = record
                    .models
                    .get(&model)
                    .cloned()
                    .ok_or(ModelRefusal::NoPriorActivation { model })?;
                Ok(RuntimeSettings {
                    execution_category: record.runtime.category,
                    network: record.settings.network.clone(),
                    authority: grant,
                    artifact_verification:
                        crate::foundation::evidence::ArtifactVerification::Verified {
                            artifacts: record.settings.verified_artifacts.clone(),
                        },
                    ..recorded
                })
            });
        Some(settings)
    }
}
