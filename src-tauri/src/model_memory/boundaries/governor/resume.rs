//! Paused reloads resume through the governor (G03 of docs/combined-plan-leftover-tasks.md:
//! "a paused reload resumes only when its activation is retried"; GPU-W05 of
//! docs/combined-gpu-memory-and-vm-sandbox-plan.md, line 1231: "expose pause/reload
//! behavior when double residency is impossible", and its GPU part §3.6, line 769: "drain
//! first and report a real pause").
//!
//! A reload waits in its slot while its old generation drains. A retried admission of the
//! same activation moves it on; without one, serving stayed paused.
//! [`LedgerPolicyGovernor::resume_reloads`] moves every waiting reload on by itself, once
//! its preconditions return:
//!
//! - lease: every old-generation lease ended, by its request finishing or at the drain
//!   deadline, which ends the rest;
//! - capacity: the reload's bounded transfer staging is granted by the CORE-03 ledger;
//! - generation still current: the authority it was admitted under still holds (the
//!   runtime's authorization epoch is the slot's, S3.1), and the coordinator still prepares
//!   its generation, with no newer generation of the model.
//!
//! A reload whose preconditions returned resumes once, with the admission a retry would
//! have received ([`ReloadResumption::Resumed`]); its caller continues it as the flow
//! continues a retried admission (hand over, load, publish). A reload whose authority was
//! revoked or whose generation was superseded never resumes, on this path or on a retry:
//! it ends, its activation is abandoned and its reservation closed. A drained reload waits
//! for its staging only until its bound (`resume_by`: the drain deadline plus the drain's
//! bound again), then ends too. Every outcome is explicit, and each call does a bounded
//! amount of work: one look and at most one staging reservation per waiting reload.

use std::collections::VecDeque;

use serde::Serialize;

use super::lifecycle::Site;
use super::{
    ledger_priority, AbandonedActivation, Admission, AdmissionRefusal, AdmissionRequest,
    CapacityRefusal, GovernorError, HostLedger, LedgerGrant, LedgerPolicyGovernor,
    PlacementGovernor, PlacementKey, ReloadPhase, ReloadStatus, TransferBudget,
};
use crate::foundation::coordination::ActivationState;
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{
    AuthorizationEpoch, Clock, ModelActivationGeneration, MonotonicTime, OperationId,
};

/// The most ended reloads kept for [`LedgerPolicyGovernor::resume_reloads`] to report;
/// beyond it the oldest are dropped, and [`LedgerPolicyGovernor::last_abandoned`] still
/// names each one's abandoned activation.
pub const MAX_ENDED_RELOADS: usize = 64;

/// Why a paused reload ended without resuming.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "end", rename_all = "snake_case")]
pub enum ReloadEnd {
    /// The authority it was admitted under no longer holds: the runtime's authorization
    /// epoch moved on, or its runtime is gone. Nothing bound to it resumes (S3.1).
    AuthorityRevoked { error: GovernorError },
    /// The coordinator no longer prepares its generation, or a newer generation of the
    /// model exists.
    Superseded {
        /// Where the coordinator has its generation, if it still has it.
        state: Option<ActivationState>,
        /// The model's newest generation at the coordinator.
        latest: Option<ModelActivationGeneration>,
    },
    /// Its old generation drained, but its staging was not granted by `resume_by`.
    TimedOut { resume_by: MonotonicTime },
    /// Its drain or its staging failed other than for capacity.
    Faulted { refusal: AdmissionRefusal },
}

/// A paused reload that ended without resuming. Its activation was abandoned and its
/// reservation closed; nothing serves until another activation publishes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EndedReload {
    pub placement: PlacementKey,
    pub epoch: AuthorizationEpoch,
    /// The request whose admission began the reload.
    pub operation: OperationId,
    pub reloading: ModelActivationGeneration,
    /// The old generation, which stopped admitting when serving paused. Its memory counts
    /// until the runtime frees it and [`PlacementGovernor::confirm_released`] reclaims it.
    pub draining: ModelActivationGeneration,
    pub end: ReloadEnd,
    /// The abandoned activation, saying what serves and whether the old content could
    /// serve again without a reload. `None` when abandoning it was refused, as `faults`
    /// says: the activation then waits again, and a later call ends it.
    pub abandoned: Option<AbandonedActivation>,
    /// What could not be undone.
    pub faults: Vec<GovernorError>,
}

/// One waiting reload after [`LedgerPolicyGovernor::resume_reloads`].
#[derive(Debug, PartialEq, Eq)]
pub enum ReloadResumption {
    /// It still waits: old requests run, or the ledger refused its staging for now.
    Waiting {
        status: ReloadStatus,
        /// The staging refusal, once the old generation drained.
        capacity: Option<CapacityRefusal>,
        /// Once drained, it waits for staging until then at the latest.
        resume_by: MonotonicTime,
    },
    /// Its preconditions returned: the admission a retry of `operation` would have
    /// received, with the drained generation to hand over. It resumes once; a retry now
    /// waits with the pause's status until the new generation publishes.
    Resumed {
        operation: OperationId,
        admission: Admission,
    },
    /// It ended without resuming.
    Ended(Box<EndedReload>),
}

/// Reloads ended on a retried admission, until they are reported.
#[derive(Default)]
pub(super) struct EndedReloads {
    ended: VecDeque<EndedReload>,
}

impl EndedReloads {
    fn push(&mut self, ended: EndedReload) {
        if self.ended.len() >= MAX_ENDED_RELOADS {
            self.ended.pop_front();
        }
        self.ended.push_back(ended);
    }
}

impl<C: Clock + Clone, P: HostLedger<C>> LedgerPolicyGovernor<C, P> {
    /// Moves every waiting reload on (G03): each resumes once its old generation drained
    /// and its staging is granted, or ends when its authority was revoked, its generation
    /// superseded or its bound passed. Reloads a retried admission ended come first. Call
    /// it when old requests may have finished, capacity may have returned or a drain
    /// deadline may have passed, such as on a periodic tick; it never waits.
    pub fn resume_reloads(&mut self) -> Vec<ReloadResumption> {
        let mut outcomes: Vec<ReloadResumption> = self
            .ended_reloads
            .ended
            .drain(..)
            .map(|ended| ReloadResumption::Ended(Box::new(ended)))
            .collect();
        let waiting: Vec<Site> = self
            .slots
            .iter()
            .filter(|(_, slot)| {
                slot.reload
                    .as_ref()
                    .is_some_and(|reload| reload.pending.is_some())
            })
            .map(|(site, _)| *site)
            .collect();
        for site in waiting {
            if let Some(outcome) = self.resume_reload(site) {
                outcomes.push(outcome);
            }
        }
        outcomes
    }

    /// Ends the reload waiting at `site` if its generation is no longer current, before a
    /// retried admission could continue it; the outcome waits for
    /// [`Self::resume_reloads`].
    pub(super) fn end_stale_reload(&mut self, site: Site) {
        if !self.reload_waits(site) {
            return;
        }
        if let Some(end) = self.reload_stale(site) {
            if let Some(ended) = self.end_reload(site, end) {
                self.ended_reloads.push(ended);
            }
        }
    }

    /// Whether a reload's activation waits in the slot at `site`, not yet taken.
    fn reload_waits(&self, site: Site) -> bool {
        self.slots
            .get(&site)
            .and_then(|slot| slot.reload.as_ref())
            .is_some_and(|reload| reload.pending.is_some())
    }

    fn resume_reload(&mut self, site: Site) -> Option<ReloadResumption> {
        let (request, resume_by) = self
            .slots
            .get(&site)
            .and_then(|slot| slot.reload.as_ref())
            .filter(|reload| reload.pending.is_some())
            .map(|reload| (reload.request.clone(), reload.resume_by))?;
        if let Some(end) = self.reload_stale(site) {
            return self.ended(site, end);
        }
        let status = match self.advance_reload(site.0, site.1) {
            Ok(status) => status,
            Err(refusal) => return self.ended(site, ReloadEnd::Faulted { refusal }),
        };
        if status.phase != ReloadPhase::HandingOver {
            return Some(ReloadResumption::Waiting {
                status,
                capacity: None,
                resume_by,
            });
        }
        let (staging, budget) = match self.reload_staging(&request) {
            Ok(staged) => staged,
            Err(AdmissionRefusal::Capacity { refusal }) if self.clock.now() < resume_by => {
                return Some(ReloadResumption::Waiting {
                    status,
                    capacity: Some(refusal),
                    resume_by,
                });
            }
            Err(AdmissionRefusal::Capacity { .. }) => {
                return self.ended(site, ReloadEnd::TimedOut { resume_by });
            }
            Err(refusal) => return self.ended(site, ReloadEnd::Faulted { refusal }),
        };
        let Some((pending, drained)) = self.take_reload(site.0, site.1) else {
            // Nothing waits to be taken any more: the staging goes back unused.
            if let Some(grant) = staging {
                let _released = self.release(grant);
            }
            return None;
        };
        let transfer_budget = budget.map(|budget| self.land(&pending, budget));
        Some(ReloadResumption::Resumed {
            operation: request.authority.operation.clone(),
            admission: Admission {
                activation: Some(pending),
                staging,
                transfer_budget,
                handover: Some(drained),
            },
        })
    }

    /// Why the reload at `site` may no longer resume, if it may not: it may while the
    /// authority it was admitted under holds and the coordinator still prepares its
    /// generation as the model's newest, in the slot's activation in progress.
    fn reload_stale(&self, site: Site) -> Option<ReloadEnd> {
        let slot = self.slots.get(&site)?;
        let reload = slot.reload.as_ref()?;
        let binding = match self.check_authority(&reload.request.authority, site.0.owner) {
            Ok(binding) => binding,
            Err(error) => return Some(ReloadEnd::AuthorityRevoked { error }),
        };
        let activations = self
            .coordinator
            .model_activations(&binding.execution, site.0.model_id());
        let state = activations
            .and_then(|activations| activations.activation(reload.reloading))
            .map(|activation| activation.state());
        let latest = activations
            .and_then(|activations| activations.latest())
            .map(|activation| activation.generations().activation);
        let in_slot = slot
            .slot
            .activation()
            .is_some_and(|activation| activation.generation == reload.reloading);
        let current =
            state == Some(ActivationState::Loading) && latest == Some(reload.reloading) && in_slot;
        (!current).then_some(ReloadEnd::Superseded { state, latest })
    }

    /// The staging and transfer budget the reload's transfers need, as its admission
    /// reserved them: bounded pinned staging charged to host RAM too.
    // The refusal is the admission's own, as `admit` and `reserve_staging` return it.
    #[allow(clippy::result_large_err)]
    fn reload_staging(
        &mut self,
        request: &AdmissionRequest,
    ) -> Result<(Option<LedgerGrant>, Option<TransferBudget>), AdmissionRefusal> {
        let overflow = AdmissionRefusal::Overflow {
            field: "transfer bytes",
        };
        let transfer_bytes = request
            .transfer
            .values()
            .try_fold(0u64, |total, bytes| total.checked_add(*bytes))
            .ok_or(overflow.clone())?;
        if transfer_bytes == 0 {
            return Ok((None, None));
        }
        let staging_bytes = transfer_bytes.min(self.policy.staging_cap_bytes);
        if staging_bytes == 0 {
            return Err(AdmissionRefusal::NoStaging);
        }
        let runtime = |error| AdmissionRefusal::Runtime { error };
        let owner = request.placement.owner;
        let binding = self
            .check_authority(&request.authority, owner)
            .map_err(runtime)?;
        let priority = ledger_priority(self.sandbox(&binding).map_err(runtime)?.priority());
        let parent = self.sandbox_reservation(&binding).map_err(runtime)?.id();
        let budget =
            TransferBudget::inbound(request.transfer.clone(), owner.device).ok_or(overflow)?;
        let grant =
            self.reserve_staging(request, &binding.execution, parent, priority, staging_bytes)?;
        Ok((Some(grant), Some(budget)))
    }

    /// [`Self::end_reload`] as an outcome.
    fn ended(&mut self, site: Site, end: ReloadEnd) -> Option<ReloadResumption> {
        self.end_reload(site, end)
            .map(|ended| ReloadResumption::Ended(Box::new(ended)))
    }

    /// Ends the reload waiting at `site` for `end`: abandons its activation and closes the
    /// reservation, which nothing was handed for, as a refused admission's is closed.
    /// `None` when no activation waits there.
    fn end_reload(&mut self, site: Site, end: ReloadEnd) -> Option<EndedReload> {
        let (pending, reloading, draining, operation) = self
            .slots
            .get_mut(&site)
            .and_then(|slot| slot.reload.as_mut())
            .and_then(|reload| {
                let pending = reload.pending.take()?;
                Some((
                    pending,
                    reload.reloading,
                    reload.draining,
                    reload.request.authority.operation.clone(),
                ))
            })?;
        let mut faults = Vec::new();
        let abandoned = match self.abandon_activation(pending) {
            Ok(abandoned) => {
                if let Err(fault) =
                    self.confirm_released(&site.0, reloading, SourceClass::GuestReport)
                {
                    faults.push(fault);
                }
                Some(abandoned)
            }
            Err(refused) => {
                // The activation waits again, so a later call ends it.
                faults.push(refused.error);
                if let Some(reload) = self
                    .slots
                    .get_mut(&site)
                    .and_then(|slot| slot.reload.as_mut())
                {
                    reload.pending = Some(refused.pending);
                }
                None
            }
        };
        Some(EndedReload {
            placement: site.0,
            epoch: site.1,
            operation,
            reloading,
            draining,
            end,
            abandoned,
            faults,
        })
    }
}
