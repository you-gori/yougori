//! Plan epochs for GPU §4.8 (line 736): "Coordinate epochs so in-flight requests finish
//! on their original execution plan."
//!
//! Each execution plan, such as a temporary two-node pipeline or a set of independent
//! replicas, is published under a new [`ModelActivationGeneration`] (S3.1: requests keep
//! the generation they were admitted with). Publishing a plan stops the previous one from
//! admitting; requests already admitted hold a [`PlanTicket`] and run and finish on their
//! own plan, and the previous plan is retired only after its last request finishes. A
//! ticket is bound to the authorization epoch, so after a revocation nothing admitted
//! before it is honoured again. A plan's execution identity must be one the
//! [`RequestedModel`] accepts; a pipeline is the same logical model under its own rank
//! topology, so it serves only requests that accept that execution.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::foundation::ids::{AuthorizationEpoch, ModelActivationGeneration, OperationId};
use crate::model_memory::identity::ExecutionIdentity;
use crate::model_memory::placement::ActivationContent;

use super::joint::RequestedModel;

/// What a plan runs on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PlanKind {
    /// Complementary layers on `stages` nodes, serving while full replicas load.
    Pipeline { stages: u32 },
    /// `nodes` independent full replicas.
    Replicas { nodes: u32 },
}

/// A plan as published.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlanPublication {
    pub generation: ModelActivationGeneration,
    pub execution: ExecutionIdentity,
    pub kind: PlanKind,
}

impl PlanPublication {
    /// The plan a placement slot published (§3.6 step 5): its generation and execution.
    pub fn from_activation(content: &ActivationContent, kind: PlanKind) -> Self {
        Self {
            generation: content.generation,
            execution: content.execution,
            kind,
        }
    }
}

/// An admitted request: the plan it keeps and the epoch it was admitted under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanTicket {
    pub request: OperationId,
    pub plan: ModelActivationGeneration,
    pub epoch: AuthorizationEpoch,
}

/// Where a plan is in its life.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanState {
    /// The current plan: new requests are admitted to it.
    Admitting,
    /// Superseded: it admits nothing and finishes its in-flight requests.
    Draining,
    /// Drained and released, or ended by a revocation.
    Retired,
}

/// Why an epoch operation was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EpochRefusal {
    /// The plan's execution is not one the requested model accepts; nothing is
    /// substituted.
    NotAccepted {
        execution: ExecutionIdentity,
    },
    /// A published generation must exceed every earlier one.
    NotNewer {
        published: ModelActivationGeneration,
        latest: ModelActivationGeneration,
    },
    /// No plan admits requests.
    NoPlan,
    /// The request presented another authorization epoch than the bound one (S3.1).
    AuthorityMismatch {
        presented: AuthorizationEpoch,
        bound: AuthorizationEpoch,
    },
    /// The ticket was admitted under an older authorization epoch.
    Revoked {
        ticket: AuthorizationEpoch,
    },
    /// The request is in flight on another plan; it never moves mid-request.
    PlanChanged {
        admitted: ModelActivationGeneration,
        offered: ModelActivationGeneration,
    },
    UnknownPlan {
        plan: ModelActivationGeneration,
    },
    UnknownTicket,
    DuplicateRequest,
    /// The plan still has requests in flight.
    InFlight {
        plan: ModelActivationGeneration,
        requests: usize,
    },
    /// Only a superseded plan is retired.
    StillCurrent {
        plan: ModelActivationGeneration,
    },
    /// A revocation must raise the epoch.
    EpochNotRaised {
        bound: AuthorizationEpoch,
        offered: AuthorizationEpoch,
    },
}

impl fmt::Display for EpochRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAccepted { execution } => {
                write!(f, "execution {execution} is not one the request accepts")
            }
            Self::NotNewer { published, latest } => write!(
                f,
                "plan generation {published} does not exceed the latest, {latest}"
            ),
            Self::NoPlan => f.write_str("no plan admits requests"),
            Self::AuthorityMismatch { presented, bound } => write!(
                f,
                "authorization epoch {presented} is not the bound epoch {bound}"
            ),
            Self::Revoked { ticket } => write!(
                f,
                "the request was admitted under authorization epoch {ticket}, since revoked"
            ),
            Self::PlanChanged { admitted, offered } => write!(
                f,
                "the request was admitted to plan {admitted} and cannot run on plan {offered}"
            ),
            Self::UnknownPlan { plan } => write!(f, "no plan {plan}"),
            Self::UnknownTicket => f.write_str("the ticket is not in flight"),
            Self::DuplicateRequest => f.write_str("the request is already in flight"),
            Self::InFlight { plan, requests } => {
                write!(f, "plan {plan} still has {requests} requests in flight")
            }
            Self::StillCurrent { plan } => write!(f, "plan {plan} is still the current plan"),
            Self::EpochNotRaised { bound, offered } => write!(
                f,
                "a revocation must raise the epoch above {bound}; {offered} does not"
            ),
        }
    }
}

impl std::error::Error for EpochRefusal {}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PlanRecord {
    publication: PlanPublication,
    state: PlanState,
    in_flight: BTreeSet<OperationId>,
}

/// What finishing a request left behind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinishReport {
    pub plan: ModelActivationGeneration,
    /// The plan is superseded and has nothing in flight, so it may be retired.
    pub drained: bool,
}

/// The plans of one model under one authorization epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanEpochs {
    model: RequestedModel,
    epoch: AuthorizationEpoch,
    plans: BTreeMap<ModelActivationGeneration, PlanRecord>,
    current: Option<ModelActivationGeneration>,
}

impl PlanEpochs {
    pub fn new(model: RequestedModel, epoch: AuthorizationEpoch) -> Self {
        Self {
            model,
            epoch,
            plans: BTreeMap::new(),
            current: None,
        }
    }

    pub fn epoch(&self) -> AuthorizationEpoch {
        self.epoch
    }

    /// The plan new requests are admitted to.
    pub fn current(&self) -> Option<&PlanPublication> {
        self.current
            .and_then(|plan| self.plans.get(&plan))
            .map(|record| &record.publication)
    }

    pub fn state(&self, plan: ModelActivationGeneration) -> Option<PlanState> {
        self.plans.get(&plan).map(|record| record.state)
    }

    /// Requests in flight on `plan`.
    pub fn in_flight(&self, plan: ModelActivationGeneration) -> usize {
        self.plans
            .get(&plan)
            .map_or(0, |record| record.in_flight.len())
    }

    /// Publishes `publication` in one step: it becomes the plan new requests are admitted
    /// to, and the previous plan drains. Returns the previous plan.
    pub fn publish(
        &mut self,
        publication: PlanPublication,
    ) -> Result<Option<ModelActivationGeneration>, EpochRefusal> {
        if !self.model.accepts(&publication.execution) {
            return Err(EpochRefusal::NotAccepted {
                execution: publication.execution,
            });
        }
        if let Some((&latest, _)) = self.plans.last_key_value() {
            if publication.generation <= latest {
                return Err(EpochRefusal::NotNewer {
                    published: publication.generation,
                    latest,
                });
            }
        }
        let previous = self.current.replace(publication.generation);
        if let Some(previous) = previous {
            if let Some(record) = self.plans.get_mut(&previous) {
                record.state = PlanState::Draining;
            }
        }
        self.plans.insert(
            publication.generation,
            PlanRecord {
                publication,
                state: PlanState::Admitting,
                in_flight: BTreeSet::new(),
            },
        );
        Ok(previous)
    }

    /// Admits `request` to the current plan under `epoch`.
    pub fn admit(
        &mut self,
        request: OperationId,
        epoch: AuthorizationEpoch,
    ) -> Result<PlanTicket, EpochRefusal> {
        if epoch != self.epoch {
            return Err(EpochRefusal::AuthorityMismatch {
                presented: epoch,
                bound: self.epoch,
            });
        }
        let plan = self.current.ok_or(EpochRefusal::NoPlan)?;
        if self
            .plans
            .values()
            .any(|record| record.in_flight.contains(&request))
        {
            return Err(EpochRefusal::DuplicateRequest);
        }
        let record = self
            .plans
            .get_mut(&plan)
            .ok_or(EpochRefusal::UnknownPlan { plan })?;
        record.in_flight.insert(request.clone());
        Ok(PlanTicket {
            request,
            plan,
            epoch,
        })
    }

    fn check_ticket(&self, ticket: &PlanTicket) -> Result<&PlanRecord, EpochRefusal> {
        if ticket.epoch != self.epoch {
            return Err(EpochRefusal::Revoked {
                ticket: ticket.epoch,
            });
        }
        let record = self
            .plans
            .get(&ticket.plan)
            .ok_or(EpochRefusal::UnknownPlan { plan: ticket.plan })?;
        if !record.in_flight.contains(&ticket.request) {
            return Err(EpochRefusal::UnknownTicket);
        }
        Ok(record)
    }

    /// Checks that a step of the request may run on `plan`: only its own plan, never
    /// another one, even a newer one.
    pub fn run_on(
        &self,
        ticket: &PlanTicket,
        plan: ModelActivationGeneration,
    ) -> Result<(), EpochRefusal> {
        self.check_ticket(ticket)?;
        if plan != ticket.plan {
            return Err(EpochRefusal::PlanChanged {
                admitted: ticket.plan,
                offered: plan,
            });
        }
        Ok(())
    }

    /// Finishes the request on its own plan.
    pub fn finish(&mut self, ticket: &PlanTicket) -> Result<FinishReport, EpochRefusal> {
        self.check_ticket(ticket)?;
        let current = self.current;
        let record = self
            .plans
            .get_mut(&ticket.plan)
            .ok_or(EpochRefusal::UnknownPlan { plan: ticket.plan })?;
        record.in_flight.remove(&ticket.request);
        Ok(FinishReport {
            plan: ticket.plan,
            drained: Some(ticket.plan) != current && record.in_flight.is_empty(),
        })
    }

    /// Retires a superseded plan once nothing is in flight on it.
    pub fn retire(&mut self, plan: ModelActivationGeneration) -> Result<(), EpochRefusal> {
        if self.current == Some(plan) {
            return Err(EpochRefusal::StillCurrent { plan });
        }
        let record = self
            .plans
            .get_mut(&plan)
            .ok_or(EpochRefusal::UnknownPlan { plan })?;
        if !record.in_flight.is_empty() {
            return Err(EpochRefusal::InFlight {
                plan,
                requests: record.in_flight.len(),
            });
        }
        record.state = PlanState::Retired;
        Ok(())
    }

    /// A revocation raised the authorization epoch to `raised`: every plan ends, every
    /// in-flight request is cancelled (returned) and nothing admitted before is honoured
    /// again. Plans must be published again under the new epoch.
    pub fn revoke(&mut self, raised: AuthorizationEpoch) -> Result<Vec<OperationId>, EpochRefusal> {
        if raised <= self.epoch {
            return Err(EpochRefusal::EpochNotRaised {
                bound: self.epoch,
                offered: raised,
            });
        }
        let mut cancelled = Vec::new();
        for record in self.plans.values_mut() {
            cancelled.extend(std::mem::take(&mut record.in_flight));
            record.state = PlanState::Retired;
        }
        self.current = None;
        self.epoch = raised;
        Ok(cancelled)
    }
}
