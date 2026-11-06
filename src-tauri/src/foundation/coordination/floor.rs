//! The durable authority floor (S2 CORE-04; VM part §6.1: "a single durable state
//! machine"; §6.2: "Persist enough state to prevent clock rollback or snapshot restore from
//! reviving expired rights"; §6.3 step 1: "advances the durable epoch or records a
//! generation tombstone", and "never reuse an identity while old valid capabilities can
//! exist"; VM-W29: durable policy epochs, restart and snapshot rollback;
//! docs/combined-plan-remaining-only.md §8, S04 / M13 / M17: "A restored snapshot ...
//! cannot revive authorization").
//!
//! [`PersistedState`] is what recovery reconciles from; the floor is what it never goes
//! below. [`AuthorityFloor::seal`] takes, from a state just stored durably, everything that
//! only rises: the coordination authority's run, the lease-id high-water mark, every
//! sandbox's generations, every model's next generations, every grant tombstone, a
//! receiver's replay limits and floors, and the last sequence of the durable revocation
//! stream. Sealing refuses a state below the floor, so the floor never moves back.
//!
//! [`AuthorityFloor::restore`] runs at a restart, after
//! [`PersistedState::adopt_revocations`] and before [`Coordinator::recover`]. A state at or
//! above the floor everywhere is the newest durable state and recovers as it is. A state
//! below it, such as a restored backup or VM snapshot of the engine's data, is never
//! trusted: it is upgraded to the floor, with its run, lease mark, generations, tombstones
//! and replay state raised and any sandbox or model it lacks recreated at the floor's
//! generations, and every sandbox whose record was below the floor is ended after recovery
//! ([`Coordinator::end_stale`]), since its recorded VM and authority are not the ones the
//! floor saw. A revocation stream behind the floor's last sequence, rolled back or
//! replaced, refuses the restore: revocations it recorded may be missing.
//!
//! Protocol: store the persisted state, seal the floor from it and store the floor apart
//! from the state, then confirm the state ([`Coordinator::confirm_persisted`]). A crash
//! between the two stores leaves a state above the floor, which recovers as it is. The
//! floor guards against a rollback of the state alone; rolling back the state, the floor
//! and the revocation stream together is caught only by a monotonic counter outside the
//! host's storage, which is an owner decision. A labelled runtime's epoch is not persisted
//! at all (its records end with the run); its scoped epochs carry the run, which the floor
//! keeps rising.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::capacity::{CapacityPort, ReconcileReport, ReservationKey, ReservationPriority};
use super::coordinator::{Compensation, CoordinationError, Coordinator};
use super::identity::{ModelGenerations, ModelId, SandboxGenerations};
use super::model::ModelActivations;
use super::port::SandboxPort;
use super::recovery::PersistedState;
use super::replay::ReplayRecord;
use super::sandbox::{SandboxLifecycle, SandboxState};
use super::scope::AuthorityIssuer;
use crate::foundation::events::EventSequence;
use crate::foundation::evidence::{RuntimeSubject, SourceClass};
use crate::foundation::ids::{Clock, ExecutionId, GrantId, Incarnation, LeaseId, TenantId};

/// Whether `state` is below `floor` in any generation.
fn sandbox_below(state: SandboxGenerations, floor: SandboxGenerations) -> bool {
    state.boot < floor.boot
        || state.policy < floor.policy
        || state.authorization < floor.authorization
}

/// Whether `state` is below `floor` in any generation.
fn model_below(state: ModelGenerations, floor: ModelGenerations) -> bool {
    state.activation < floor.activation || state.gpu_allocation < floor.gpu_allocation
}

/// What the floor keeps of one sandbox: enough to recreate its record at the floor's
/// generations when a restored state lacks it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxFloor {
    tenant: TenantId,
    runtime: RuntimeSubject,
    priority: ReservationPriority,
    generations: SandboxGenerations,
}

impl SandboxFloor {
    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// The runtime of the sandbox's last boot.
    pub fn runtime(&self) -> &RuntimeSubject {
        &self.runtime
    }

    pub fn priority(&self) -> ReservationPriority {
        self.priority
    }

    /// The generations no restored record goes below.
    pub fn generations(&self) -> SandboxGenerations {
        self.generations
    }
}

/// What the floor keeps of one execution.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionFloor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sandbox: Option<SandboxFloor>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    models: BTreeMap<ModelId, ModelGenerations>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    revoked_grants: BTreeSet<GrantId>,
}

impl ExecutionFloor {
    /// The sandbox's floor, for a VM sandbox.
    pub fn sandbox(&self) -> Option<&SandboxFloor> {
        self.sandbox.as_ref()
    }

    /// Each model's next generations.
    pub fn models(&self) -> &BTreeMap<ModelId, ModelGenerations> {
        &self.models
    }

    /// The grants revoked under the execution. A retired execution keeps none: its
    /// retirement refuses everything they did.
    pub fn revoked_grants(&self) -> &BTreeSet<GrantId> {
        &self.revoked_grants
    }

    /// Whether the execution was retired ([`Coordinator::retire`]).
    pub fn is_retired(&self) -> bool {
        self.sandbox
            .as_ref()
            .is_some_and(|sandbox| sandbox.generations.is_retired())
    }
}

/// One way a persisted state is below the floor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "regression", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum Regression {
    Incarnation {
        floor: Incarnation,
        state: Incarnation,
    },
    NextLease {
        floor: LeaseId,
        state: LeaseId,
    },
    SandboxMissing {
        execution: ExecutionId,
    },
    SandboxGenerations {
        execution: ExecutionId,
        floor: SandboxGenerations,
        state: SandboxGenerations,
    },
    ModelMissing {
        execution: ExecutionId,
        model: ModelId,
    },
    ModelGenerations {
        execution: ExecutionId,
        model: ModelId,
        floor: ModelGenerations,
        state: ModelGenerations,
    },
    /// A grant the floor holds revoked is not tombstoned in the state, and the execution
    /// is not retired.
    TombstoneMissing {
        execution: ExecutionId,
        grant: GrantId,
    },
    /// The revocation stream ends before the sequence the floor recorded.
    RevocationLog {
        floor: EventSequence,
        found: Option<EventSequence>,
    },
}

crate::foundation::strict_serde::strict_tag!(Regression, "regression");

/// A seal refused: the state is below the floor, which never moves back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FloorRegression {
    pub regressions: Vec<Regression>,
}

impl fmt::Display for FloorRegression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the state is below the authority floor in {} place(s); the floor never moves back",
            self.regressions.len()
        )
    }
}

impl std::error::Error for FloorRegression {}

/// Why a restore was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum FloorRefusal {
    /// The floor belongs to `floor`, another host or issuer than the one restarting.
    ForeignFloor { floor: AuthorityIssuer },
    /// The revocation stream ends before the sequence the floor recorded: it was rolled
    /// back or replaced, and revocations it held may be missing.
    RevocationLogBehind {
        floor: EventSequence,
        found: Option<EventSequence>,
    },
}

crate::foundation::strict_serde::strict_tag!(FloorRefusal, "refusal");

impl fmt::Display for FloorRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ForeignFloor { floor } => {
                write!(f, "the floor is {floor}'s, not the restarting authority's")
            }
            Self::RevocationLogBehind { floor, found } => match found {
                Some(found) => write!(
                    f,
                    "the revocation stream ends at {}, before the {} the floor recorded",
                    found.get(),
                    floor.get()
                ),
                None => write!(
                    f,
                    "the revocation stream is empty, but the floor recorded {}",
                    floor.get()
                ),
            },
        }
    }
}

impl std::error::Error for FloorRefusal {}

/// One part of a restored state raised to the floor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "upgrade", rename_all = "snake_case", deny_unknown_fields)]
#[serde(remote = "Self")]
pub enum FloorUpgrade {
    Incarnation {
        from: Incarnation,
        to: Incarnation,
    },
    NextLease {
        from: LeaseId,
        to: LeaseId,
    },
    SandboxRaised {
        execution: ExecutionId,
        from: SandboxGenerations,
        to: SandboxGenerations,
    },
    /// The state lacked the sandbox; its record was recreated, planned, at the floor's
    /// generations.
    SandboxRecreated {
        execution: ExecutionId,
        generations: SandboxGenerations,
    },
    /// The floor holds the sandbox retired, but the state's record, from before, was still
    /// `recorded`; a planned record at the retired generations replaced it.
    SandboxRetired {
        execution: ExecutionId,
        recorded: SandboxState,
    },
    ModelRaised {
        execution: ExecutionId,
        model: ModelId,
        from: ModelGenerations,
        to: ModelGenerations,
    },
    /// The state lacked the model; its record was recreated with no activation at the
    /// floor's next generations.
    ModelRecreated {
        execution: ExecutionId,
        model: ModelId,
        next: ModelGenerations,
    },
    TombstonesRestored {
        execution: ExecutionId,
        grants: BTreeSet<GrantId>,
    },
}

crate::foundation::strict_serde::strict_tag!(FloorUpgrade, "upgrade");

/// What a restore did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FloorRestore {
    /// Every part raised to the floor; none for the newest durable state.
    pub upgrades: Vec<FloorUpgrade>,
    /// The executions whose sandbox or model records were below the floor. Recovery
    /// keeps no authority of theirs; [`Coordinator::end_stale`] ends their sandboxes.
    pub stale: BTreeSet<ExecutionId>,
    /// The replay record to restore the receiver from: the stored one raised to the
    /// floor's.
    pub replay: ReplayRecord,
}

impl FloorRestore {
    /// Whether the state was the newest durable one, needing nothing raised.
    pub fn is_current(&self) -> bool {
        self.upgrades.is_empty()
    }
}

/// How ending one stale sandbox went.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StaleEnded {
    /// What termination released.
    pub compensations: Vec<Compensation>,
    /// How the ledger reconciled the execution once its VM was gone; reservations of the
    /// lost record were closed as released, the VM's end having been observed through the
    /// host port.
    pub reconciled: ReconcileReport,
}

/// The coordination authority's durable floor (S2 CORE-04; VM part §6.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityFloor {
    issuer: AuthorityIssuer,
    /// How many seals made it; 0 before the first.
    sequence: u64,
    incarnation: Incarnation,
    next_lease: LeaseId,
    executions: BTreeMap<ExecutionId, ExecutionFloor>,
    /// The revocation stream's last sequence when the floor was sealed.
    revocation_log: Option<EventSequence>,
    replay: ReplayRecord,
}

impl AuthorityFloor {
    /// The floor of `issuer` before its first seal: nothing recorded.
    pub fn new(issuer: AuthorityIssuer) -> Self {
        Self {
            issuer,
            sequence: 0,
            incarnation: Incarnation::FIRST,
            next_lease: LeaseId::FIRST,
            executions: BTreeMap::new(),
            revocation_log: None,
            replay: ReplayRecord::default(),
        }
    }

    /// The host and issuer whose authority the floor is.
    pub fn issuer(&self) -> AuthorityIssuer {
        self.issuer
    }

    /// How many seals made it.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn incarnation(&self) -> Incarnation {
        self.incarnation
    }

    pub fn next_lease(&self) -> LeaseId {
        self.next_lease
    }

    /// What the floor keeps of `execution`.
    pub fn execution(&self, execution: &ExecutionId) -> Option<&ExecutionFloor> {
        self.executions.get(execution)
    }

    /// Every execution the floor keeps.
    pub fn executions(&self) -> &BTreeMap<ExecutionId, ExecutionFloor> {
        &self.executions
    }

    /// The revocation stream's last sequence when the floor was sealed.
    pub fn revocation_log(&self) -> Option<EventSequence> {
        self.revocation_log
    }

    /// The replay limits and floors sealed so far.
    pub fn replay(&self) -> &ReplayRecord {
        &self.replay
    }

    /// The next floor, from `state`, just stored durably, with `replay`, a receiver's
    /// latest record, and `revocation_log`, the durable revocation stream's last sequence
    /// now. Refused, listing every regression, when the state, or the stream, is below
    /// this floor anywhere: the floor never moves back. The replay record only merges
    /// upward.
    pub fn seal(
        &self,
        state: &PersistedState,
        replay: &ReplayRecord,
        revocation_log: Option<EventSequence>,
    ) -> Result<Self, FloorRegression> {
        let regressions = self.regressions(state, revocation_log);
        if !regressions.is_empty() {
            return Err(FloorRegression { regressions });
        }
        let mut executions: BTreeMap<ExecutionId, ExecutionFloor> = BTreeMap::new();
        for sandbox in &state.sandboxes {
            executions
                .entry(sandbox.execution().clone())
                .or_default()
                .sandbox = Some(SandboxFloor {
                tenant: sandbox.tenant().clone(),
                runtime: sandbox.runtime().clone(),
                priority: sandbox.priority(),
                generations: sandbox.generations(),
            });
        }
        for models in &state.models {
            executions
                .entry(models.execution().clone())
                .or_default()
                .models
                .insert(models.model(), models.next_generations());
        }
        for (execution, grants) in &state.revoked_grants {
            let entry = executions.entry(execution.clone()).or_default();
            if !entry.is_retired() {
                entry.revoked_grants = grants.clone();
            }
        }
        Ok(Self {
            issuer: self.issuer,
            sequence: self.sequence.saturating_add(1),
            incarnation: state.incarnation,
            next_lease: state.next_lease,
            executions,
            revocation_log,
            replay: self.replay.merge(replay),
        })
    }

    /// Every way `state` and `revocation_log` are below this floor.
    pub fn regressions(
        &self,
        state: &PersistedState,
        revocation_log: Option<EventSequence>,
    ) -> Vec<Regression> {
        let mut regressions = Vec::new();
        if state.incarnation < self.incarnation {
            regressions.push(Regression::Incarnation {
                floor: self.incarnation,
                state: state.incarnation,
            });
        }
        if state.next_lease < self.next_lease {
            regressions.push(Regression::NextLease {
                floor: self.next_lease,
                state: state.next_lease,
            });
        }
        if let Some(floor) = self.revocation_log {
            if revocation_log.is_none_or(|found| found < floor) {
                regressions.push(Regression::RevocationLog {
                    floor,
                    found: revocation_log,
                });
            }
        }
        for (execution, floor) in &self.executions {
            let sandbox = state
                .sandboxes
                .iter()
                .find(|sandbox| sandbox.execution() == execution);
            if let Some(sandbox_floor) = &floor.sandbox {
                match sandbox {
                    None => regressions.push(Regression::SandboxMissing {
                        execution: execution.clone(),
                    }),
                    Some(sandbox)
                        if sandbox_below(sandbox.generations(), sandbox_floor.generations) =>
                    {
                        regressions.push(Regression::SandboxGenerations {
                            execution: execution.clone(),
                            floor: sandbox_floor.generations,
                            state: sandbox.generations(),
                        })
                    }
                    Some(_) => {}
                }
            }
            for (model, next) in &floor.models {
                match state
                    .models
                    .iter()
                    .find(|models| models.execution() == execution && models.model() == *model)
                {
                    None => regressions.push(Regression::ModelMissing {
                        execution: execution.clone(),
                        model: *model,
                    }),
                    Some(models) if model_below(models.next_generations(), *next) => regressions
                        .push(Regression::ModelGenerations {
                            execution: execution.clone(),
                            model: *model,
                            floor: *next,
                            state: models.next_generations(),
                        }),
                    Some(_) => {}
                }
            }
            let retired = sandbox.is_some_and(|sandbox| sandbox.generations().is_retired());
            if retired {
                continue;
            }
            let held = state.revoked_grants.get(execution);
            for grant in &floor.revoked_grants {
                if !held.is_some_and(|held| held.contains(grant)) {
                    regressions.push(Regression::TombstoneMissing {
                        execution: execution.clone(),
                        grant: *grant,
                    });
                }
            }
        }
        regressions
    }

    /// Raises `state`, read back at a restart, to this floor before
    /// [`Coordinator::recover`] (after [`PersistedState::adopt_revocations`]), and returns
    /// what it raised, the executions whose records were below the floor and the replay
    /// record to restore the receiver from (`replay`, the stored one, merged with the
    /// floor's). `issuer` is the authority restarting; `revocation_log` the durable
    /// revocation stream's last sequence now. Refused for another authority's floor and for
    /// a stream behind the floor; nothing in `state` changes then.
    pub fn restore(
        &self,
        issuer: AuthorityIssuer,
        state: &mut PersistedState,
        replay: &ReplayRecord,
        revocation_log: Option<EventSequence>,
    ) -> Result<FloorRestore, FloorRefusal> {
        if issuer != self.issuer {
            return Err(FloorRefusal::ForeignFloor { floor: self.issuer });
        }
        if let Some(floor) = self.revocation_log {
            if revocation_log.is_none_or(|found| found < floor) {
                return Err(FloorRefusal::RevocationLogBehind {
                    floor,
                    found: revocation_log,
                });
            }
        }
        let mut upgrades = Vec::new();
        let mut stale = BTreeSet::new();
        if state.incarnation < self.incarnation {
            upgrades.push(FloorUpgrade::Incarnation {
                from: state.incarnation,
                to: self.incarnation,
            });
            state.incarnation = self.incarnation;
        }
        if state.next_lease < self.next_lease {
            upgrades.push(FloorUpgrade::NextLease {
                from: state.next_lease,
                to: self.next_lease,
            });
            state.next_lease = self.next_lease;
        }
        for (execution, floor) in &self.executions {
            if let Some(sandbox_floor) = &floor.sandbox {
                Self::raise_sandbox(state, execution, sandbox_floor, &mut upgrades, &mut stale);
            }
            for (model, next) in &floor.models {
                Self::raise_model(state, execution, *model, *next, &mut upgrades, &mut stale);
            }
            let retired = state.sandboxes.iter().any(|sandbox| {
                sandbox.execution() == execution && sandbox.generations().is_retired()
            });
            if retired || floor.revoked_grants.is_empty() {
                continue;
            }
            let held = state.revoked_grants.entry(execution.clone()).or_default();
            let restored: BTreeSet<GrantId> =
                floor.revoked_grants.difference(held).copied().collect();
            if !restored.is_empty() {
                held.extend(restored.iter().copied());
                upgrades.push(FloorUpgrade::TombstonesRestored {
                    execution: execution.clone(),
                    grants: restored,
                });
            }
        }
        Ok(FloorRestore {
            upgrades,
            stale,
            replay: replay.merge(&self.replay),
        })
    }

    fn raise_sandbox(
        state: &mut PersistedState,
        execution: &ExecutionId,
        floor: &SandboxFloor,
        upgrades: &mut Vec<FloorUpgrade>,
        stale: &mut BTreeSet<ExecutionId>,
    ) {
        match state
            .sandboxes
            .iter_mut()
            .find(|sandbox| sandbox.execution() == execution)
        {
            Some(sandbox) => {
                if !sandbox_below(sandbox.generations(), floor.generations) {
                    return;
                }
                if floor.generations.is_retired() && sandbox.state() != SandboxState::Stopped {
                    // Retirement came after the sandbox stopped and its cleanup finished, so
                    // the record's handles name nothing left; and recovery could not advance
                    // an exhausted epoch to reconcile it. A planned record at the retired
                    // generations takes its place, which recovery stops at once.
                    let recorded = sandbox.state();
                    *sandbox = Self::recreated(execution, floor);
                    upgrades.push(FloorUpgrade::SandboxRetired {
                        execution: execution.clone(),
                        recorded,
                    });
                } else {
                    let from = sandbox.raise_generations(floor.generations);
                    upgrades.push(FloorUpgrade::SandboxRaised {
                        execution: execution.clone(),
                        from,
                        to: sandbox.generations(),
                    });
                }
                stale.insert(execution.clone());
            }
            None => {
                let sandbox = Self::recreated(execution, floor);
                upgrades.push(FloorUpgrade::SandboxRecreated {
                    execution: execution.clone(),
                    generations: sandbox.generations(),
                });
                state.sandboxes.push(sandbox);
                stale.insert(execution.clone());
            }
        }
    }

    /// A planned record of `execution` at `floor`'s generations, with nothing created.
    fn recreated(execution: &ExecutionId, floor: &SandboxFloor) -> SandboxLifecycle {
        let mut sandbox = SandboxLifecycle::new(
            execution.clone(),
            floor.tenant.clone(),
            floor.runtime.clone(),
            floor.priority,
        );
        sandbox.raise_generations(floor.generations);
        sandbox
    }

    fn raise_model(
        state: &mut PersistedState,
        execution: &ExecutionId,
        model: ModelId,
        next: ModelGenerations,
        upgrades: &mut Vec<FloorUpgrade>,
        stale: &mut BTreeSet<ExecutionId>,
    ) {
        match state
            .models
            .iter_mut()
            .find(|models| models.execution() == execution && models.model() == model)
        {
            Some(models) => {
                if model_below(models.next_generations(), next) {
                    let from = models.raise_next(next);
                    upgrades.push(FloorUpgrade::ModelRaised {
                        execution: execution.clone(),
                        model,
                        from,
                        to: models.next_generations(),
                    });
                    stale.insert(execution.clone());
                }
            }
            None => {
                let mut models = ModelActivations::new(execution.clone(), model);
                models.raise_next(next);
                upgrades.push(FloorUpgrade::ModelRecreated {
                    execution: execution.clone(),
                    model,
                    next: models.next_generations(),
                });
                state.models.push(models);
                stale.insert(execution.clone());
            }
        }
    }
}

impl<C: Clock, P: CapacityPort> Coordinator<C, P> {
    /// Ends, after [`Coordinator::recover`], each sandbox whose record a floor restore found
    /// below the floor ([`FloorRestore::stale`]): recovery kept a live VM of it without
    /// authority, for fresh evidence and a fresh grant, but the record it kept it by is not
    /// the one the floor saw, so the VM is terminated through its handle instead
    /// ([`Coordinator::terminate`]). Once it is stopped, the ledger reconciles the execution
    /// and the reservations its lost record held are closed as released: the VM's end was
    /// observed through the host port, and nothing of the execution is left. A sandbox
    /// already stopped is reconciled only; one granted authority since is refused, as
    /// `terminate` refuses it.
    pub fn end_stale(
        &mut self,
        restore: &FloorRestore,
        port: &mut dyn SandboxPort,
    ) -> BTreeMap<ExecutionId, Result<StaleEnded, CoordinationError>> {
        let mut ended = BTreeMap::new();
        for execution in &restore.stale {
            let Some(sandbox) = self.sandbox(execution) else {
                continue;
            };
            let compensations = if sandbox.state() == SandboxState::Stopped {
                Ok(Vec::new())
            } else {
                self.terminate(execution, port)
            };
            let outcome = compensations.and_then(|compensations| {
                let reconciled = self
                    .close_lost_reservations(execution)
                    .map_err(|refusal| CoordinationError::Capacity { refusal })?;
                Ok(StaleEnded {
                    compensations,
                    reconciled,
                })
            });
            ended.insert(execution.clone(), outcome);
        }
        ended
    }

    /// Reconciles a stopped execution with the ledger and closes as released every
    /// reservation the ledger still counts for it that no record expects.
    fn close_lost_reservations(
        &mut self,
        execution: &ExecutionId,
    ) -> Result<ReconcileReport, super::capacity::CapacityRefusal> {
        let expected: BTreeSet<ReservationKey> = self
            .models
            .iter()
            .filter(|((owner, _), _)| owner == execution)
            .flat_map(|(_, models)| models.counted_reservations())
            .collect();
        let mut reconciled = self.capacity.reconcile(execution, &expected)?;
        for key in std::mem::take(&mut reconciled.pending_orphans) {
            self.capacity
                .confirm_release(&key, SourceClass::HostProbe)?;
            reconciled.released_orphans.insert(key);
        }
        Ok(reconciled)
    }
}
