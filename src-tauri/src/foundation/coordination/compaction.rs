//! Safe tombstone compaction: retiring an execution (S2 CORE-04; VM part §6.3: "Bound
//! tombstone storage through safe expiry/epoch compaction; never reuse an identity while
//! old valid capabilities can exist"; VM-W29: tombstone compaction tested;
//! docs/combined-plan-remaining-only.md §8, S04 / M13 / M17: "safe tombstone
//! expiry/compaction").
//!
//! A grant tombstone keeps a revoked grant from being honoured or granted again under its
//! execution: through a lease issued under it, an activation whose settings use it, a
//! relaunch or re-authorization that grants the last settings again, or a watcher that
//! cached it. While the execution can hold authority again, none of its tombstones is safe
//! to drop. Compaction therefore works per execution, at its retirement: once the sandbox
//! has stopped and the evidence shows that nothing can still present any authority revoked
//! under it, [`Coordinator::retire`] exhausts its generations, so it is never launched,
//! relaunched, granted work or given a scoped epoch again, and its tombstones, now
//! subsumed by that, leave. The retired generations are sealed into the durable floor
//! ([`AuthorityFloor`](super::AuthorityFloor)), so a state restored from before the
//! retirement is raised to them again.
//!
//! The evidence, a [`RetirementProof`], is read from the coordinator's own records at one
//! instant, on a clock that has not gone back:
//!
//! - leases: every lease of the execution was released, acknowledged its cancellation, was
//!   not revived by a recovery, or expired on this clock session, so none is honoured,
//!   renewed or still in use;
//! - activation counters: every activation of every model under the execution is retired.
//!   A newer activation generation proves nothing about an older one, so counters are never
//!   compared, only each activation's own state;
//! - cached grants: the stopped sandbox holds no authority, and the settings its record
//!   keeps for a relaunch can never be granted again once its generations are exhausted;
//! - watchers: every watcher of the execution acknowledged the current revision in this run,
//!   ended (it deregistered, its process is gone or its PID names another process, or the
//!   engine restarted), or let its last view lapse past the allowed skew on this clock
//!   session ([`WatcherRegistry::standing`]).
//!
//! A labelled runtime is not retired: its records are not persisted, so a later run could
//! authorize it afresh, and its tombstones stay.

use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::capacity::CapacityPort;
use super::coordinator::Coordinator;
use super::identity::{ModelId, SandboxGenerations};
use super::lease::LeaseState;
use super::model::ActivationState;
use super::sandbox::{SandboxState, SettingsGrant};
use super::scope::{AuthorityIssuer, ScopeRefusal};
use super::watchers::{AuthorityRevision, WatcherId, WatcherRegistry, WatcherStanding};
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{
    AuthorizationEpoch, Clock, ExecutionId, GrantId, Incarnation, LeaseId,
    ModelActivationGeneration, MonotonicTime, PolicyEpoch, SandboxBootGeneration,
};

impl SandboxGenerations {
    /// The generations of a retired sandbox: each one exhausted, so no step advances them
    /// again and the sandbox never boots or holds authority again.
    pub const RETIRED: Self = Self {
        boot: SandboxBootGeneration::new(u64::MAX),
        policy: PolicyEpoch::new(u64::MAX),
        authorization: AuthorizationEpoch::new(u64::MAX),
    };

    /// Whether the sandbox is retired: its authorization epoch is exhausted, so no
    /// authority is granted under it again.
    pub fn is_retired(&self) -> bool {
        self.authorization.next().is_none()
    }
}

/// How much clock uncertainty compaction allows (VM part §6.2: an explicit clock-skew
/// policy for remote expiry).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactionPolicy {
    /// How long after a watcher's last view expired on the coordinator's clock the watcher
    /// may still use it on its own clock.
    pub watcher_skew: Duration,
}

/// Why a lease of the execution can no longer present its authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "closed", rename_all = "snake_case")]
pub enum LeaseClosure {
    Released,
    /// The holder acknowledged its cancellation.
    Cancelled,
    /// A recovery found it and never revived it.
    NotRevived,
    /// It expired on this clock session, so it is never honoured or renewed again.
    Expired {
        expires_at: MonotonicTime,
    },
}

/// What stands in the way of retiring an execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "blocker", rename_all = "snake_case")]
pub enum RetirementBlocker {
    /// The execution is unknown or already retired, or the coordination authority's run is
    /// not persisted yet.
    Scope { refusal: ScopeRefusal },
    /// A labelled runtime: its records are not persisted, so its tombstones stay.
    NotAVmSandbox,
    /// The sandbox has not stopped.
    NotStopped { state: SandboxState },
    /// The clock reads earlier than it already did; no expiry or lapse is judged on it.
    ClockWentBack {
        now: MonotonicTime,
        high_water: MonotonicTime,
    },
    /// A lease is active or cancelling and has not expired.
    LeaseMayPresent {
        lease: LeaseId,
        state: LeaseState,
        expires_at: MonotonicTime,
    },
    /// An active or cancelling lease is stamped on another clock session, so its expiry
    /// cannot be judged.
    LeaseOnOtherClock { lease: LeaseId },
    /// An activation is not retired.
    ActivationUnretired {
        model: ModelId,
        activation: ModelActivationGeneration,
        state: ActivationState,
    },
    /// A watcher may still hold a view from before the current revision.
    WatcherPending {
        watcher: WatcherId,
        standing: WatcherStanding,
    },
}

/// A retirement refused, with everything in its way.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RetirementBlocked {
    pub execution: ExecutionId,
    pub blockers: Vec<RetirementBlocker>,
}

impl fmt::Display for RetirementBlocked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "execution {} cannot be retired yet: {} blocker(s)",
            self.execution,
            self.blockers.len()
        )
    }
}

impl std::error::Error for RetirementBlocked {}

/// The evidence that nothing can still present any authority revoked under one execution
/// (VM part §6.3). Only the coordinator makes one, from its own records; it is kept for the
/// audit and never read back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RetirementProof {
    execution: ExecutionId,
    issuer: AuthorityIssuer,
    incarnation: Incarnation,
    clock: ClockSession,
    at: MonotonicTime,
    revision: AuthorityRevision,
    leases: Vec<(LeaseId, LeaseClosure)>,
    activations: Vec<(ModelId, ModelActivationGeneration)>,
    relaunch_settings: SettingsGrant,
    watchers: Vec<(WatcherId, WatcherStanding)>,
    tombstones: BTreeSet<GrantId>,
}

impl RetirementProof {
    pub fn execution(&self) -> &ExecutionId {
        &self.execution
    }

    pub fn issuer(&self) -> AuthorityIssuer {
        self.issuer
    }

    /// The run of the coordination authority the proof was taken in.
    pub fn incarnation(&self) -> Incarnation {
        self.incarnation
    }

    /// The clock session `at` is a point on.
    pub fn clock(&self) -> ClockSession {
        self.clock
    }

    pub fn at(&self) -> MonotonicTime {
        self.at
    }

    /// The execution's revision the watchers were judged against.
    pub fn revision(&self) -> AuthorityRevision {
        self.revision
    }

    /// Every lease of the execution, and why it can no longer present its authority.
    pub fn leases(&self) -> &[(LeaseId, LeaseClosure)] {
        &self.leases
    }

    /// Every activation under the execution, each retired.
    pub fn activations(&self) -> &[(ModelId, ModelActivationGeneration)] {
        &self.activations
    }

    /// The settings the sandbox's record kept for a relaunch, which is never granted
    /// again.
    pub fn relaunch_settings(&self) -> &SettingsGrant {
        &self.relaunch_settings
    }

    /// Every watcher of the execution, none pending.
    pub fn watchers(&self) -> &[(WatcherId, WatcherStanding)] {
        &self.watchers
    }

    /// The tombstones the retirement subsumes.
    pub fn tombstones(&self) -> &BTreeSet<GrantId> {
        &self.tombstones
    }
}

/// A retired execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Retirement {
    pub proof: RetirementProof,
    /// The sandbox's generations now: [`SandboxGenerations::RETIRED`].
    pub generations: SandboxGenerations,
    /// How many watcher records the registry forgot.
    pub watchers_forgotten: usize,
}

impl<C: Clock, P: CapacityPort> Coordinator<C, P> {
    /// The evidence that `execution` can be retired now: its sandbox stopped, and no lease,
    /// activation, cached grant or watcher of it can still present authority revoked under
    /// it (see the module documentation). Refused, with every blocker, otherwise. Changes
    /// nothing; [`Coordinator::retire`] takes the same evidence and acts on it.
    pub fn prove_retirement(
        &self,
        issuer: AuthorityIssuer,
        execution: &ExecutionId,
        watchers: &WatcherRegistry,
        policy: CompactionPolicy,
    ) -> Result<RetirementProof, RetirementBlocked> {
        let blocked = |blockers| RetirementBlocked {
            execution: execution.clone(),
            blockers,
        };
        if !self.sandboxes.contains_key(execution) && self.labelled.contains_key(execution) {
            return Err(blocked(vec![RetirementBlocker::NotAVmSandbox]));
        }
        let epoch = self
            .scoped_epoch(issuer, execution)
            .map_err(|refusal| blocked(vec![RetirementBlocker::Scope { refusal }]))?;
        let revision = self
            .authority_revision(execution)
            .map_err(|refusal| blocked(vec![RetirementBlocker::Scope { refusal }]))?;
        let Some(sandbox) = self.sandboxes.get(execution) else {
            return Err(blocked(vec![RetirementBlocker::NotAVmSandbox]));
        };
        let mut blockers = Vec::new();
        if sandbox.state() != SandboxState::Stopped {
            blockers.push(RetirementBlocker::NotStopped {
                state: sandbox.state(),
            });
        }
        let (now, at) = match self.forward_now() {
            Ok(now) => (Some(now), now),
            Err((now, high_water)) => {
                blockers.push(RetirementBlocker::ClockWentBack { now, high_water });
                (None, high_water)
            }
        };

        let mut leases = Vec::new();
        for record in self.leases.records() {
            let lease = record.lease();
            if lease.parent() != execution {
                continue;
            }
            let closure = match record.state() {
                LeaseState::Released { .. } => LeaseClosure::Released,
                LeaseState::Cancelled { .. } => LeaseClosure::Cancelled,
                LeaseState::NotRevived => LeaseClosure::NotRevived,
                state @ (LeaseState::Active | LeaseState::Cancelling { .. }) => {
                    if lease.clock() != self.session {
                        blockers.push(RetirementBlocker::LeaseOnOtherClock { lease: lease.id() });
                        continue;
                    }
                    let expires_at = lease.expires_at();
                    if now.is_none_or(|now| now < expires_at) {
                        blockers.push(RetirementBlocker::LeaseMayPresent {
                            lease: lease.id(),
                            state,
                            expires_at,
                        });
                        continue;
                    }
                    LeaseClosure::Expired { expires_at }
                }
            };
            leases.push((lease.id(), closure));
        }

        let mut activations = Vec::new();
        for ((owner, model), models) in &self.models {
            if owner != execution {
                continue;
            }
            for activation in models.activations() {
                let generation = activation.generations().activation;
                if activation.state().is_retired() {
                    activations.push((*model, generation));
                } else {
                    blockers.push(RetirementBlocker::ActivationUnretired {
                        model: *model,
                        activation: generation,
                        state: activation.state(),
                    });
                }
            }
        }

        let mut standings = Vec::new();
        for (watcher, record) in watchers.watchers_of(execution) {
            let standing = WatcherRegistry::standing(
                record,
                (&epoch, revision),
                self.session,
                now,
                policy.watcher_skew,
            );
            if standing.is_clear() {
                standings.push((watcher, standing));
            } else {
                blockers.push(RetirementBlocker::WatcherPending { watcher, standing });
            }
        }

        if !blockers.is_empty() {
            return Err(blocked(blockers));
        }
        Ok(RetirementProof {
            execution: execution.clone(),
            issuer,
            incarnation: epoch.incarnation,
            clock: self.session,
            at,
            revision,
            leases,
            activations,
            relaunch_settings: sandbox.settings_grant().clone(),
            watchers: standings,
            tombstones: self
                .grant_tombstones
                .get(execution)
                .cloned()
                .unwrap_or_default(),
        })
    }

    /// Retires `execution` on the evidence of [`Coordinator::prove_retirement`], taken now:
    /// its sandbox's generations are exhausted ([`SandboxGenerations::RETIRED`]), so it is
    /// never launched, relaunched, granted work, re-authorized or given a scoped epoch again,
    /// and its grant tombstones, subsumed by that, leave. The registry forgets its watchers,
    /// whose views are refused from now on. Durable once a persisted state carrying it is
    /// stored and sealed into the floor; a receiver retires its replay scopes with
    /// [`ReplayState::retire_line`](super::ReplayState::retire_line).
    pub fn retire(
        &mut self,
        issuer: AuthorityIssuer,
        execution: &ExecutionId,
        watchers: &mut WatcherRegistry,
        policy: CompactionPolicy,
    ) -> Result<Retirement, RetirementBlocked> {
        let proof = self.prove_retirement(issuer, execution, watchers, policy)?;
        let generations = match self.sandboxes.get_mut(execution) {
            Some(sandbox) => {
                sandbox.raise_generations(SandboxGenerations::RETIRED);
                sandbox.generations()
            }
            None => {
                return Err(RetirementBlocked {
                    execution: execution.clone(),
                    blockers: vec![RetirementBlocker::NotAVmSandbox],
                })
            }
        };
        self.grant_tombstones.remove(execution);
        self.grant_revocations
            .retain(|(owner, _), _| owner != execution);
        let watchers_forgotten = watchers.forget(execution);
        Ok(Retirement {
            proof,
            generations,
            watchers_forgotten,
        })
    }

    /// Whether `execution` was retired: nothing under it is honoured again.
    pub fn is_retired(&self, execution: &ExecutionId) -> bool {
        self.sandboxes
            .get(execution)
            .is_some_and(|sandbox| sandbox.generations().is_retired())
    }
}
