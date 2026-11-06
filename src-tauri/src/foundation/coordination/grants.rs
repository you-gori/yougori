//! Revocation of one grant (CORE-04; VM part §6.3 step 1: "advances the durable epoch or
//! records a generation tombstone"; VM part §4.6; VM-W43).
//!
//! Revoking the sandbox advances its authorization epoch and ends everything its
//! authority granted (INT-02). Revoking one grant under that authority, such as a network
//! route or a scoped delegation, records a tombstone for the grant under the execution
//! instead, and leaves the epoch and every other grant in force, so a sandbox that shares
//! a violated grant loses that grant and nothing else (V14 decision 6). A grant is named
//! by its [`GrantId`]: the digest its issuer assigned, or, for a network grant of the
//! authority's settings, [`network_grant_id`]. From the revocation on:
//!
//! - the grant is never honoured under that execution again: no lease is issued under
//!   it, no lease issued under it is honoured or renewed, its network grant leaves the
//!   settings the authority grants its models and is never granted again, not after a
//!   relaunch or a re-authorization either, and no request is admitted to an activation
//!   whose settings use it;
//! - every lease bound to it is cancelled with its declared bound (INT-02): the leases
//!   issued under it or bound to it later ([`Coordinator::bind_grants`]) and the model
//!   leases of activations whose settings use it, and no other lease;
//! - the tombstone is persisted with the coordinator's state ([`PersistedState`]), so
//!   recovery never grants it again. Tombstones last as long as their execution's record,
//!   one per grant ever revoked under it (§6.3: bound tombstone storage).
//!
//! The revocation reaches the event plane as a whole revocation does, through
//! [`RevocationEvents`] ([`Coordinator::revoke_grant_and_publish`]).
//!
//! [`PersistedState`]: super::PersistedState
//! [`RevocationEvents`]: super::RevocationEvents

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::capacity::CapacityPort;
use super::coordinator::{CoordinationError, Coordinator};
use super::identity::ModelId;
use super::lease::{
    CancelCause, Lease, LeaseCancellation, LeaseKind, LeaseRefusal, LeaseRequest, LeaseTerms,
    ModelBinding,
};
use super::revocation::DeniedRequest;
use super::sandbox::SettingsGrant;
use crate::foundation::evidence::NetworkGrant;
use crate::foundation::ids::{
    AuthorizationEpoch, Clock, DigestBuilder, ExecutionId, GrantId, LeaseId,
    ModelActivationGeneration, MonotonicTime, OperationId,
};

/// The digest domain of [`network_grant_id`].
const NETWORK_GRANT_DOMAIN: &str = "yougori/coordination/network-grant/v1";

/// The identity of a network grant of the authority's settings (VM part §1.3: network
/// authority): its kind and the route, operation or service it names, so two kinds never
/// share an identity. The host names a violated network grant by it, so a revocation of
/// it ([`Coordinator::revoke_grant`]) reaches the settings that use it.
pub fn network_grant_id(grant: &NetworkGrant) -> GrantId {
    let (kind, named) = match grant {
        NetworkGrant::NamedRoute { route } => ("named_route", route),
        NetworkGrant::CredentialedOperation { operation } => ("credentialed_operation", operation),
        NetworkGrant::PublishedService { service } => ("published_service", service),
    };
    GrantId::from_digest(
        DigestBuilder::new(NETWORK_GRANT_DOMAIN)
            .str(kind)
            .digest(named)
            .finish(),
    )
}

/// One grant revoked under an execution's authority, and what its revocation cancelled
/// (VM part §6.3 steps 1–2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokedGrant {
    pub execution: ExecutionId,
    pub grant: GrantId,
    /// The authorization epoch in force, which revoking the grant left unchanged.
    pub epoch: AuthorizationEpoch,
    pub at: MonotonicTime,
    /// The network grant the identity names, if the authority granted it to its models
    /// or an activation's settings used it; it left the settings the authority grants.
    pub network: Option<NetworkGrant>,
    /// The leases bound to the grant, cancelled with their declared bounds.
    pub cancellations: Vec<LeaseCancellation>,
    /// The unretired activations whose settings use the grant. None admits a request
    /// again, and their model leases are among the cancellations; the model side retires
    /// them or activates again without the grant.
    pub activations: Vec<ModelBinding>,
}

impl<C: Clock, P: CapacityPort> Coordinator<C, P> {
    /// Revokes one grant under `execution`'s authority, a VM sandbox's or a labelled
    /// runtime's, without advancing its authorization epoch (VM part §6.3 step 1: a
    /// tombstone). The grant is never honoured under `execution` again; every lease bound
    /// to it is cancelled with its declared bound, and no other lease is; a network grant
    /// leaves the settings the authority grants its models. A grant `execution` never held
    /// is tombstoned all the same, so it is never granted later. Revoking it again returns
    /// the same record; after recovery, which keeps the tombstone, the record shows
    /// nothing left to cancel. Durable once a persisted state carrying it is stored
    /// ([`Coordinator::persist`]).
    pub fn revoke_grant(
        &mut self,
        execution: &ExecutionId,
        grant: GrantId,
    ) -> Result<RevokedGrant, CoordinationError> {
        let key = (execution.clone(), grant);
        if let Some(revoked) = self.grant_revocations.get(&key) {
            return Ok(revoked.clone());
        }
        let epoch = match (self.sandboxes.get(execution), self.labelled.get(execution)) {
            (Some(sandbox), _) => sandbox.generations().authorization,
            (None, Some(record)) => record.epoch(),
            (None, None) => {
                return Err(CoordinationError::UnknownExecution {
                    execution: execution.clone(),
                })
            }
        };
        let now = self.monotonic_now();
        self.grant_tombstones
            .entry(execution.clone())
            .or_default()
            .insert(grant);
        let named = |candidate: &NetworkGrant| network_grant_id(candidate) == grant;
        let mut network = None;
        if let Some(sandbox) = self.sandboxes.get_mut(execution) {
            network = network.or(sandbox.withdraw_network(named));
        }
        if let Some(record) = self.labelled.get_mut(execution) {
            network = network.or(record.withdraw_network(named));
        }
        let mut users: BTreeSet<(ModelId, ModelActivationGeneration)> = BTreeSet::new();
        let mut activations = Vec::new();
        for ((owner, model), models) in &self.models {
            if owner != execution {
                continue;
            }
            for activation in models.activations() {
                let Some(used) = activation
                    .settings()
                    .network
                    .iter()
                    .find(|&used| named(used))
                else {
                    continue;
                };
                network = network.or(Some(*used));
                let generations = activation.generations();
                users.insert((*model, generations.activation));
                if !activation.state().is_retired() {
                    activations.push(ModelBinding {
                        model: *model,
                        generations,
                    });
                }
            }
        }
        let cancellations = self.leases.cancel_where(
            |lease| {
                lease.parent() == execution
                    && (lease.grants().contains(&grant)
                        || lease.model().is_some_and(|binding| {
                            users.contains(&(binding.model, binding.generations.activation))
                        }))
            },
            CancelCause::GrantRevoked,
            now,
        );
        let revoked = RevokedGrant {
            execution: execution.clone(),
            grant,
            epoch,
            at: now,
            network,
            cancellations,
            activations,
        };
        self.grant_revocations.insert(key, revoked.clone());
        Ok(revoked)
    }

    /// Whether `grant` was revoked under `execution`'s authority; such a grant is never
    /// honoured there again.
    pub fn grant_revoked(&self, execution: &ExecutionId, grant: GrantId) -> bool {
        self.grant_tombstones
            .get(execution)
            .is_some_and(|revoked| revoked.contains(&grant))
    }

    /// The revocation of `grant` under `execution` this run recorded, with what it
    /// cancelled. A revocation from before a recovery keeps only its tombstone
    /// ([`Coordinator::grant_revoked`]).
    pub fn revoked_grant(&self, execution: &ExecutionId, grant: GrantId) -> Option<&RevokedGrant> {
        self.grant_revocations.get(&(execution.clone(), grant))
    }

    /// Binds the lease `lease` to more grants of its parent's authority that its work
    /// depends on, such as the grant to serve the adapter a model request runs with: from
    /// now on revoking any of them cancels the lease with its declared bound, as for a
    /// lease issued under them ([`Coordinator::start_granted_work`]). Binding only narrows
    /// the lease; its authority, generations and expiry stay as issued. The lease must be
    /// honoured now, and a grant already revoked under its parent is refused with nothing
    /// bound. Binding a grant again changes nothing. Returns the lease as now recorded.
    pub fn bind_grants(
        &mut self,
        lease: LeaseId,
        grants: &BTreeSet<GrantId>,
    ) -> Result<Lease, LeaseRefusal> {
        let current = self.check_lease(lease)?;
        if let Some(grant) = grants
            .iter()
            .copied()
            .find(|grant| self.grant_revoked(current.parent(), *grant))
        {
            return Err(LeaseRefusal::GrantRevoked { grant });
        }
        self.leases.bind_grants(lease, grants)
    }

    /// Starts child work under its parent execution as [`Coordinator::start_child_work`]
    /// does, issued under `grants` of the parent's authority, such as a route or a scoped
    /// delegation (VM part §4.6): revoking any of them cancels the lease
    /// ([`Coordinator::revoke_grant`]). A grant already revoked under the parent is
    /// refused, after the parent's own checks.
    pub fn start_granted_work(
        &mut self,
        execution: &ExecutionId,
        operation: OperationId,
        kind: LeaseKind,
        terms: LeaseTerms,
        grants: BTreeSet<GrantId>,
    ) -> Result<Lease, LeaseRefusal> {
        self.start_granted_work_until(execution, operation, kind, terms, grants, None)
    }

    /// As `start_granted_work`, with an additional absolute deadline on this clock.
    /// Both the first term and all renewal lifetime are narrowed at the same clock
    /// reading used to issue the lease. Time spent checking readiness or waiting for
    /// a lock cannot become additional delegated lifetime.
    pub fn start_granted_work_until(
        &mut self,
        execution: &ExecutionId,
        operation: OperationId,
        kind: LeaseKind,
        terms: LeaseTerms,
        grants: BTreeSet<GrantId>,
        deadline: Option<MonotonicTime>,
    ) -> Result<Lease, LeaseRefusal> {
        let started = self.start_work(execution, operation, kind, terms, grants, deadline);
        if let Err(refusal) = &started {
            self.note_denial(execution, DeniedRequest::NewLease { kind }, refusal);
        }
        started
    }

    fn start_work(
        &mut self,
        execution: &ExecutionId,
        operation: OperationId,
        kind: LeaseKind,
        mut terms: LeaseTerms,
        grants: BTreeSet<GrantId>,
        deadline: Option<MonotonicTime>,
    ) -> Result<Lease, LeaseRefusal> {
        if matches!(kind, LeaseKind::ModelRequest | LeaseKind::Preparation) {
            return Err(LeaseRefusal::NeedsModelAdmission);
        }
        let context = self.new_work_context(execution, None)?;
        let now = self.lease_time()?;
        if let Some(deadline) = deadline {
            terms.check().map_err(|problem| LeaseRefusal::InvalidTerms { problem })?;
            if deadline <= now {
                return Err(LeaseRefusal::Expired {
                    expired_at: deadline,
                });
            }
            let remaining = deadline.saturating_duration_since(now);
            terms.term = terms.term.min(remaining);
            terms.max_lifetime = terms.max_lifetime.min(remaining);
        }
        let revoked_grant = grants
            .iter()
            .copied()
            .find(|grant| self.grant_revoked(execution, *grant));
        self.leases.issue(
            LeaseRequest {
                parent: execution.clone(),
                operation,
                kind,
                model: None,
                grants,
                revoked_grant,
                terms,
            },
            now,
            &context,
        )
    }

    /// The first grant `lease` depends on that was revoked under its parent: one it was
    /// issued under, or a network grant its activation's settings use.
    pub(super) fn revoked_grant_of(&self, lease: &Lease) -> Option<GrantId> {
        let execution = lease.parent();
        let revoked = self.grant_tombstones.get(execution)?;
        if let Some(grant) = lease.grants().iter().find(|grant| revoked.contains(grant)) {
            return Some(*grant);
        }
        let binding = lease.model()?;
        self.activation_revoked_grant(execution, binding.model, binding.generations.activation)
    }

    /// The first network grant the settings of `activation` use that was revoked under
    /// `execution`.
    pub(super) fn activation_revoked_grant(
        &self,
        execution: &ExecutionId,
        model: ModelId,
        activation: ModelActivationGeneration,
    ) -> Option<GrantId> {
        let revoked = self.grant_tombstones.get(execution)?;
        self.models
            .get(&(execution.clone(), model))?
            .activation(activation)?
            .settings()
            .network
            .iter()
            .map(network_grant_id)
            .find(|grant| revoked.contains(grant))
    }

    /// `settings` without the network grants revoked under `execution`: what an authority
    /// granted afresh may grant its models.
    pub(super) fn without_revoked(
        &self,
        execution: &ExecutionId,
        mut settings: SettingsGrant,
    ) -> SettingsGrant {
        if let Some(revoked) = self.grant_tombstones.get(execution) {
            settings
                .network
                .retain(|grant| !revoked.contains(&network_grant_id(grant)));
        }
        settings
    }
}
