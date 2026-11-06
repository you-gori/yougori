//! Revocation of the activation's whole authority (G06 of
//! docs/combined-plan-leftover-tasks.md: "whole-authority (epoch) revocation"; CORE-04 and
//! INT-02 of docs/combined-gpu-memory-and-vm-sandbox-plan.md: revoking a sandbox advances
//! its authorization epoch, and nothing bound to an older epoch is honoured again; VM part
//! §6.3 steps 1–3).
//!
//! A per-grant revocation ([`super::ActiveAdapters::apply_revocation`]) withdraws one
//! adapter and leaves the rest serving. Revoking the authority the activation serves under
//! withdraws everything at once: from the coordinator's tombstone on, every attach,
//! admission, switch, variant record and KV record or reuse asks the authority whether the
//! activation's epoch still stands ([`super::GrantRevocations::authority_revoked`]) and is
//! refused once it does not, before the notice arrives. The notice
//! ([`ActiveAdapters::apply_authority_revocation`]) then detaches every adapter, ends every
//! variant, drops every KV state, the base's included, withdraws every waiting attachment
//! and stops every request in flight by its declared bound. Memory is released through the
//! ledger as for any detach: only once no request may use it and the runner reported it
//! unloaded.

use crate::foundation::coordination::{LeaseCancellation, RevocationNotice};
use crate::foundation::ids::{AuthorizationEpoch, Digest, LeaseId};
use crate::model_memory::identity::{AdapterIdentity, ExecutionIdentity};

use super::{ActiveAdapters, DetachCause, Drain, DrainingRequest, GrantRevocations};

/// What applying a revocation of the activation's whole authority did. The revocation is
/// in force either way.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuthorityRevocationEffects {
    /// The activation's epoch the notice ended; `None` when the notice was for another
    /// authority or an earlier epoch, or was applied already, and nothing changed.
    pub epoch: Option<AuthorizationEpoch>,
    /// Adapters detached by it.
    pub detached: Vec<AdapterIdentity>,
    /// Merged variants that serve no one any more: retire their activations, or unload
    /// those materialized here ([`Drain::unload_variants`]).
    pub variants: Vec<ExecutionIdentity>,
    /// Every KV state recorded here, by [`super::kv_state_key`]: drop them.
    pub kv: Vec<Digest>,
    /// Attachments that waited for a slot; they are never attached here.
    pub withdrawn: Vec<AdapterIdentity>,
    /// Every request in flight with the bound by which it stops (its `revoked` names a
    /// grant only when a revocation of that grant cancelled it before), and what is ready
    /// to unload.
    pub drain: Drain,
}

impl ActiveAdapters {
    /// The epoch of the activation's authority whose revocation was applied here.
    pub fn authority_revoked(&self) -> Option<AuthorizationEpoch> {
        self.authority_revoked
    }

    /// The activation's authority stands: no revocation of its epoch was applied here,
    /// and `grants`, the coordination authority, still has it in force. Otherwise the
    /// revoked epoch.
    pub(super) fn authority_stands(
        &self,
        grants: &dyn GrantRevocations,
    ) -> Result<(), AuthorizationEpoch> {
        if let Some(epoch) = self.authority_revoked {
            return Err(epoch);
        }
        if grants.authority_revoked(&self.base.authority, self.base.epoch) {
            return Err(self.base.epoch);
        }
        Ok(())
    }

    /// Applies the coordination authority's revocation of the activation's whole authority
    /// (CORE-04; INT-02): `notice` as `Coordinator::revoke` returned it, and
    /// `cancellations`, the leases it cancelled with their declared bounds (its
    /// `RevocationOperation::cancellations`). A notice for another authority, or one that
    /// revoked only an epoch before the activation's, changes nothing, and so does
    /// applying it again.
    ///
    /// Every adapter not yet revoked is detached, every variant ends, every KV state is
    /// dropped, every waiting attachment is withdrawn, and every request in flight must stop
    /// at its next cancellation boundary and by its bound at the latest: the bound the
    /// coordinator recorded for its lease, else the revocation time plus the drain bound,
    /// or an earlier bound it already had.
    pub fn apply_authority_revocation(
        &mut self,
        notice: &RevocationNotice,
        cancellations: &[LeaseCancellation],
    ) -> AuthorityRevocationEffects {
        let mut effects = AuthorityRevocationEffects::default();
        let applies = notice.execution == self.base.authority
            && notice.revoked >= self.base.epoch
            && self.authority_revoked.is_none();
        if !applies {
            return effects;
        }
        let epoch = self.base.epoch;
        self.authority_revoked = Some(epoch);
        effects.epoch = Some(epoch);
        for (adapter, attached) in &mut self.attached {
            let revoked_already = matches!(
                attached.detached,
                Some(DetachCause::Revoked { .. } | DetachCause::AuthorityRevoked { .. })
            );
            if !revoked_already {
                attached.detached = Some(DetachCause::AuthorityRevoked { epoch });
                effects.detached.push(*adapter);
            }
        }
        effects.variants = self
            .variants
            .iter()
            .filter(|(_, entry)| entry.invalidated.is_none())
            .map(|(variant, _)| *variant)
            .collect();
        effects.kv = std::mem::take(&mut self.kv).into_keys().collect();
        effects.withdrawn = self
            .attach_waits
            .waiters()
            .map(|waiter| waiter.key)
            .collect();
        for adapter in &effects.withdrawn {
            self.attach_waits.leave(adapter);
        }
        let fallback = notice.at.saturating_add(self.drain_bound);
        let bound_for = |lease: LeaseId| {
            cancellations
                .iter()
                .find(|cancellation| cancellation.lease == lease)
                .map_or(fallback, |cancellation| cancellation.bound_at)
        };
        for (lease, request) in &mut self.requests {
            let bound_at = request
                .bound
                .map_or(bound_for(*lease), |bound| bound.min(bound_for(*lease)));
            request.bound = Some(bound_at);
            request.authority = true;
            effects.drain.draining.push(DrainingRequest {
                lease: *lease,
                route: request.route,
                bound_at,
                revoked: request.revoked,
            });
        }
        effects.drain.unload = self
            .attached
            .keys()
            .filter(|adapter| self.unloadable(adapter))
            .copied()
            .collect();
        effects.drain.unload_variants = self.unloadable_variants();
        effects
    }
}
