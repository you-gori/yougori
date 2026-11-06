//! Binding a model request's lease to the grants of what it is served with (G06 of
//! docs/combined-plan-leftover-tasks.md: "model request leases carry no adapter grant yet,
//! so `revoke_grant` cancels none and the drain bound always applies"; CORE-04 per-grant
//! revocation; VM part §6.3 steps 1–2: every lease bound to a revoked grant is cancelled
//! with its declared bound, INT-02).
//!
//! The coordinator issues a model request's lease for the activation, with no grant
//! beyond the authority's. [`ActiveAdapters::admit_bound`] admits the request on its route
//! and then binds that lease, through the coordinator, to the grant of every adapter the
//! route serves it with ([`ActiveAdapters::route_grants`]). From then on
//! `Coordinator::revoke_grant` cancels the lease itself: its `RevokedGrant` lists the
//! cancellation with the bound the lease's own terms declare, which
//! [`ActiveAdapters::apply_revocation`] applies instead of the registry's drain bound, and
//! the coordinator refuses the lease at every later check, a result publication included.

use std::collections::BTreeSet;

use crate::foundation::coordination::{CapacityPort, Coordinator, LeaseRefusal};
use crate::foundation::ids::{Clock, GrantId, LeaseId, MonotonicTime};

use super::{
    adapter_grant_id, ActiveAdapters, AdapterUse, Caller, GrantRevocations, Route, RouteRefusal,
};

/// The coordination authority's binding of a lease to more grants of its parent's
/// authority (CORE-04 per-grant revocation). A [`Coordinator`] is one.
pub trait LeaseGrants: GrantRevocations {
    /// Binds `lease` to `grants`, so revoking any of them cancels it with its declared
    /// bound. Refused for a lease not honoured now or a grant already revoked.
    fn bind_lease_grants(
        &mut self,
        lease: LeaseId,
        grants: &BTreeSet<GrantId>,
    ) -> Result<(), LeaseRefusal>;
}

impl<C: Clock, P: CapacityPort> LeaseGrants for Coordinator<C, P> {
    fn bind_lease_grants(
        &mut self,
        lease: LeaseId,
        grants: &BTreeSet<GrantId>,
    ) -> Result<(), LeaseRefusal> {
        self.bind_grants(lease, grants).map(|_| ())
    }
}

impl ActiveAdapters {
    /// The grants a request on `route` depends on beyond the activation's authority: the
    /// adapter's own for an adapter, every merged adapter's for a recorded merged variant,
    /// none for the base.
    pub fn route_grants(&self, route: Route) -> BTreeSet<GrantId> {
        match route {
            Route::Base => BTreeSet::new(),
            Route::Adapter(adapter) => BTreeSet::from([adapter_grant_id(&adapter)]),
            Route::Merged(variant) => self
                .variants
                .get(&variant)
                .map(|entry| entry.adapters.keys().map(adapter_grant_id).collect())
                .unwrap_or_default(),
        }
    }

    /// Admits one request as [`ActiveAdapters::admit`] does, then binds its coordinator
    /// lease to [`ActiveAdapters::route_grants`] through `host`, so revoking any of them
    /// cancels the lease with the bound its own terms declare. A binding the coordinator
    /// refuses, as for a lease no longer honoured, admits nothing.
    pub fn admit_bound<H: LeaseGrants>(
        &mut self,
        host: &mut H,
        lease: LeaseId,
        route: Route,
        caller: &Caller<'_>,
        now: MonotonicTime,
    ) -> Result<AdapterUse, RouteRefusal> {
        let admitted = self.admit(lease, route, caller, &*host, now)?;
        let grants = self.route_grants(route);
        if grants.is_empty() {
            return Ok(admitted);
        }
        match host.bind_lease_grants(lease, &grants) {
            Ok(()) => Ok(admitted),
            Err(refusal) => {
                self.requests.remove(&lease);
                Err(RouteRefusal::LeaseNotBound { refusal })
            }
        }
    }
}
