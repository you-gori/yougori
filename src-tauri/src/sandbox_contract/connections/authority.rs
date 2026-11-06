//! What the gate asks CORE-04 and lends from the release accounts (VM §4.7, §2.5, §6.3;
//! VM-W13).
//!
//! The gate never keeps authority of its own. Every admission, connection and byte it
//! moves is checked against the coordinator: the sandbox must still hold the
//! authorization epoch and the policy epoch it was attached under, and its current
//! authority must hold the CORE-04 network grant that covers the service.
//!
//! That grant is CORE-04's own [`NetworkGrant::PublishedService`], identified by CORE-04's
//! [`network_grant_id`]. CORE-04 names a published service only by a digest; the gate
//! derives that digest from the V02 [`ServiceIdentity`] (`service_grant` module,
//! [`super::published_service_grant`]) and never takes one from the host. The host puts
//! the derived grant in the sandbox's launch settings ([`SettingsGrant::network`]) and
//! names the service when it attaches the sandbox
//! ([`super::SandboxRegistration::published_services`]). CORE-04 needs nothing from this
//! module.
//!
//! Guest responses are charged to the sandbox's one release account (§2.5: central
//! reservations), which the host lends through [`ReleaseAccounts`] rather than handing the
//! gate a second account with its own copy of the general release budget.
//!
//! [`SettingsGrant::network`]: crate::foundation::coordination::SettingsGrant::network
//! [`ServiceIdentity`]: crate::sandbox_contract::destinations::ServiceIdentity

use std::collections::BTreeMap;

use crate::foundation::coordination::{network_grant_id, CapacityPort, Coordinator};
use crate::foundation::evidence::NetworkGrant;
use crate::foundation::ids::{
    AuthorizationEpoch, Clock, Digest, ExecutionId, GrantId, MonotonicTime, PolicyEpoch,
};
use crate::sandbox_contract::destinations::ReleaseAccount;

/// The CORE-04 network grant whose `service` digest is `service`; the gate builds one only
/// from a derived digest ([`super::published_service_grant`]).
pub(super) const fn service_grant(service: Digest) -> NetworkGrant {
    NetworkGrant::PublishedService { service }
}

/// The coordinator as the gate reads it (CORE-04). Implemented for [`Coordinator`]; the
/// gate never writes through it.
pub trait ConnectionAuthority {
    /// The shared clock now. The gate never lets its own reading go back
    /// ([`super::ConnectionGate`] keeps a high-water mark).
    fn now(&self) -> MonotonicTime;

    /// The authorization epoch `sandbox` holds now, while it holds current, unexpired
    /// authority; `None` once it is revoked, stopped, expired or unknown.
    fn current_epoch(&self, sandbox: &ExecutionId) -> Option<AuthorizationEpoch>;

    /// The policy epoch `sandbox` is at now; `None` if it is unknown. A policy change
    /// raises it without touching the authorization epoch.
    fn current_policy(&self, sandbox: &ExecutionId) -> Option<PolicyEpoch>;

    /// Whether the current authority of `sandbox` holds `grant` among the network grants
    /// it grants now: never once it holds no current authority, nor once the grant is
    /// tombstoned.
    fn holds_network_grant(&self, sandbox: &ExecutionId, grant: &NetworkGrant) -> bool;

    /// Whether `grant` is tombstoned under `sandbox`; such a grant is never honoured there
    /// again.
    fn grant_revoked(&self, sandbox: &ExecutionId, grant: GrantId) -> bool;
}

impl<C: Clock, P: CapacityPort> ConnectionAuthority for Coordinator<C, P> {
    fn now(&self) -> MonotonicTime {
        Coordinator::now(self).max(self.clock_high_water())
    }

    /// A copy, through CORE-04's public accessors, of the check CORE-04's private
    /// `lease::parent_authority` makes before it starts child work: the sandbox is in a
    /// state that holds authority, its grant is stamped with this coordinator's clock
    /// session, carries the epoch in force and is unexpired. Replace it with CORE-04's own
    /// accessor once CORE-04 exposes one. One difference: CORE-04 refuses child work while
    /// its clock reads earlier than its high-water mark, where this reads the mark, which
    /// only ends authority sooner.
    fn current_epoch(&self, sandbox: &ExecutionId) -> Option<AuthorizationEpoch> {
        let lifecycle = self.sandbox(sandbox)?;
        if !lifecycle.state().holds_authority() {
            return None;
        }
        let grant = lifecycle.authority()?;
        let now = ConnectionAuthority::now(self);
        (grant.clock == self.session()
            && grant.epoch == lifecycle.generations().authorization
            && now < grant.expires_at)
            .then_some(grant.epoch)
    }

    fn current_policy(&self, sandbox: &ExecutionId) -> Option<PolicyEpoch> {
        self.sandbox(sandbox)
            .map(|lifecycle| lifecycle.generations().policy)
    }

    /// Read from the settings the authority grants ([`SandboxLifecycle::settings_grant`]),
    /// which count only while the authority is held and lose a network grant when it is
    /// tombstoned.
    ///
    /// [`SandboxLifecycle::settings_grant`]:
    ///     crate::foundation::coordination::SandboxLifecycle::settings_grant
    fn holds_network_grant(&self, sandbox: &ExecutionId, grant: &NetworkGrant) -> bool {
        ConnectionAuthority::current_epoch(self, sandbox).is_some()
            && !Coordinator::grant_revoked(self, sandbox, network_grant_id(grant))
            && self
                .sandbox(sandbox)
                .is_some_and(|lifecycle| lifecycle.settings_grant().network.contains(grant))
    }

    fn grant_revoked(&self, sandbox: &ExecutionId, grant: GrantId) -> bool {
        Coordinator::grant_revoked(self, sandbox, grant)
    }
}

/// The release accounts of the host's sandboxes (VM §2.5), lent to the gate for each
/// charge. A sandbox without an account releases nothing.
pub trait ReleaseAccounts {
    /// The release account of `sandbox`, if the host keeps one.
    fn account(&mut self, sandbox: &ExecutionId) -> Option<&mut ReleaseAccount>;
}

impl ReleaseAccounts for BTreeMap<ExecutionId, ReleaseAccount> {
    fn account(&mut self, sandbox: &ExecutionId) -> Option<&mut ReleaseAccount> {
        self.get_mut(sandbox)
    }
}
