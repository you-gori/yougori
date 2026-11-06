//! The committed mapping from a published service to its CORE-04 grant (VM part §4.7
//! "Ingress, previews and connected sandboxes", §1.3 network authority; VM-W13).
//!
//! V02 names a service a sandbox offers by its [`ServiceIdentity`]; CORE-04 names it only
//! by the digest in its [`NetworkGrant::PublishedService`]. This is the one mapping between
//! them. The `service` digest is a [`DigestBuilder`] digest of the identity's one canonical
//! field, its identifier text exactly as V02 accepted it, under
//! [`PUBLISHED_SERVICE_DOMAIN`]:
//!
//! - one service always gives one digest, on every host and after every restart, so a
//!   grant CORE-04 restored from its persisted state still covers the same service;
//! - two different services never share one: the identifier is the whole identity and
//!   is compared byte for byte, case included;
//! - the domain keeps it apart from every other digest of the same text, and CORE-04's
//!   [`network_grant_id`] adds the grant's kind, so the grant's identity never collides
//!   with a route's or an operation's.
//!
//! The host puts [`published_service_grant`] of every service it lets the sandbox offer in
//! the sandbox's launch settings ([`SettingsGrant::network`]) and names the same services
//! in its registration ([`super::SandboxRegistration::published_services`]). The gate
//! derives each grant again, never takes a digest from the host, and refuses a
//! registration whose launch settings do not hold one ([`super::ConnectionGate::attach`]).
//! To stop one service, the host tombstones [`published_service_grant_id`] through
//! [`Coordinator::revoke_grant`]; the gate closes what that grant covered.
//!
//! Changing the domain or the field layout changes every grant already in launch settings
//! and in persisted CORE-04 state, so it needs a new domain version; a known-answer test
//! pins this one.
//!
//! [`SettingsGrant::network`]: crate::foundation::coordination::SettingsGrant::network
//! [`Coordinator::revoke_grant`]: crate::foundation::coordination::Coordinator::revoke_grant

use super::authority::service_grant;
use crate::foundation::coordination::network_grant_id;
use crate::foundation::evidence::NetworkGrant;
use crate::foundation::ids::{Digest, DigestBuilder, GrantId};
use crate::sandbox_contract::destinations::ServiceIdentity;

/// The digest domain of [`published_service_digest`]: one part, the service identity's
/// identifier text.
pub const PUBLISHED_SERVICE_DOMAIN: &str = "yougori/sandbox/published-service/v1";

/// The `service` digest of the CORE-04 published-service grant that covers `service`.
pub fn published_service_digest(service: &ServiceIdentity) -> Digest {
    DigestBuilder::new(PUBLISHED_SERVICE_DOMAIN)
        .str(service.as_str())
        .finish()
}

/// CORE-04's [`NetworkGrant::PublishedService`] that covers `service`: the grant the host
/// puts in the sandbox's launch settings and the gate checks for the service.
pub fn published_service_grant(service: &ServiceIdentity) -> NetworkGrant {
    service_grant(published_service_digest(service))
}

/// CORE-04's identity of [`published_service_grant`] ([`network_grant_id`]): the identity
/// a revocation of the service names, and the one the gate's refusals and closure reports
/// carry.
pub fn published_service_grant_id(service: &ServiceIdentity) -> GrantId {
    network_grant_id(&published_service_grant(service))
}
