//! Revocation of the authorities identity's decisions are bound to (S3.1; T09: VM part
//! §6.3, S6 INT-02).
//!
//! Revoking a sandbox advances its authorization epoch, and nothing bound to an older
//! epoch is honoured again. Identity asks a [`RevocationPort`] whether an
//! [`AuthorityBinding`] still stands before it honours anything made or configured under
//! it, so a revocation takes effect at the next check. Identity never depends on the
//! coordinator: [`RevokedAuthorities`] answers from the coordinator's revocation notices,
//! as `Coordinator::revoke` and `Coordinator::revoke_and_publish` issue them.

use std::collections::BTreeMap;

use crate::foundation::coordination::RevocationNotice;
use crate::foundation::ids::{AuthorizationEpoch, ExecutionId};

use super::fields::AuthorityBinding;

/// Whether an authority binding was revoked (S3.1; VM part §6.3).
pub trait RevocationPort {
    /// True once the coordination authority revoked `authority`: its parent execution's
    /// authorization was revoked at or after `authority`'s epoch. A binding without an
    /// epoch is revoked by any revocation of its parent.
    fn is_revoked(&self, authority: &AuthorityBinding) -> bool;
}

/// The coordination authority's revocations, kept from its notices (T09:
/// [`RevocationNotice`]). Record each notice as the coordinator issues it, for example
/// `published.notice` from `revoke_and_publish`; every later check sees it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RevokedAuthorities {
    /// The newest epoch revoked per execution; every older epoch is revoked with it.
    revoked: BTreeMap<ExecutionId, AuthorizationEpoch>,
}

impl RevokedAuthorities {
    /// Nothing revoked yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records `notice`. A notice never un-revokes anything: the newest revoked epoch per
    /// execution is kept.
    pub fn record(&mut self, notice: &RevocationNotice) {
        let revoked = self
            .revoked
            .entry(notice.execution.clone())
            .or_insert(notice.revoked);
        *revoked = (*revoked).max(notice.revoked);
    }

    /// The newest epoch revoked for `execution`, if any.
    pub fn revoked_epoch(&self, execution: &ExecutionId) -> Option<AuthorizationEpoch> {
        self.revoked.get(execution).copied()
    }
}

impl RevocationPort for RevokedAuthorities {
    fn is_revoked(&self, authority: &AuthorityBinding) -> bool {
        self.revoked
            .get(authority.parent())
            .is_some_and(|revoked| authority.epoch().is_none_or(|epoch| epoch <= *revoked))
    }
}
