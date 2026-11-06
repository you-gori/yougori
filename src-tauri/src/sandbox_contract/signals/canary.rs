//! Canary uses as signals (V09 [`CanaryHit`] and
//! [`CanaryRegistry::refuse_credential_use`](crate::sandbox_contract::canaries::CanaryRegistry::refuse_credential_use);
//! VM part §4.5 "Fake canary", §8.2: "Canary use is a signal, not a proof of malicious
//! intent"; VM-W10).
//!
//! Every canary use is the guest's: only it can find a planted canary and use it. It is a
//! violation of [`ViolationKind::CanaryUse`], which V14 treats as a signal and never proof:
//! by default it isolates and revokes and never stops.
//!
//! - A hit goes through V14's own mapping,
//!   [`MonitoringSignal::from_canary_hit`]: about the sandbox whose traffic or report
//!   carried the canary, with the canary as the subject; a host-observed hit was seen by the
//!   relay, which belongs to the [`HostObserver::Perimeter`], at the time it saw it, and a
//!   guest-reported hit stays guest-reported, dated when the host matched it. It names no
//!   grant.
//! - A credential refused because it carries a canary value was presented at one of the
//!   checkpoints V09 names ([`CredentialCheckpoint`]: the vault, an executor or a
//!   credential import). The checkpoint maps onto a host observer, and V14 decides whether
//!   that observer can see a canary use ([`SignalRefusal::MislabelledSource`] if not): the
//!   vault and an import belong to the [`HostObserver::Broker`], an executor is the
//!   [`HostObserver::Executor`], and V14 accepts both. An executor uses only the narrow
//!   credential the vault holds (§4.5), never a canary, so a canary in what it was given
//!   came from the guest. The subject is the same canary, so a hit and
//!   a presentation of one canary are one incident. The grant the credential was presented
//!   on is compromised, so the violation names it when the checkpoint knows it.

use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::GrantId;
use crate::sandbox_contract::canaries::{CanaryHit, CredentialUseRefusal};
use crate::sandbox_contract::response::{
    HostObserver, MonitoringSignal, SignalRefusal, ViolationKind,
};

use super::observed::{draft_of, Classification, Observed};

/// Where a credential carrying a canary was presented and refused (V09: "The vault, an
/// executor or a credential import calls this before accepting a credential").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CredentialCheckpoint {
    Vault,
    Executor,
    Import,
}

impl CredentialCheckpoint {
    /// The host observer the checkpoint belongs to.
    pub const fn observer(self) -> HostObserver {
        match self {
            Self::Vault | Self::Import => HostObserver::Broker,
            Self::Executor => HostObserver::Executor,
        }
    }
}

/// What made a canary observation a violation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CanaryViolation {
    /// A V09 hit, host-observed by the relay or reported by the guest.
    Hit,
    /// A presented credential carried a canary value and was refused at this checkpoint.
    CredentialPresented { checkpoint: CredentialCheckpoint },
}

/// The signal of one canary hit (pure), on the host clock `session` the hit's times were
/// read from: always a violation, by V14's mapping.
pub fn canary_hit_signal(
    hit: &CanaryHit,
    session: ClockSession,
) -> Classification<CanaryViolation> {
    Classification::Violation {
        cause: CanaryViolation::Hit,
        draft: draft_of(&MonitoringSignal::from_canary_hit(hit, session)),
    }
}

/// The signal of one credential refused at `checkpoint` because it carries a canary
/// (pure), presented by the sandbox `observed` names on `presented_on`, the grant it was
/// presented under if the checkpoint knows it. Refused when V14 does not accept the
/// checkpoint's observer for a canary use.
pub fn canary_credential_signal(
    refusal: &CredentialUseRefusal,
    checkpoint: CredentialCheckpoint,
    observed: &Observed,
    presented_on: Option<GrantId>,
) -> Result<Classification<CanaryViolation>, SignalRefusal> {
    let CredentialUseRefusal::CanaryValue { canary, .. } = refusal;
    let draft = observed.violation(
        ViolationKind::CanaryUse,
        checkpoint.observer(),
        *canary.digest(),
        presented_on,
    );
    // V14's own check of the source label.
    MonitoringSignal::new(draft.clone())?;
    Ok(Classification::Violation {
        cause: CanaryViolation::CredentialPresented { checkpoint },
        draft,
    })
}
