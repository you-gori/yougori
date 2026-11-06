//! What every adapter shares (VM part §8.2 "Detection and audit"; VM-W43): the stamp of an
//! observation on the shared host clock, the classification of an enforcement point's
//! outcome, the host anomalies that are no guest's doing, and the typed reasons an outcome
//! is not a violation.
//!
//! The stamp is a reading of the host clock that V14 assesses freshness against
//! ([`assess_violation`](crate::sandbox_contract::response::assess_violation) takes the
//! same clock and session), never a time the guest claims. The sandbox is the one the host
//! knows from the channel, handle or perimeter it served, never one the guest names.
//!
//! Only something a sandbox's guest did is a violation, the only outcome that can revoke or
//! stop it. What the host side got wrong is either ordinary (a host fault or wiring bug the
//! guest cannot cause) or, where it may weaken the sandbox's confinement, a
//! [`HostAnomaly`]: it drafts no V14 signal about the guest, and the response it carries is
//! V14's uncertain result, notify the user and deny new high-impact operations, never more.

use std::collections::BTreeSet;
use std::fmt;

use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{Clock, Digest, ExecutionId, GrantId, MonotonicTime, TrustScope};
use crate::sandbox_contract::files::{LinkKind, RequestContext};
use crate::sandbox_contract::response::{
    HostObserver, MonitoringSignal, Reading, ResponseAction, SignalClass, SignalDraft,
    SignalSource, UncertainPolicy, ViolationKind,
};

/// Where and when a host enforcement point observed an outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observed {
    /// The sandbox the outcome is about, as the host knows it from the channel, handle or
    /// perimeter it served.
    pub sandbox: ExecutionId,
    /// When the enforcement point observed it, on the shared host clock.
    pub at: MonotonicTime,
    /// The host clock session `at` was read from.
    pub session: ClockSession,
}

/// A file request whose trust scope is not the one the host assigned the sandbox it is
/// attributed to: the attribution is wrong, so no observation is made of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeMismatch {
    pub sandbox: ExecutionId,
    /// The scope the host assigned the sandbox.
    pub expected: TrustScope,
    /// The scope the request carried.
    pub request: TrustScope,
}

impl fmt::Display for ScopeMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the request's trust scope is not the one sandbox {} was assigned",
            self.sandbox
        )
    }
}

impl std::error::Error for ScopeMismatch {}

impl Observed {
    /// An observation about `sandbox` stamped now: `clock` is the shared host clock and
    /// `session` its current session, the two V14 later assesses freshness against.
    pub fn read(sandbox: ExecutionId, clock: &dyn Clock, session: ClockSession) -> Self {
        Self {
            sandbox,
            at: clock.now(),
            session,
        }
    }

    /// An observation stamped with the host clock reading a file request was checked at
    /// ([`RequestContext::now`] and [`RequestContext::session`]), about `sandbox`, whose
    /// host-assigned trust scope `sandbox_scope` must be the request's.
    pub fn of_request(
        sandbox: ExecutionId,
        sandbox_scope: TrustScope,
        request: &RequestContext,
    ) -> Result<Self, ScopeMismatch> {
        if request.scope != sandbox_scope {
            return Err(ScopeMismatch {
                sandbox,
                expected: sandbox_scope,
                request: request.scope,
            });
        }
        Ok(Self {
            sandbox,
            at: request.now,
            session: request.session,
        })
    }

    /// The V14 draft of a violation `observer` saw itself.
    pub fn violation(
        &self,
        kind: ViolationKind,
        observer: HostObserver,
        subject: Digest,
        violated_grant: Option<GrantId>,
    ) -> SignalDraft {
        self.draft(
            kind,
            observer,
            subject,
            Reading::ViolationObserved,
            violated_grant,
        )
    }

    /// The V14 draft of a check `observer` made of `subject` that found no violation.
    pub(super) fn check_passed(
        &self,
        kind: ViolationKind,
        observer: HostObserver,
        subject: Digest,
    ) -> SignalDraft {
        self.draft(kind, observer, subject, Reading::CheckPassed, None)
    }

    /// The notice of a host anomaly `observer` met about `subject`.
    pub(super) fn anomaly(
        &self,
        anomaly: HostAnomaly,
        observer: HostObserver,
        subject: Digest,
    ) -> AnomalyNotice {
        AnomalyNotice {
            anomaly,
            sandbox: self.sandbox.clone(),
            observer,
            subject,
            observed_at: self.at,
            session: self.session,
        }
    }

    fn draft(
        &self,
        kind: ViolationKind,
        observer: HostObserver,
        subject: Digest,
        reading: Reading,
        violated_grant: Option<GrantId>,
    ) -> SignalDraft {
        SignalDraft {
            sandbox: self.sandbox.clone(),
            class: SignalClass::Violation { kind },
            source: SignalSource::HostObserved { observer },
            subject,
            reading,
            observed_at: self.at,
            session: self.session,
            violated_grant,
        }
    }
}

/// The draft a checked V14 signal was made from, so a signal V14 builds itself (a canary
/// hit) joins the same batches as the adapters' drafts.
pub(super) fn draft_of(signal: &MonitoringSignal) -> SignalDraft {
    SignalDraft {
        sandbox: signal.sandbox().clone(),
        class: signal.class(),
        source: signal.source(),
        subject: *signal.subject(),
        reading: signal.reading(),
        observed_at: signal.observed_at(),
        session: signal.session(),
        violated_grant: signal.violated_grant(),
    }
}

/// Something host-side an enforcement point met that may weaken the sandbox's confinement
/// but that its guest did not do and could not have done.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HostAnomaly {
    /// A link of this kind beneath a root only the host and the file service write (a
    /// read-only snapshot or quarantine output): the service never creates one.
    LinkInHostRoot { link: LinkKind },
    /// A device, FIFO or socket beneath such a root.
    DeviceInHostRoot,
    /// A rule outside the perimeter changed while the installer worked; it cannot tell who
    /// changed it.
    ForeignRuleChanged,
    /// A rule under the perimeter's tag that no transaction recorded; a tag is bookkeeping
    /// that anything with administrator rights can write.
    UnclaimedTaggedRule,
    /// Recovery rolled back, verified the perimeter's own rules and left this many rules
    /// under its tag that no transaction recorded.
    UnclaimedAfterRecovery { rules: usize },
}

/// A host anomaly about one sandbox, and what the runtime does about it: V14's uncertain
/// result ([`UncertainPolicy::ACTIONS`]), never a revocation or a stop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnomalyNotice {
    pub anomaly: HostAnomaly,
    /// The sandbox whose confinement the anomaly may weaken.
    pub sandbox: ExecutionId,
    /// The host component that met it.
    pub observer: HostObserver,
    /// What it is about: the entry or the perimeter, as a digest.
    pub subject: Digest,
    /// When, on the shared host clock.
    pub observed_at: MonotonicTime,
    /// The host clock session `observed_at` was read from.
    pub session: ClockSession,
}

impl AnomalyNotice {
    /// The response to a host anomaly: notify the user and deny new high-impact
    /// operations, the uncertain result of V14, never more and never nothing.
    pub fn actions(&self) -> BTreeSet<ResponseAction> {
        UncertainPolicy::ACTIONS.into_iter().collect()
    }
}

/// Why an enforcement point's outcome is not a violation: the point refused an ordinary
/// request as designed, or the host side failed. No signal is drafted for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Ordinary {
    /// The entry, name or answer does not exist.
    NotFound,
    /// The entry exists already, is not empty or is of another kind than the request
    /// needs: the ordinary state of the tree.
    EntryState,
    /// A second spelling of a stored name on a case-insensitive root was refused; nothing
    /// was planted.
    CaseSpelling,
    /// A link, device or socket a live workspace legitimately holds (package-manager hard
    /// links, a development server's socket) was refused and not followed.
    WorkspaceEntry,
    /// A size, quota or budget refused the request before anything was used.
    LimitReached,
    /// The grant or policy does not permit the request: something not granted was asked
    /// for and refused.
    NotPermitted,
    /// Authority, an answer or a validation is no longer current; the caller checks again.
    NotCurrent,
    /// The entry changed while the enforcement point worked on it, and nothing was
    /// followed.
    ChangedDuringRequest,
    /// The resolver's answer, the server's redirect or the destination's address cannot be
    /// used: a refused address class, another name or family, an empty or overlong answer.
    UnusableDestination,
    /// The host side failed: I/O, an unreadable or unavailable store, a journal write, a
    /// root it cannot count.
    HostFault,
    /// The host presented its enforcement point something only the host holds that the
    /// point never issued or already settled, such as a move-only reservation: a wiring
    /// bug the guest cannot cause.
    HostWiring,
    /// The host called the enforcement point inconsistently or with a configuration it
    /// refuses: another root, a stale plan, a mismatched grant, an identity the platform
    /// does not offer.
    HostConfiguration,
    /// The outcome checked nothing a signal could carry.
    NothingObserved,
}

impl Ordinary {
    /// The snake_case label used in audit fields.
    pub const fn label(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::EntryState => "entry_state",
            Self::CaseSpelling => "case_spelling",
            Self::WorkspaceEntry => "workspace_entry",
            Self::LimitReached => "limit_reached",
            Self::NotPermitted => "not_permitted",
            Self::NotCurrent => "not_current",
            Self::ChangedDuringRequest => "changed_during_request",
            Self::UnusableDestination => "unusable_destination",
            Self::HostFault => "host_fault",
            Self::HostWiring => "host_wiring",
            Self::HostConfiguration => "host_configuration",
            Self::NothingObserved => "nothing_observed",
        }
    }
}

impl fmt::Display for Ordinary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// What an adapter's classifier found, before drafting.
pub(super) enum Finding<V> {
    Violation(V),
    Anomaly(HostAnomaly),
    Ordinary(Ordinary),
}

impl<V> Finding<V> {
    /// The stronger of two findings about one outcome: a violation over an anomaly over an
    /// ordinary reason, the first on a tie.
    pub(super) fn or(self, other: Self) -> Self {
        match (self, other) {
            (Self::Violation(cause), _) | (_, Self::Violation(cause)) => Self::Violation(cause),
            (Self::Anomaly(anomaly), _) | (_, Self::Anomaly(anomaly)) => Self::Anomaly(anomaly),
            (ordinary, _) => ordinary,
        }
    }
}

/// What one enforcement point's outcome is to monitoring (VM-W43): a guest violation with
/// its typed cause and V14 draft, a host check that found nothing, a host anomaly that is
/// no guest's doing, or an ordinary outcome that drafts nothing. `V` is the adapter's
/// violation cause.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Classification<V> {
    /// A known violation by the sandbox's guest, observed by a host enforcement point.
    Violation { cause: V, draft: SignalDraft },
    /// The enforcement point checked the subject and found no violation: it can
    /// contradict another host observation and never clears one by itself (V14
    /// [`Reading::CheckPassed`]).
    CheckPassed { draft: SignalDraft },
    /// A host anomaly: no V14 signal about the guest, and V14's uncertain result.
    HostAnomaly { notice: AnomalyNotice },
    /// Not a violation, and why.
    Ordinary { reason: Ordinary },
}

impl<V> Classification<V> {
    /// The draft to feed V14, if the outcome drafts one.
    pub fn draft(&self) -> Option<&SignalDraft> {
        match self {
            Self::Violation { draft, .. } | Self::CheckPassed { draft } => Some(draft),
            Self::HostAnomaly { .. } | Self::Ordinary { .. } => None,
        }
    }

    /// The draft, taken.
    pub fn into_draft(self) -> Option<SignalDraft> {
        match self {
            Self::Violation { draft, .. } | Self::CheckPassed { draft } => Some(draft),
            Self::HostAnomaly { .. } | Self::Ordinary { .. } => None,
        }
    }

    /// The violation's cause, if the outcome is one.
    pub fn cause(&self) -> Option<&V> {
        match self {
            Self::Violation { cause, .. } => Some(cause),
            Self::CheckPassed { .. } | Self::HostAnomaly { .. } | Self::Ordinary { .. } => None,
        }
    }

    /// The host anomaly's notice, if the outcome is one.
    pub fn anomaly(&self) -> Option<&AnomalyNotice> {
        match self {
            Self::HostAnomaly { notice } => Some(notice),
            Self::Violation { .. } | Self::CheckPassed { .. } | Self::Ordinary { .. } => None,
        }
    }

    /// Why the outcome is not a violation, if it is an ordinary one.
    pub fn ordinary(&self) -> Option<Ordinary> {
        match self {
            Self::Ordinary { reason } => Some(*reason),
            Self::Violation { .. } | Self::CheckPassed { .. } | Self::HostAnomaly { .. } => None,
        }
    }

    /// Whether the outcome is a guest violation.
    pub const fn is_violation(&self) -> bool {
        matches!(self, Self::Violation { .. })
    }
}
