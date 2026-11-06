//! Monitoring signals: what was observed about a sandbox, by whom and when (VM part §8.2
//! lines 2266–2268 and 2274; VM-W43 line 2491).
//!
//! Authorization decisions, budgets, lease events, launch facts and termination receipts
//! are kept outside the guest, and guest stdout and syscall reports are untrusted
//! observations (line 2268). A signal therefore names its source: one of the host
//! observers, or the guest. Hypervisor counters are host observations about the VM and the
//! hypervisor process; they do not reveal what happens inside the guest, and a signal that
//! claims a host observer which cannot see the thing observed is refused rather than
//! relabelled.

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::foundation::events::{AuditDraft, Field, HostFact};
use crate::foundation::evidence::{ClockSession, SourceClass, Staleness};
use crate::foundation::ids::{Digest, ExecutionId, GrantId, MonotonicTime};
use crate::sandbox_contract::canaries::{CanaryHit, ObservationSource};

/// A host component that observes a sandbox from outside the guest (§8.2 line 2268).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostObserver {
    /// The sandbox supervisor: launch facts, artifact checks, bindings and host processes.
    Supervisor,
    /// The credential and operation broker: credential use, release budgets, replays.
    Broker,
    /// The independent network perimeter and its relay: destinations, packets, connections.
    Perimeter,
    /// Counters the host reads about the VM and the hypervisor process (CPU time, memory,
    /// disk and network I/O). Host-observed, but blind to what happens inside the guest.
    HypervisorCounters,
    /// The narrow executor of external effects.
    Executor,
}

impl HostObserver {
    /// Every host observer.
    pub const ALL: [Self; 5] = [
        Self::Supervisor,
        Self::Broker,
        Self::Perimeter,
        Self::HypervisorCounters,
        Self::Executor,
    ];

    /// The snake_case label used in audit fields.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Supervisor => "supervisor",
            Self::Broker => "broker",
            Self::Perimeter => "perimeter",
            Self::HypervisorCounters => "hypervisor_counters",
            Self::Executor => "executor",
        }
    }
}

strict_response_enum! {
    /// Who observed a signal (§8.2 line 2268: label telemetry sources correctly).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum SignalSource tag "source" {
        /// A host observer saw it itself.
        HostObserved {
            /// Which one.
            observer: HostObserver,
        },
        /// The guest reported it: untrusted, whatever it claims, and it stays labelled so.
        GuestReported,
    }
}

impl SignalSource {
    /// The CORE-01 source class: a guest report stays one.
    pub const fn source_class(self) -> SourceClass {
        match self {
            Self::HostObserved { .. } => SourceClass::HostProbe,
            Self::GuestReported => SourceClass::GuestReport,
        }
    }

    /// Whether a host observer saw it.
    pub const fn is_host_observed(self) -> bool {
        matches!(self, Self::HostObserved { .. })
    }

    /// The host observer, if any.
    pub const fn observer(self) -> Option<HostObserver> {
        match self {
            Self::HostObserved { observer } => Some(observer),
            Self::GuestReported => None,
        }
    }

    /// The snake_case label used in audit fields.
    pub const fn label(self) -> &'static str {
        match self {
            Self::HostObserved { .. } => "host_observed",
            Self::GuestReported => "guest_reported",
        }
    }
}

/// A known violation (VM-W43 "known violations trigger bounded responses").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationKind {
    /// Use of an internal canary (VM-W10): a signal, not proof of malicious intent (§8.2
    /// line 2274).
    CanaryUse,
    /// Traffic outside the declared perimeter or destination rules.
    PerimeterRule,
    /// A credential presented again outside its single use or its binding.
    CredentialReplay,
    /// An operation capability presented again, or under another binding (§6.3 line 2141).
    CapabilityReplay,
    /// A launch artifact whose identity does not match what was verified.
    LaunchArtifactIntegrity,
    /// A request under a policy epoch that is no longer current.
    PolicyEpochMismatch,
    /// A request under an authorization epoch that is no longer current.
    AuthorizationEpochMismatch,
    /// A guest reaching for files outside the roots its own grants bind, such as through a
    /// file grant presented from another trust scope than the one it binds (§5.1
    /// "Capability-rooted access"; VM-P15: the guest cannot escape the granted root).
    FileRootEscape,
    /// More used than a budget the guest was granted, beyond any documented allowance:
    /// bytes released past a reservation and its in-flight allowance (§2.5 "Bound releases
    /// and post-revocation exposure").
    BudgetOverrun,
}

impl ViolationKind {
    /// Every variant.
    pub const ALL: [Self; 9] = [
        Self::CanaryUse,
        Self::PerimeterRule,
        Self::CredentialReplay,
        Self::CapabilityReplay,
        Self::LaunchArtifactIntegrity,
        Self::PolicyEpochMismatch,
        Self::AuthorizationEpochMismatch,
        Self::FileRootEscape,
        Self::BudgetOverrun,
    ];

    /// The snake_case label used in audit fields.
    pub const fn label(self) -> &'static str {
        match self {
            Self::CanaryUse => "canary_use",
            Self::PerimeterRule => "perimeter_rule",
            Self::CredentialReplay => "credential_replay",
            Self::CapabilityReplay => "capability_replay",
            Self::LaunchArtifactIntegrity => "launch_artifact_integrity",
            Self::PolicyEpochMismatch => "policy_epoch_mismatch",
            Self::AuthorizationEpochMismatch => "authorization_epoch_mismatch",
            Self::FileRootEscape => "file_root_escape",
            Self::BudgetOverrun => "budget_overrun",
        }
    }

    /// The host observers that can see this violation themselves.
    pub const fn host_observers(self) -> &'static [HostObserver] {
        match self {
            // The relay sees a canary leave; the vault, a credential import and an executor
            // each refuse a canary credential presented to them (V09). An executor uses only
            // the credential the vault holds (§4.5), which is never a canary, so a canary
            // value in what it was given came from the guest.
            Self::CanaryUse => &[
                HostObserver::Perimeter,
                HostObserver::Broker,
                HostObserver::Executor,
            ],
            Self::PerimeterRule => &[HostObserver::Perimeter],
            Self::CredentialReplay => &[HostObserver::Broker, HostObserver::Executor],
            Self::CapabilityReplay
            | Self::PolicyEpochMismatch
            | Self::AuthorizationEpochMismatch => &[
                HostObserver::Supervisor,
                HostObserver::Broker,
                HostObserver::Executor,
            ],
            Self::LaunchArtifactIntegrity => &[HostObserver::Supervisor],
            // The file service checks each request's grant against the requester's scope.
            Self::FileRootEscape => &[HostObserver::Supervisor],
            // The release budgets a guest is granted are settled by the broker's release
            // account and route budgets and the executor's release ledger, the observers of
            // `MonitoredResource::ReleaseBudgetSpentBytes`.
            Self::BudgetOverrun => &[HostObserver::Broker, HostObserver::Executor],
        }
    }
}

/// A resource the monitor judges over sustained windows (VM-W43).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MonitoredResource {
    CpuMillicores,
    MemoryBytes,
    DiskBytes,
    /// Host processes of the sandbox as the supervisor counts them; processes inside the
    /// guest are only ever guest-reported.
    ProcessCount,
    PacketsPerSecond,
    ConnectionsPerSecond,
    /// Bytes spent of the sandbox's release budget (§2.5 lines 1810–1814).
    ReleaseBudgetSpentBytes,
}

impl MonitoredResource {
    /// Every variant.
    pub const ALL: [Self; 7] = [
        Self::CpuMillicores,
        Self::MemoryBytes,
        Self::DiskBytes,
        Self::ProcessCount,
        Self::PacketsPerSecond,
        Self::ConnectionsPerSecond,
        Self::ReleaseBudgetSpentBytes,
    ];

    /// The snake_case label used in audit fields.
    pub const fn label(self) -> &'static str {
        match self {
            Self::CpuMillicores => "cpu_millicores",
            Self::MemoryBytes => "memory_bytes",
            Self::DiskBytes => "disk_bytes",
            Self::ProcessCount => "process_count",
            Self::PacketsPerSecond => "packets_per_second",
            Self::ConnectionsPerSecond => "connections_per_second",
            Self::ReleaseBudgetSpentBytes => "release_budget_spent_bytes",
        }
    }

    /// The unit every amount and mark of this resource is in.
    pub const fn unit(self) -> &'static str {
        match self {
            Self::CpuMillicores => "millicores",
            Self::MemoryBytes | Self::DiskBytes | Self::ReleaseBudgetSpentBytes => "bytes",
            Self::ProcessCount => "processes",
            Self::PacketsPerSecond => "packets_per_second",
            Self::ConnectionsPerSecond => "connections_per_second",
        }
    }

    /// The host observers that can measure this resource themselves.
    pub const fn host_observers(self) -> &'static [HostObserver] {
        match self {
            Self::CpuMillicores | Self::MemoryBytes => &[HostObserver::HypervisorCounters],
            Self::DiskBytes => &[HostObserver::HypervisorCounters, HostObserver::Supervisor],
            Self::ProcessCount => &[HostObserver::Supervisor],
            Self::PacketsPerSecond => &[HostObserver::Perimeter, HostObserver::HypervisorCounters],
            Self::ConnectionsPerSecond => &[HostObserver::Perimeter],
            Self::ReleaseBudgetSpentBytes => &[HostObserver::Broker, HostObserver::Executor],
        }
    }
}

strict_response_enum! {
    /// What a signal is about: a known violation or a resource.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum SignalClass tag "class" {
        Violation {
            kind: ViolationKind,
        },
        Resource {
            resource: MonitoredResource,
        },
    }
}

impl SignalClass {
    /// Every class: the violations, then the resources.
    pub fn all() -> Vec<Self> {
        ViolationKind::ALL
            .iter()
            .map(|&kind| Self::Violation { kind })
            .chain(
                MonitoredResource::ALL
                    .iter()
                    .map(|&resource| Self::Resource { resource }),
            )
            .collect()
    }

    /// The host observers that can see this class themselves.
    pub const fn host_observers(self) -> &'static [HostObserver] {
        match self {
            Self::Violation { kind } => kind.host_observers(),
            Self::Resource { resource } => resource.host_observers(),
        }
    }

    /// The snake_case label used in audit fields and identities.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Violation { kind } => kind.label(),
            Self::Resource { resource } => resource.label(),
        }
    }

    /// Whether the class is a known violation.
    pub const fn is_violation(self) -> bool {
        matches!(self, Self::Violation { .. })
    }
}

impl fmt::Display for SignalClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// The grant a violation was against (a credential, route, file or capability grant): the
/// shared CORE-04 grant identity, so the grant a response names is the one CORE-04 can
/// revoke under one execution. A response reaches another sandbox only when that sandbox
/// holds the same grant (VM-W43). The name stays for this module's callers; the wire form
/// is the identity's digest, as before.
pub type GrantRef = GrantId;

strict_response_enum! {
    /// What the observer read.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum Reading tag "reading" {
        /// The observer saw the violation.
        ViolationObserved,
        /// The observer checked the same subject and found no violation. It can contradict
        /// another host observation; it never clears one by itself.
        CheckPassed,
        /// A resource amount in the resource's unit ([`MonitoredResource::unit`]).
        Amount {
            amount: u64,
        },
    }
}

impl Reading {
    /// The snake_case label used in audit fields.
    pub const fn label(self) -> &'static str {
        match self {
            Self::ViolationObserved => "violation_observed",
            Self::CheckPassed => "check_passed",
            Self::Amount { .. } => "amount",
        }
    }
}

/// Why a signal was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignalRefusal {
    /// The named host observer cannot see this class itself (§8.2 line 2268: label
    /// telemetry sources correctly).
    MislabelledSource {
        class: SignalClass,
        observer: HostObserver,
    },
    /// A violation needs a violation reading, a resource an amount.
    ReadingDoesNotFitClass {
        class: SignalClass,
        reading: Reading,
    },
    /// Only a violation is against a grant.
    GrantOnResourceSignal { class: SignalClass },
}

impl fmt::Display for SignalRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MislabelledSource { class, observer } => write!(
                f,
                "the {} cannot observe {class} itself; the signal is refused rather than relabelled",
                observer.label()
            ),
            Self::ReadingDoesNotFitClass { class, reading } => {
                write!(f, "a {} reading does not fit {class}", reading.label())
            }
            Self::GrantOnResourceSignal { class } => {
                write!(f, "{class} is a resource signal and is against no grant")
            }
        }
    }
}

impl std::error::Error for SignalRefusal {}

/// The parts of a signal before its source label and reading are checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignalDraft {
    /// The sandbox the observation is about, as the host knows it from the channel or
    /// counter it read, never from what the guest says.
    pub sandbox: ExecutionId,
    pub class: SignalClass,
    pub source: SignalSource,
    /// What the signal is about: the canary, rule, credential, capability or artifact
    /// identity, or the resource series.
    pub subject: Digest,
    pub reading: Reading,
    /// When the host observed it, or received the guest's report, on the host clock. No
    /// time the guest claims is used.
    pub observed_at: MonotonicTime,
    /// The host clock session `observed_at` was read from.
    pub session: ClockSession,
    /// The grant the violation was against, if known.
    pub violated_grant: Option<GrantRef>,
}

/// One monitoring signal (§8.2; VM-W43). Built only from a checked [`SignalDraft`] or a V09
/// canary hit; reading one back refuses what the checks would refuse.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawSignal")]
pub struct MonitoringSignal {
    sandbox: ExecutionId,
    class: SignalClass,
    source: SignalSource,
    subject: Digest,
    reading: Reading,
    observed_at: MonotonicTime,
    session: ClockSession,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    violated_grant: Option<GrantRef>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSignal {
    sandbox: ExecutionId,
    class: SignalClass,
    source: SignalSource,
    subject: Digest,
    reading: Reading,
    observed_at: MonotonicTime,
    session: ClockSession,
    #[serde(default)]
    violated_grant: Option<GrantRef>,
}

impl TryFrom<RawSignal> for MonitoringSignal {
    type Error = SignalRefusal;

    fn try_from(raw: RawSignal) -> Result<Self, Self::Error> {
        Self::new(SignalDraft {
            sandbox: raw.sandbox,
            class: raw.class,
            source: raw.source,
            subject: raw.subject,
            reading: raw.reading,
            observed_at: raw.observed_at,
            session: raw.session,
            violated_grant: raw.violated_grant,
        })
    }
}

impl MonitoringSignal {
    /// Checks the source label and the reading against the class.
    pub fn new(draft: SignalDraft) -> Result<Self, SignalRefusal> {
        if let SignalSource::HostObserved { observer } = draft.source {
            if !draft.class.host_observers().contains(&observer) {
                return Err(SignalRefusal::MislabelledSource {
                    class: draft.class,
                    observer,
                });
            }
        }
        let fits = match draft.class {
            SignalClass::Violation { .. } => matches!(
                draft.reading,
                Reading::ViolationObserved | Reading::CheckPassed
            ),
            SignalClass::Resource { .. } => matches!(draft.reading, Reading::Amount { .. }),
        };
        if !fits {
            return Err(SignalRefusal::ReadingDoesNotFitClass {
                class: draft.class,
                reading: draft.reading,
            });
        }
        if draft.violated_grant.is_some() && !draft.class.is_violation() {
            return Err(SignalRefusal::GrantOnResourceSignal { class: draft.class });
        }
        Ok(Self {
            sandbox: draft.sandbox,
            class: draft.class,
            source: draft.source,
            subject: draft.subject,
            reading: draft.reading,
            observed_at: draft.observed_at,
            session: draft.session,
            violated_grant: draft.violated_grant,
        })
    }

    /// A V09 canary hit as one monitoring input (§8.2 line 2274: a signal, not proof). The
    /// signal is about the sandbox whose traffic or report carried the canary, and its
    /// subject is the canary. A host-observed hit was seen by the relay, which belongs to
    /// the perimeter; a guest-reported hit stays guest-reported and is dated when the host
    /// matched it.
    pub fn from_canary_hit(hit: &CanaryHit, session: ClockSession) -> Self {
        let (source, observed_at) = match hit.source() {
            ObservationSource::HostObserved { observed_at } => (
                SignalSource::HostObserved {
                    observer: HostObserver::Perimeter,
                },
                observed_at,
            ),
            ObservationSource::GuestReported => (SignalSource::GuestReported, hit.matched_at()),
        };
        Self {
            sandbox: hit.observed_in().sandbox.execution.clone(),
            class: SignalClass::Violation {
                kind: ViolationKind::CanaryUse,
            },
            source,
            subject: *hit.canary().digest(),
            reading: Reading::ViolationObserved,
            observed_at,
            session,
            violated_grant: None,
        }
    }

    /// The sandbox the observation is about.
    pub fn sandbox(&self) -> &ExecutionId {
        &self.sandbox
    }

    /// The violation or resource class.
    pub const fn class(&self) -> SignalClass {
        self.class
    }

    /// Who observed it.
    pub const fn source(&self) -> SignalSource {
        self.source
    }

    /// What it is about.
    pub const fn subject(&self) -> &Digest {
        &self.subject
    }

    /// What the observer read.
    pub const fn reading(&self) -> Reading {
        self.reading
    }

    /// When the host observed or received it.
    pub const fn observed_at(&self) -> MonotonicTime {
        self.observed_at
    }

    /// The host clock session of `observed_at`.
    pub const fn session(&self) -> ClockSession {
        self.session
    }

    /// The grant the violation was against, if known.
    pub const fn violated_grant(&self) -> Option<GrantRef> {
        self.violated_grant
    }

    /// How fresh the signal is at `now` on `current_session`.
    pub fn freshness(
        &self,
        now: MonotonicTime,
        current_session: ClockSession,
        max_age: Duration,
    ) -> Freshness {
        judge_freshness(
            self.observed_at,
            self.session,
            now,
            current_session,
            max_age,
        )
    }

    /// The signal as CORE-06 metadata fields: identifiers, digests, counts and labels.
    pub fn audit_fields(&self) -> Vec<Field> {
        let mut fields = vec![
            Field::metadata("event", "monitoring_signal"),
            Field::metadata("sandbox", self.sandbox.as_str()),
            Field::metadata("class", self.class.label()),
            Field::metadata("source", self.source.label()),
            Field::metadata("subject", self.subject),
            Field::metadata("reading", self.reading.label()),
            Field::metadata("observed_at_ns", self.observed_at.as_nanos()),
        ];
        if let Some(observer) = self.source.observer() {
            fields.push(Field::metadata("observer", observer.label()));
        }
        if let Reading::Amount { amount } = self.reading {
            fields.push(Field::metadata("amount", amount));
            if let SignalClass::Resource { resource } = self.class {
                fields.push(Field::metadata("unit", resource.unit()));
            }
        }
        if let Some(grant) = self.violated_grant {
            fields.push(Field::metadata("violated_grant", *grant.digest()));
        }
        fields
    }

    /// The CORE-06 audit draft: a host-observed signal is a host fact of kind
    /// [`HostFact::DetectionSignal`]; a guest-reported one is a guest observation, which
    /// the journal labels a guest report and bounds by its emission limit.
    pub fn audit_draft(&self) -> AuditDraft {
        match self.source {
            SignalSource::HostObserved { .. } => AuditDraft::HostFact {
                fact: HostFact::DetectionSignal,
                fields: self.audit_fields(),
            },
            SignalSource::GuestReported => AuditDraft::GuestObservation {
                fields: self.audit_fields(),
            },
        }
    }
}

/// Two host observers that disagree about one subject: one saw the violation or the
/// exceeded limit, the other checked and found none.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Conflict {
    pub reported_by: HostObserver,
    pub contradicted_by: HostObserver,
}

strict_response_enum! {
    /// Whether an observation can be acted on (VM-W43; CORE-01 freshness). A stale or
    /// conflicting observation is an uncertain result, never a pass.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Freshness tag "freshness" {
        Fresh,
        Stale {
            staleness: Staleness,
        },
        Conflicting {
            conflict: Conflict,
        },
    }
}

impl Freshness {
    /// Whether the observation can be acted on.
    pub const fn is_fresh(self) -> bool {
        matches!(self, Self::Fresh)
    }

    /// The snake_case label used in audit fields.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Stale { .. } => "stale",
            Self::Conflicting { .. } => "conflicting",
        }
    }
}

/// Judges one observation time against the host clock (CORE-01 freshness rules): another
/// clock session is stale because its age cannot be known, a time after `now` is stale
/// because a monotonic clock never produces one, and an age above `max_age` is too old.
/// An age of exactly `max_age` is fresh.
pub fn judge_freshness(
    observed_at: MonotonicTime,
    observed_session: ClockSession,
    now: MonotonicTime,
    current_session: ClockSession,
    max_age: Duration,
) -> Freshness {
    if observed_session != current_session {
        return Freshness::Stale {
            staleness: Staleness::OtherClock,
        };
    }
    let Some(age) = now.checked_duration_since(observed_at) else {
        return Freshness::Stale {
            staleness: Staleness::ObservedAfterNow,
        };
    };
    if age > max_age {
        return Freshness::Stale {
            staleness: Staleness::TooOld {
                age,
                limit: max_age,
            },
        };
    }
    Freshness::Fresh
}
