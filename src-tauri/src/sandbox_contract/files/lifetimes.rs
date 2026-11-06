//! Leases and lifetimes (VM part §6.2 lines 2121–2127; VM-D12; VM-W25; VM-P18, VM-P40).
//!
//! Everything here is built on the coordination leases (CORE-04): a [`LifetimePolicy`]
//! turns the per-call, task, idle, absolute and service-renewal limits into
//! `LeaseTerms` and a launch's authority lifetime, and the coordinator issues, renews and
//! checks the leases. The starting values are VM-D12's: idle 12 h and absolute 24 h for
//! task sandboxes, service renewal every 7 days. The per-call and task limits have no
//! plan default and come from the workload's needs.
//!
//! - [`IdleKeepAlive`] renews the idle lease only on host-observed activity: a host call
//!   under a live call lease of the same sandbox, or user interaction. Network traffic in
//!   either direction, output streams and guest heartbeats never renew it (line 2123), so
//!   a busy stream cannot keep an idle VM alive (VM-P18).
//! - [`ExpiryGuard`] checks leases through the coordinator, presented with its clock
//!   session: the coordinator's own clock high-water mark refuses a clock that went back
//!   and its session check refuses a lease from another run. The guard persists the leases
//!   it saw refused and never honours one again, so neither a clock that goes back and
//!   recovers nor a restart revives an expired or refused lease (§6.2: persist enough
//!   state to prevent clock rollback or snapshot restore from reviving expired rights).
//! - [`ClockSkewPolicy`] turns a remote expiry into a local monotonic deadline under an
//!   explicit skew allowance, refuses excessive skew and lifetimes, and a
//!   [`WallClockGuard`] keeps the wall-clock high-water mark and ended rights across
//!   restarts. A [`LocalExpiry`] is bound to its clock session and boot generation, so a
//!   restart or snapshot restore never revives it (VM-P40).

use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::class::SandboxClass;
use crate::foundation::coordination::{
    CapacityPort, Coordinator, LaunchPlan, Lease, LeaseKind, LeaseRefusal, LeaseTerms,
};
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{
    Clock, Digest, ExecutionId, LeaseId, MonotonicTime, OperationId, SandboxBootGeneration,
};

/// VM-D12: a task sandbox's idle limit, 12 h.
pub const DEFAULT_IDLE_SECONDS: u64 = 12 * 3_600;
/// VM-D12: a task sandbox's absolute limit, 24 h.
pub const DEFAULT_TASK_ABSOLUTE_SECONDS: u64 = 24 * 3_600;
/// VM-D12: a service sandbox renews at least every 7 days.
pub const DEFAULT_SERVICE_RENEWAL_SECONDS: u64 = 7 * 24 * 3_600;

/// One of the limits of §6.2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifetimeLimit {
    PerCall,
    Task,
    Idle,
    Absolute,
    ServiceRenewal,
    CancelWithin,
}

/// Why lifetime limits were refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum LifetimeProblem {
    Zero {
        limit: LifetimeLimit,
    },
    /// `limit` is longer than `bound`, which must contain it.
    Exceeds {
        limit: LifetimeLimit,
        bound: LifetimeLimit,
    },
    /// The limit does not apply to the class, such as a task limit on a service.
    NotForClass {
        limit: LifetimeLimit,
        class: SandboxClass,
    },
    /// A launch asked for more authority than the policy's absolute or renewal limit.
    AuthorityTooLong {
        plan_seconds: u64,
        policy_seconds: u64,
    },
}

impl fmt::Display for LifetimeProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero { limit } => write!(f, "the {limit:?} limit is zero"),
            Self::Exceeds { limit, bound } => {
                write!(f, "the {limit:?} limit is longer than the {bound:?} limit")
            }
            Self::NotForClass { limit, class } => {
                write!(f, "the {limit:?} limit does not apply to {class:?} sandboxes")
            }
            Self::AuthorityTooLong {
                plan_seconds,
                policy_seconds,
            } => write!(
                f,
                "the launch asks for {plan_seconds} s of authority; the policy allows {policy_seconds} s"
            ),
        }
    }
}

impl std::error::Error for LifetimeProblem {}

/// The lifetime limits of one sandbox (§6.2; VM-D12), all in seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "PolicyWire")]
pub struct LifetimePolicy {
    class: SandboxClass,
    per_call_seconds: u64,
    task_seconds: Option<u64>,
    idle_seconds: Option<u64>,
    absolute_seconds: Option<u64>,
    service_renewal_seconds: Option<u64>,
    cancel_within_seconds: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyWire {
    class: SandboxClass,
    per_call_seconds: u64,
    task_seconds: Option<u64>,
    idle_seconds: Option<u64>,
    absolute_seconds: Option<u64>,
    service_renewal_seconds: Option<u64>,
    cancel_within_seconds: u64,
}

impl TryFrom<PolicyWire> for LifetimePolicy {
    type Error = LifetimeProblem;

    fn try_from(wire: PolicyWire) -> Result<Self, Self::Error> {
        Self {
            class: wire.class,
            per_call_seconds: wire.per_call_seconds,
            task_seconds: wire.task_seconds,
            idle_seconds: wire.idle_seconds,
            absolute_seconds: wire.absolute_seconds,
            service_renewal_seconds: wire.service_renewal_seconds,
            cancel_within_seconds: wire.cancel_within_seconds,
        }
        .checked()
    }
}

fn seconds(value: u64) -> Duration {
    Duration::from_secs(value)
}

impl LifetimePolicy {
    /// A task sandbox with VM-D12's idle (12 h) and absolute (24 h) limits; the per-call
    /// and task limits come from the workload.
    pub fn task(
        per_call_seconds: u64,
        task_seconds: u64,
        cancel_within_seconds: u64,
    ) -> Result<Self, LifetimeProblem> {
        Self {
            class: SandboxClass::Task,
            per_call_seconds,
            task_seconds: Some(task_seconds),
            idle_seconds: Some(DEFAULT_IDLE_SECONDS),
            absolute_seconds: Some(DEFAULT_TASK_ABSOLUTE_SECONDS),
            service_renewal_seconds: None,
            cancel_within_seconds,
        }
        .checked()
    }

    /// A service sandbox renewed at least every 7 days (VM-D12). A service has no idle
    /// limit by default; the renewal limit bounds it whatever its traffic.
    pub fn service(
        per_call_seconds: u64,
        cancel_within_seconds: u64,
    ) -> Result<Self, LifetimeProblem> {
        Self {
            class: SandboxClass::Service,
            per_call_seconds,
            task_seconds: None,
            idle_seconds: None,
            absolute_seconds: None,
            service_renewal_seconds: Some(DEFAULT_SERVICE_RENEWAL_SECONDS),
            cancel_within_seconds,
        }
        .checked()
    }

    /// The idle limit adjusted from measurement (VM-D12, §12.4).
    pub fn with_idle_seconds(mut self, idle_seconds: u64) -> Result<Self, LifetimeProblem> {
        self.idle_seconds = Some(idle_seconds);
        self.checked()
    }

    /// The task sandbox's absolute limit adjusted from measurement.
    pub fn with_absolute_seconds(mut self, absolute_seconds: u64) -> Result<Self, LifetimeProblem> {
        if self.class != SandboxClass::Task {
            return Err(LifetimeProblem::NotForClass {
                limit: LifetimeLimit::Absolute,
                class: self.class,
            });
        }
        self.absolute_seconds = Some(absolute_seconds);
        self.checked()
    }

    /// The service renewal limit adjusted from measurement.
    pub fn with_service_renewal_seconds(
        mut self,
        service_renewal_seconds: u64,
    ) -> Result<Self, LifetimeProblem> {
        if self.class != SandboxClass::Service {
            return Err(LifetimeProblem::NotForClass {
                limit: LifetimeLimit::ServiceRenewal,
                class: self.class,
            });
        }
        self.service_renewal_seconds = Some(service_renewal_seconds);
        self.checked()
    }

    fn checked(self) -> Result<Self, LifetimeProblem> {
        let class = self.class;
        let not_for = |limit| Err(LifetimeProblem::NotForClass { limit, class });
        match class {
            SandboxClass::Task => {
                if self.service_renewal_seconds.is_some() {
                    return not_for(LifetimeLimit::ServiceRenewal);
                }
            }
            SandboxClass::Service => {
                if self.task_seconds.is_some() {
                    return not_for(LifetimeLimit::Task);
                }
                if self.absolute_seconds.is_some() {
                    return not_for(LifetimeLimit::Absolute);
                }
            }
        }
        let outer = self.outer();
        let (outer_limit, outer_seconds) = outer.ok_or(LifetimeProblem::Zero {
            limit: match class {
                SandboxClass::Task => LifetimeLimit::Absolute,
                SandboxClass::Service => LifetimeLimit::ServiceRenewal,
            },
        })?;
        let mut limits = vec![
            (LifetimeLimit::PerCall, Some(self.per_call_seconds)),
            (LifetimeLimit::Task, self.task_seconds),
            (LifetimeLimit::Idle, self.idle_seconds),
            (outer_limit, Some(outer_seconds)),
            (
                LifetimeLimit::CancelWithin,
                Some(self.cancel_within_seconds),
            ),
        ];
        limits.retain(|(_, value)| value.is_some());
        for (limit, value) in &limits {
            if *value == Some(0) {
                return Err(LifetimeProblem::Zero { limit: *limit });
            }
        }
        let bound = self
            .task_seconds
            .map_or((outer_limit, outer_seconds), |task| {
                (LifetimeLimit::Task, task)
            });
        if self.per_call_seconds > bound.1 {
            return Err(LifetimeProblem::Exceeds {
                limit: LifetimeLimit::PerCall,
                bound: bound.0,
            });
        }
        for (limit, value) in [
            (LifetimeLimit::Task, self.task_seconds),
            (LifetimeLimit::Idle, self.idle_seconds),
        ] {
            if value.is_some_and(|value| value > outer_seconds) {
                return Err(LifetimeProblem::Exceeds {
                    limit,
                    bound: outer_limit,
                });
            }
        }
        Ok(self)
    }

    /// The limit that bounds everything: absolute for a task, renewal for a service.
    fn outer(&self) -> Option<(LifetimeLimit, u64)> {
        match self.class {
            SandboxClass::Task => self
                .absolute_seconds
                .map(|value| (LifetimeLimit::Absolute, value)),
            SandboxClass::Service => self
                .service_renewal_seconds
                .map(|value| (LifetimeLimit::ServiceRenewal, value)),
        }
    }

    pub fn class(&self) -> SandboxClass {
        self.class
    }

    pub fn per_call_seconds(&self) -> u64 {
        self.per_call_seconds
    }

    pub fn task_seconds(&self) -> Option<u64> {
        self.task_seconds
    }

    pub fn idle_seconds(&self) -> Option<u64> {
        self.idle_seconds
    }

    pub fn absolute_seconds(&self) -> Option<u64> {
        self.absolute_seconds
    }

    pub fn service_renewal_seconds(&self) -> Option<u64> {
        self.service_renewal_seconds
    }

    /// The authority a launch gets: the absolute limit of a task sandbox, the renewal
    /// limit of a service sandbox. Coordination never renews authority, so a service
    /// renews by relaunching under §5.5's volume rules.
    pub fn authority_seconds(&self) -> u64 {
        self.outer().map_or(0, |(_, value)| value)
    }

    /// Refuses a launch plan whose authority outlives the policy.
    pub fn check_launch(&self, plan: &LaunchPlan) -> Result<(), LifetimeProblem> {
        let plan_seconds = plan.authority_lifetime.as_secs()
            + u64::from(plan.authority_lifetime.subsec_nanos() > 0);
        if plan.authority_lifetime.is_zero() {
            return Err(LifetimeProblem::Zero {
                limit: self
                    .outer()
                    .map_or(LifetimeLimit::Absolute, |(limit, _)| limit),
            });
        }
        if plan_seconds > self.authority_seconds() {
            return Err(LifetimeProblem::AuthorityTooLong {
                plan_seconds,
                policy_seconds: self.authority_seconds(),
            });
        }
        Ok(())
    }

    /// Terms of one call: it lasts the per-call limit and cannot be renewed past it.
    pub fn call_terms(&self) -> LeaseTerms {
        LeaseTerms {
            term: seconds(self.per_call_seconds),
            max_lifetime: seconds(self.per_call_seconds),
            cancel_within: seconds(self.cancel_within_seconds),
        }
    }

    /// Terms of the task lease of a task sandbox.
    pub fn task_terms(&self) -> Option<LeaseTerms> {
        self.task_seconds.map(|task| LeaseTerms {
            term: seconds(task),
            max_lifetime: seconds(task),
            cancel_within: seconds(self.cancel_within_seconds),
        })
    }

    /// Terms of the idle lease: each renewal extends it by the idle limit, never past the
    /// absolute or renewal limit.
    pub fn idle_terms(&self) -> Option<LeaseTerms> {
        let idle = self.idle_seconds?;
        Some(LeaseTerms {
            term: seconds(idle),
            max_lifetime: seconds(self.authority_seconds()),
            cancel_within: seconds(self.cancel_within_seconds),
        })
    }
}

/// Something that happened in or around a sandbox, as the host sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "activity", rename_all = "snake_case")]
pub enum Activity {
    /// A host-issued call running under this call lease.
    HostCall {
        lease: LeaseId,
    },
    /// Input the host observed in the sandbox's own window or terminal.
    UserInteraction,
    InboundNetwork {
        bytes: u64,
    },
    OutboundNetwork {
        bytes: u64,
    },
    /// Output streaming from the guest, such as logs or a model's tokens.
    OutputStream {
        bytes: u64,
    },
    /// A liveness report from inside the guest.
    GuestHeartbeat,
}

/// Why an activity did not renew the idle lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IgnoredActivity {
    /// Arbitrary network traffic never keeps an idle VM alive (line 2123).
    NetworkTraffic,
    /// A busy stream is not activity (VM-P18).
    OutputStream,
    /// A guest report is not a host observation.
    GuestReport,
}

/// What an activity did to the idle lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum KeepAliveDecision {
    Renewed { expires_at: MonotonicTime },
    Ignored { reason: IgnoredActivity },
}

/// Why a lifetime operation was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum LifetimeRefusal {
    /// The owning host's supervisor refused readiness, lifetime, lockdown or
    /// delegation scope. This is distinct from the coordinator's lease check.
    HostPolicy { detail: String },
    /// The coordinator refused the lease, among others for a clock reading below its
    /// high-water mark ([`LeaseRefusal::ClockWentBack`]) or a lease presented under
    /// another clock session ([`LeaseRefusal::OtherClock`]) (§6.2).
    Lease { refusal: LeaseRefusal },
    /// The policy has no idle limit (a service sandbox by default).
    NoIdleLimit,
    /// The call lease belongs to another sandbox or is not a call.
    ForeignCall { lease: LeaseId },
    /// The lease was seen refused or expired before; it is never honoured again.
    Ended { lease: LeaseId },
}

impl fmt::Display for LifetimeRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HostPolicy { detail } => write!(f, "host authority refused: {detail}"),
            Self::Lease { refusal } => write!(f, "{refusal}"),
            Self::NoIdleLimit => f.write_str("the policy has no idle limit"),
            Self::ForeignCall { lease } => {
                write!(f, "lease {lease} is not a call of this sandbox")
            }
            Self::Ended { lease } => write!(f, "lease {lease} already ended"),
        }
    }
}

impl std::error::Error for LifetimeRefusal {}

impl From<LeaseRefusal> for LifetimeRefusal {
    fn from(refusal: LeaseRefusal) -> Self {
        Self::Lease { refusal }
    }
}

/// The idle lease of one sandbox, renewed only by host-observed activity (§6.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdleKeepAlive {
    execution: ExecutionId,
    lease: LeaseId,
}

impl IdleKeepAlive {
    /// Issues the idle lease under `execution`'s current authority.
    pub fn start<C: Clock, P: CapacityPort>(
        coordinator: &mut Coordinator<C, P>,
        execution: &ExecutionId,
        operation: OperationId,
        policy: &LifetimePolicy,
    ) -> Result<Self, LifetimeRefusal> {
        let terms = policy.idle_terms().ok_or(LifetimeRefusal::NoIdleLimit)?;
        let lease =
            coordinator.start_child_work(execution, operation, LeaseKind::Service, terms)?;
        Ok(Self {
            execution: execution.clone(),
            lease: lease.id(),
        })
    }

    pub fn lease(&self) -> LeaseId {
        self.lease
    }

    /// Renews the idle lease for a host call or user interaction; ignores network
    /// traffic, output streams and guest heartbeats.
    pub fn observe<C: Clock, P: CapacityPort>(
        &self,
        coordinator: &mut Coordinator<C, P>,
        activity: Activity,
    ) -> Result<KeepAliveDecision, LifetimeRefusal> {
        match activity {
            Activity::InboundNetwork { .. } | Activity::OutboundNetwork { .. } => {
                return Ok(KeepAliveDecision::Ignored {
                    reason: IgnoredActivity::NetworkTraffic,
                })
            }
            Activity::OutputStream { .. } => {
                return Ok(KeepAliveDecision::Ignored {
                    reason: IgnoredActivity::OutputStream,
                })
            }
            Activity::GuestHeartbeat => {
                return Ok(KeepAliveDecision::Ignored {
                    reason: IgnoredActivity::GuestReport,
                })
            }
            Activity::HostCall { lease } => {
                let call = coordinator.check_lease(lease)?;
                if call.parent() != &self.execution || call.kind() != LeaseKind::ChildWork {
                    return Err(LifetimeRefusal::ForeignCall { lease });
                }
            }
            Activity::UserInteraction => {}
        }
        let renewed = coordinator.renew_lease(self.lease)?;
        Ok(KeepAliveDecision::Renewed {
            expires_at: renewed.expires_at(),
        })
    }
}

/// What an [`ExpiryGuard`] persists (§6.2: persist enough state to prevent clock rollback
/// or snapshot restore from reviving expired rights): the clock session it presents
/// leases with and the leases it saw refused. The clock high-water mark is the
/// coordinator's ([`Coordinator::clock_high_water`]); the guard keeps none of its own.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardState {
    pub session: ClockSession,
    pub ended: BTreeSet<LeaseId>,
}

/// Checks leases through [`Coordinator::check_presented_lease`] and makes every refusal
/// final (§6.2). The coordinator refuses a clock reading below its own high-water mark
/// ([`LeaseRefusal::ClockWentBack`]) and a lease issued on another clock session
/// ([`LeaseRefusal::OtherClock`]); it honours the lease again once the clock passes the
/// mark, but the guard never does, nor after a restart.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpiryGuard {
    state: GuardState,
}

impl ExpiryGuard {
    /// A guard presenting leases with `session`, the clock session of the coordinator
    /// that issues them.
    pub fn new(session: ClockSession) -> Self {
        Self {
            state: GuardState {
                session,
                ended: BTreeSet::new(),
            },
        }
    }

    /// Restores a persisted guard that now presents leases with `session` (§6.2: snapshot
    /// restore or a restart never revives expired rights). The ended leases stay ended on
    /// any session; a lease issued on an earlier session is refused by the coordinator's
    /// session check.
    pub fn restore(state: GuardState, session: ClockSession) -> Self {
        Self {
            state: GuardState {
                session,
                ended: state.ended,
            },
        }
    }

    pub fn state(&self) -> &GuardState {
        &self.state
    }

    /// Whether `lease` is honoured now. A lease the guard saw refused is refused again
    /// without asking the coordinator; any other lease is checked by the coordinator,
    /// presented with the guard's session, and any refusal ends it for good (§6.2).
    pub fn check<C: Clock, P: CapacityPort>(
        &mut self,
        coordinator: &Coordinator<C, P>,
        lease: LeaseId,
    ) -> Result<Lease, LifetimeRefusal> {
        if self.state.ended.contains(&lease) {
            // The lease is not checked again, but the clock is still read, so the reading
            // raises the coordinator's high-water mark as a check would.
            let _ = coordinator.now();
            return Err(LifetimeRefusal::Ended { lease });
        }
        coordinator
            .check_presented_lease(lease, self.state.session)
            .map_err(|refusal| {
                self.state.ended.insert(lease);
                LifetimeRefusal::Lease { refusal }
            })
    }
}

/// The explicit clock-skew policy for remote expiry (§6.2 line 2125; VM-P40).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClockSkewPolicy {
    /// The largest accepted difference between the local and remote wall clocks; the
    /// remote expiry is also treated as this much earlier.
    pub max_skew_seconds: u64,
    /// The longest remote right accepted, so no delegated authority is immortal.
    pub max_remote_lifetime_seconds: u64,
}

/// A right's expiry as a remote authority states it, all on the remote clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteExpiry {
    pub right: Digest,
    pub issued_unix_seconds: i64,
    pub expires_unix_seconds: i64,
    /// The remote clock when it answered.
    pub remote_now_unix_seconds: i64,
}

/// When the local host asked and heard back, on its monotonic clock, and its wall clock
/// on receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteObservation {
    pub sent_at: MonotonicTime,
    pub received_at: MonotonicTime,
    pub local_unix_seconds: i64,
}

/// Why a remote right was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum SkewRefusal {
    /// The right was seen expired before; it never revives.
    Ended {
        right: Digest,
    },
    /// The local wall clock reads earlier than a reading already persisted.
    LocalClockRollback {
        local_unix_seconds: i64,
        high_water_unix_seconds: i64,
    },
    /// The reply arrived before the request was sent.
    InvalidObservation,
    /// The remote times contradict each other.
    InconsistentRemote,
    LifetimeExceedsPolicy {
        lifetime_seconds: u64,
        max_seconds: u64,
    },
    SkewExceeded {
        observed_seconds: u64,
        allowed_seconds: u64,
    },
    Expired {
        right: Digest,
    },
    /// The local deadline was computed on another clock session.
    OtherSession,
    /// The sandbox booted again, such as from a snapshot, since the right was localized.
    RestoredBoot {
        bound: SandboxBootGeneration,
        current: SandboxBootGeneration,
    },
}

impl fmt::Display for SkewRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ended { right } => write!(f, "right {right} already ended"),
            Self::LocalClockRollback {
                local_unix_seconds,
                high_water_unix_seconds,
            } => write!(
                f,
                "the local clock reads {local_unix_seconds}, before {high_water_unix_seconds}"
            ),
            Self::InvalidObservation => f.write_str("the reply arrived before the request"),
            Self::InconsistentRemote => f.write_str("the remote times contradict each other"),
            Self::LifetimeExceedsPolicy {
                lifetime_seconds,
                max_seconds,
            } => write!(
                f,
                "the right lasts {lifetime_seconds} s; at most {max_seconds} s"
            ),
            Self::SkewExceeded {
                observed_seconds,
                allowed_seconds,
            } => write!(
                f,
                "the clocks differ by {observed_seconds} s; at most {allowed_seconds} s"
            ),
            Self::Expired { right } => write!(f, "right {right} expired"),
            Self::OtherSession => f.write_str("the deadline is on another clock session"),
            Self::RestoredBoot { bound, current } => {
                write!(
                    f,
                    "the right is bound to boot {bound}, the sandbox is at {current}"
                )
            }
        }
    }
}

impl std::error::Error for SkewRefusal {}

/// The persisted wall-clock high-water mark and the remote rights seen expired.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WallClockGuard {
    pub high_water_unix_seconds: i64,
    pub ended: BTreeSet<Digest>,
}

impl WallClockGuard {
    fn observe(&mut self, local_unix_seconds: i64) -> Result<(), SkewRefusal> {
        if local_unix_seconds < self.high_water_unix_seconds {
            return Err(SkewRefusal::LocalClockRollback {
                local_unix_seconds,
                high_water_unix_seconds: self.high_water_unix_seconds,
            });
        }
        self.high_water_unix_seconds = local_unix_seconds;
        Ok(())
    }

    fn end(&mut self, right: Digest) -> SkewRefusal {
        self.ended.insert(right);
        SkewRefusal::Expired { right }
    }
}

/// A remote right's deadline on the local monotonic clock, bound to the clock session
/// and the sandbox boot it was computed for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalExpiry {
    pub right: Digest,
    pub session: ClockSession,
    pub boot: SandboxBootGeneration,
    pub deadline: MonotonicTime,
}

impl LocalExpiry {
    /// Whether the right still holds at `now`. Once seen expired it never revives.
    pub fn check(
        &self,
        now: MonotonicTime,
        session: ClockSession,
        boot: SandboxBootGeneration,
        guard: &mut WallClockGuard,
    ) -> Result<(), SkewRefusal> {
        if guard.ended.contains(&self.right) {
            return Err(SkewRefusal::Ended { right: self.right });
        }
        if session != self.session {
            return Err(SkewRefusal::OtherSession);
        }
        if boot != self.boot {
            return Err(SkewRefusal::RestoredBoot {
                bound: self.boot,
                current: boot,
            });
        }
        if now >= self.deadline {
            return Err(guard.end(self.right));
        }
        Ok(())
    }
}

impl ClockSkewPolicy {
    /// Turns `remote` into a local deadline. The remaining time is measured on the remote
    /// clock alone (expiry minus its own now), less the skew allowance, and counted from
    /// when the request was sent, so latency only shortens it.
    pub fn localize(
        &self,
        remote: &RemoteExpiry,
        observed: &RemoteObservation,
        session: ClockSession,
        boot: SandboxBootGeneration,
        guard: &mut WallClockGuard,
    ) -> Result<LocalExpiry, SkewRefusal> {
        if guard.ended.contains(&remote.right) {
            return Err(SkewRefusal::Ended {
                right: remote.right,
            });
        }
        guard.observe(observed.local_unix_seconds)?;
        let round_trip = observed
            .received_at
            .checked_duration_since(observed.sent_at)
            .ok_or(SkewRefusal::InvalidObservation)?;
        if remote.issued_unix_seconds > remote.remote_now_unix_seconds
            || remote.expires_unix_seconds <= remote.issued_unix_seconds
        {
            return Err(SkewRefusal::InconsistentRemote);
        }
        let lifetime_seconds = remote
            .expires_unix_seconds
            .abs_diff(remote.issued_unix_seconds);
        if lifetime_seconds > self.max_remote_lifetime_seconds {
            return Err(SkewRefusal::LifetimeExceedsPolicy {
                lifetime_seconds,
                max_seconds: self.max_remote_lifetime_seconds,
            });
        }
        let round_trip_seconds = round_trip.as_secs() + u64::from(round_trip.subsec_nanos() > 0);
        let allowed_seconds = self.max_skew_seconds.saturating_add(round_trip_seconds);
        let observed_seconds = observed
            .local_unix_seconds
            .abs_diff(remote.remote_now_unix_seconds);
        if observed_seconds > allowed_seconds {
            return Err(SkewRefusal::SkewExceeded {
                observed_seconds,
                allowed_seconds,
            });
        }
        let remaining_seconds = if remote.expires_unix_seconds > remote.remote_now_unix_seconds {
            remote
                .expires_unix_seconds
                .abs_diff(remote.remote_now_unix_seconds)
        } else {
            0
        };
        if remaining_seconds <= self.max_skew_seconds {
            return Err(guard.end(remote.right));
        }
        let usable_seconds = remaining_seconds - self.max_skew_seconds;
        Ok(LocalExpiry {
            right: remote.right,
            session,
            boot,
            deadline: observed.sent_at.saturating_add(seconds(usable_seconds)),
        })
    }
}
