//! Timeouts and leases (VM part §6.2 lines 2298–2306; §2.5 lines 1997–2002; VM-W25 line
//! 2456; VM-D7 line 3204; VM-D12 line 3207).
//!
//! Five limits: per call and per task, which bound each piece of child work and go into
//! the CORE-04 lease terms; and idle, absolute and service renewal, which bound the
//! sandbox itself. The VM-D12 starting values are documented defaults a caller may lower
//! and never raise, and the record shows which applies. Only typed activity keeps an idle
//! sandbox alive; arbitrary traffic does not. Times are points on the shared monotonic
//! clock; a remote enforcement point gets an explicit skew policy; and the persisted lease
//! state keeps an expiry durable, so a clock rollback or a restored snapshot of this state
//! cannot revive it.

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::foundation::coordination::{LeaseTerms, TermsProblem};
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::MonotonicTime;

/// The VM-D12 starting value of the idle limit.
pub const DEFAULT_IDLE: Duration = Duration::from_secs(12 * 3600);
/// The VM-D12 starting value of a task sandbox's absolute limit.
pub const DEFAULT_TASK_ABSOLUTE: Duration = Duration::from_secs(24 * 3600);
/// The VM-D12 starting value of a service sandbox's renewal period.
pub const DEFAULT_SERVICE_RENEWAL: Duration = Duration::from_secs(7 * 24 * 3600);

/// The class of a sandbox, which decides its limits and what happens when the engine dies
/// (VM-D7) or a violation is found (VM-D10).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxClass {
    /// Ends with the engine; bounded by idle and absolute limits.
    Task,
    /// Continues under supervisor leases; bounded by idle and service renewal.
    Service,
}

impl fmt::Display for SandboxClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Task => "task sandbox",
            Self::Service => "service sandbox",
        })
    }
}

/// The five limits of §6.2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitKind {
    PerCall,
    Task,
    Idle,
    Absolute,
    ServiceRenewal,
}

impl fmt::Display for LimitKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PerCall => "per-call limit",
            Self::Task => "task limit",
            Self::Idle => "idle limit",
            Self::Absolute => "absolute limit",
            Self::ServiceRenewal => "service renewal period",
        })
    }
}

/// Where a limit's value came from, shown in the record (VM-D12).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitOrigin {
    DocumentedDefault,
    LoweredByCaller,
    /// The local owner selected no idle timeout; stop/revoke and engine supervision remain.
    DisabledByOwner,
}

/// One limit and its origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limit {
    pub duration: Duration,
    pub origin: LimitOrigin,
}

impl Limit {
    const fn default_of(duration: Duration) -> Self {
        Self {
            duration,
            origin: LimitOrigin::DocumentedDefault,
        }
    }
}

/// Why a limit was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum LimitRefusal {
    /// A caller may lower a documented default, never raise it (VM-D12: adjusted from
    /// measurement, not by a request).
    CannotRaise {
        kind: LimitKind,
        default: Duration,
        requested: Duration,
    },
    Zero {
        kind: LimitKind,
    },
    /// The class has no such limit.
    NotApplicable {
        kind: LimitKind,
        class: SandboxClass,
    },
}

crate::foundation::strict_serde::strict_tag!(LimitRefusal, "refusal");

impl fmt::Display for LimitRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CannotRaise {
                kind,
                default,
                requested,
            } => write!(
                f,
                "the {kind} may be lowered below its default of {} s, not raised to {} s",
                default.as_secs(),
                requested.as_secs()
            ),
            Self::Zero { kind } => write!(f, "the {kind} must be longer than zero"),
            Self::NotApplicable { kind, class } => {
                write!(f, "a {class} has no {kind}")
            }
        }
    }
}

impl std::error::Error for LimitRefusal {}

/// The sandbox-level limits of one sandbox: idle for both classes, absolute for a task
/// sandbox, renewal for a service sandbox (VM-D12).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseLimits {
    pub class: SandboxClass,
    pub idle: Limit,
    pub absolute: Option<Limit>,
    pub service_renewal: Option<Limit>,
}

impl LeaseLimits {
    /// Local owner-managed workloads run until stopped. Duration::MAX is the
    /// supervisor's non-expiring idle sentinel, not a replacement wall-clock cap.
    pub fn without_timeout(mut self, kind: LimitKind) -> Result<Self, LimitRefusal> {
        match kind {
            LimitKind::Idle => self.idle = Limit { duration: Duration::MAX, origin: LimitOrigin::DisabledByOwner },
            LimitKind::Absolute if self.class == SandboxClass::Task => self.absolute = None,
            _ => return Err(LimitRefusal::NotApplicable { kind, class: self.class }),
        }
        Ok(self)
    }
    /// The documented starting values for `class` (VM-D12).
    pub const fn defaults(class: SandboxClass) -> Self {
        match class {
            SandboxClass::Task => Self {
                class,
                idle: Limit::default_of(DEFAULT_IDLE),
                absolute: Some(Limit::default_of(DEFAULT_TASK_ABSOLUTE)),
                service_renewal: None,
            },
            SandboxClass::Service => Self {
                class,
                idle: Limit::default_of(DEFAULT_IDLE),
                absolute: None,
                service_renewal: Some(Limit::default_of(DEFAULT_SERVICE_RENEWAL)),
            },
        }
    }

    /// Lowers one limit. Raising it, zeroing it or naming a limit the class lacks is
    /// refused.
    pub fn lower(mut self, kind: LimitKind, duration: Duration) -> Result<Self, LimitRefusal> {
        if duration.is_zero() {
            return Err(LimitRefusal::Zero { kind });
        }
        let class = self.class;
        let slot = match kind {
            LimitKind::Idle => &mut self.idle,
            LimitKind::Absolute => self
                .absolute
                .as_mut()
                .ok_or(LimitRefusal::NotApplicable { kind, class })?,
            LimitKind::ServiceRenewal => self
                .service_renewal
                .as_mut()
                .ok_or(LimitRefusal::NotApplicable { kind, class })?,
            LimitKind::PerCall | LimitKind::Task => {
                return Err(LimitRefusal::NotApplicable { kind, class })
            }
        };
        let default = match kind {
            LimitKind::Idle => DEFAULT_IDLE,
            LimitKind::Absolute => DEFAULT_TASK_ABSOLUTE,
            _ => DEFAULT_SERVICE_RENEWAL,
        };
        if duration > default {
            return Err(LimitRefusal::CannotRaise {
                kind,
                default,
                requested: duration,
            });
        }
        *slot = Limit {
            duration,
            origin: LimitOrigin::LoweredByCaller,
        };
        Ok(self)
    }

    /// How long authority granted at launch may last: the absolute limit of a task
    /// sandbox, the renewal period of a service sandbox. Authority never outlives it.
    pub fn authority_lifetime(&self) -> Duration {
        match (self.absolute, self.service_renewal) {
            (Some(limit), _) | (None, Some(limit)) => limit.duration,
            (None, None) => Duration::MAX,
        }
    }
}

/// The per-call and task limits of one piece of child work (§6.2: "interactive work may
/// have a different call timeout, but still has bounded authority").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallTerms {
    pub per_call: Duration,
    pub task: Duration,
}

/// The CORE-04 lease terms of child work: each call is one term, the task is the maximum
/// lifetime, and `cancel_within` is the declared bound the holder stops within.
pub fn child_lease_terms(
    call: CallTerms,
    cancel_within: Duration,
) -> Result<LeaseTerms, TermsProblem> {
    let terms = LeaseTerms {
        term: call.per_call,
        max_lifetime: call.task,
        cancel_within,
    };
    terms.check()?;
    Ok(terms)
}

/// Something that happened in or around a sandbox, and whether it counts as activity
/// for the idle limit (§6.2: "arbitrary network traffic must not keep an otherwise idle
/// VM alive forever").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityKind {
    /// A command the engine ran in the guest.
    Command,
    /// A tool result returned to the engine.
    ToolResult,
    /// Input from the user.
    UserInput,
    /// A request a published service completed under its typed policy.
    AuthorizedRequestServed,
    /// Packets, probes or connections of any kind; never activity.
    NetworkTraffic,
    /// A keep-alive from the guest; never activity.
    Heartbeat,
    /// A GUI attached to the sandbox; never activity, and its closure ends nothing.
    GuiPresence,
}

impl ActivityKind {
    pub const fn counts_as_activity(self) -> bool {
        matches!(
            self,
            Self::Command | Self::ToolResult | Self::UserInput | Self::AuthorizedRequestServed
        )
    }
}

/// Why an activity report changed nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum ActivityRefusal {
    /// The kind is not activity; the idle clock keeps running.
    NotActivity { kind: ActivityKind },
    /// The lease already expired; nothing revives it.
    Expired { expiry: Expiry },
}

crate::foundation::strict_serde::strict_tag!(ActivityRefusal, "refusal");

impl fmt::Display for ActivityRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotActivity { kind } => {
                write!(
                    f,
                    "{kind:?} is not activity and does not reset the idle limit"
                )
            }
            Self::Expired { expiry } => write!(f, "the lease expired: {expiry}"),
        }
    }
}

/// A limit that ran out, recorded durably.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expiry {
    pub kind: LimitKind,
    pub at: MonotonicTime,
}

impl fmt::Display for Expiry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the {} ran out at {} ns", self.kind, self.at.as_nanos())
    }
}

/// What is left of each limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Remaining {
    pub idle: Duration,
    pub absolute: Option<Duration>,
    pub service_renewal: Option<Duration>,
}

/// Why a service renewal was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum RenewalRefusal {
    NotAService { class: SandboxClass },
    Expired { expiry: Expiry },
}

crate::foundation::strict_serde::strict_tag!(RenewalRefusal, "refusal");

impl fmt::Display for RenewalRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAService { class } => write!(f, "a {class} has no service renewal"),
            Self::Expired { expiry } => write!(f, "the lease expired: {expiry}"),
        }
    }
}

/// Why a persisted lease was not restored as live.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum LeaseRestoreRefusal {
    /// The lease is from another clock session, such as before a restart; its times
    /// cannot be compared, and no pre-crash lease is revived.
    OtherClockSession,
    /// The clock reads earlier than the persisted high-water mark.
    ClockRolledBack {
        reading: MonotonicTime,
        high_water: MonotonicTime,
    },
    /// The persisted state already records the expiry; it stays expired.
    AlreadyExpired { expiry: Expiry },
}

crate::foundation::strict_serde::strict_tag!(LeaseRestoreRefusal, "refusal");

impl fmt::Display for LeaseRestoreRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OtherClockSession => {
                f.write_str("the lease is from another clock session and is not revived")
            }
            Self::ClockRolledBack {
                reading,
                high_water,
            } => write!(
                f,
                "the clock reads {} ns, before the persisted high-water mark of {} ns",
                reading.as_nanos(),
                high_water.as_nanos()
            ),
            Self::AlreadyExpired { expiry } => write!(f, "{expiry}"),
        }
    }
}

/// The lease of one sandbox: when it started, when it was last active, when it was last
/// renewed, the latest clock reading it saw, and the expiry once one limit ran out. It is
/// persisted; an expiry is durable, and a reading below the high-water mark is a rollback
/// (§6.2 "persist enough state to prevent clock rollback or snapshot restore from
/// reviving expired rights").
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxLease {
    limits: LeaseLimits,
    clock: ClockSession,
    started_at: MonotonicTime,
    last_activity_at: MonotonicTime,
    renewed_at: MonotonicTime,
    high_water: MonotonicTime,
    expired: Option<Expiry>,
}

impl SandboxLease {
    /// A lease started at `now` on `clock`; its deadlines are bound to this moment, never
    /// to an earlier snapshot.
    pub fn new(limits: LeaseLimits, clock: ClockSession, now: MonotonicTime) -> Self {
        Self {
            limits,
            clock,
            started_at: now,
            last_activity_at: now,
            renewed_at: now,
            high_water: now,
            expired: None,
        }
    }

    pub fn limits(&self) -> &LeaseLimits {
        &self.limits
    }

    pub fn class(&self) -> SandboxClass {
        self.limits.class
    }

    pub fn clock(&self) -> ClockSession {
        self.clock
    }

    pub fn started_at(&self) -> MonotonicTime {
        self.started_at
    }

    pub fn last_activity_at(&self) -> MonotonicTime {
        self.last_activity_at
    }

    pub fn renewed_at(&self) -> MonotonicTime {
        self.renewed_at
    }

    /// The latest reading the lease saw.
    pub fn high_water(&self) -> MonotonicTime {
        self.high_water
    }

    /// The expiry, once a limit ran out.
    pub fn expired(&self) -> Option<Expiry> {
        self.expired
    }

    fn note(&mut self, now: MonotonicTime) -> Result<(), LeaseRestoreRefusal> {
        if now < self.high_water {
            return Err(LeaseRestoreRefusal::ClockRolledBack {
                reading: now,
                high_water: self.high_water,
            });
        }
        self.high_water = now;
        Ok(())
    }

    /// What is left at `now`, or the expiry. Checking records the first limit that ran out
    /// durably; after that the lease stays expired whatever the clock says. A reading
    /// earlier than the last one is a rollback and is refused rather than honoured.
    pub fn check(&mut self, now: MonotonicTime) -> Result<Remaining, LeaseRestoreRefusal> {
        if let Some(expiry) = self.expired {
            return Err(LeaseRestoreRefusal::AlreadyExpired { expiry });
        }
        self.note(now)?;
        let remaining = self.remaining_at(now);
        let idle_out = remaining.idle.is_zero();
        let absolute_out = remaining.absolute.is_some_and(|left| left.is_zero());
        let renewal_out = remaining.service_renewal.is_some_and(|left| left.is_zero());
        let kind = if absolute_out {
            Some(LimitKind::Absolute)
        } else if renewal_out {
            Some(LimitKind::ServiceRenewal)
        } else if idle_out {
            Some(LimitKind::Idle)
        } else {
            None
        };
        match kind {
            Some(kind) => {
                let expiry = Expiry { kind, at: now };
                self.expired = Some(expiry);
                Err(LeaseRestoreRefusal::AlreadyExpired { expiry })
            }
            None => Ok(remaining),
        }
    }

    fn remaining_at(&self, now: MonotonicTime) -> Remaining {
        let left = |since: MonotonicTime, limit: Duration| {
            limit.saturating_sub(now.saturating_duration_since(since))
        };
        Remaining {
            idle: left(self.last_activity_at, self.limits.idle.duration),
            absolute: self
                .limits
                .absolute
                .map(|limit| left(self.started_at, limit.duration)),
            service_renewal: self
                .limits
                .service_renewal
                .map(|limit| left(self.renewed_at, limit.duration)),
        }
    }

    /// Records activity at `now`. Only typed activity resets the idle limit; traffic,
    /// heartbeats and a GUI do not, and an expired lease is not revived.
    pub fn activity(
        &mut self,
        kind: ActivityKind,
        now: MonotonicTime,
    ) -> Result<(), ActivityRefusal> {
        if let Some(expiry) = self.expired {
            return Err(ActivityRefusal::Expired { expiry });
        }
        if !kind.counts_as_activity() {
            return Err(ActivityRefusal::NotActivity { kind });
        }
        if let Err(LeaseRestoreRefusal::ClockRolledBack { .. }) = self.note(now) {
            // A rollback never moves the activity mark; the next check refuses it.
            return Ok(());
        }
        self.last_activity_at = now;
        Ok(())
    }

    /// Records a service renewal at `now` (§6.2 service-renewal limit). A task sandbox has
    /// none, and an expired lease is not renewed.
    pub fn renew(&mut self, now: MonotonicTime) -> Result<(), RenewalRefusal> {
        if self.limits.class != SandboxClass::Service {
            return Err(RenewalRefusal::NotAService {
                class: self.limits.class,
            });
        }
        if let Some(expiry) = self.expired {
            return Err(RenewalRefusal::Expired { expiry });
        }
        if self.note(now).is_ok() {
            self.renewed_at = now;
        }
        Ok(())
    }

    /// Restores a persisted lease into the session `clock` reading `now`. An expired lease
    /// stays expired; one from another session is not revived; a reading below the
    /// persisted high-water mark is a rollback.
    pub fn restore(
        persisted: Self,
        clock: ClockSession,
        now: MonotonicTime,
    ) -> Result<Self, LeaseRestoreRefusal> {
        if let Some(expiry) = persisted.expired {
            return Err(LeaseRestoreRefusal::AlreadyExpired { expiry });
        }
        if persisted.clock != clock {
            return Err(LeaseRestoreRefusal::OtherClockSession);
        }
        let mut lease = persisted;
        lease.note(now)?;
        Ok(lease)
    }
}

/// The explicit clock-skew policy for remote expiry (§6.2; §2.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkewPolicy {
    /// How far a remote clock may differ from the issuer's.
    pub allowed_clock_uncertainty: Duration,
}

/// What the remote enforcement point does (§2.5: "the bound applies only if the remote
/// enforcement point checks leases and cannot mint renewals").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteEnforcement {
    pub checks_leases: bool,
    pub can_mint_renewals: bool,
}

/// Why the §2.5 bound cannot be claimed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum BoundNotApplicable {
    RemoteDoesNotCheckLeases,
    RemoteCanMintRenewals,
}

crate::foundation::strict_serde::strict_tag!(BoundNotApplicable, "reason");

impl fmt::Display for BoundNotApplicable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RemoteDoesNotCheckLeases => {
                "the remote enforcement point does not check leases, so no bound holds"
            }
            Self::RemoteCanMintRenewals => {
                "the remote enforcement point can mint renewals, so no bound holds"
            }
        })
    }
}

impl std::error::Error for BoundNotApplicable {}

/// The §2.5 bound: `remaining_authorized_time <= lease_TTL + allowed_clock_uncertainty`,
/// evaluated at issue.
pub fn authorized_time_bound(lease_ttl: Duration, skew: &SkewPolicy) -> Duration {
    lease_ttl.saturating_add(skew.allowed_clock_uncertainty)
}

/// The most authorized time that can remain at a remote enforcement point `elapsed` after
/// issue, under the §2.5 bound. It is always within [`authorized_time_bound`], and it is
/// claimed only for a remote point that checks leases and cannot mint renewals.
pub fn remaining_authorized_time(
    lease_ttl: Duration,
    elapsed: Duration,
    skew: &SkewPolicy,
    enforcement: &RemoteEnforcement,
) -> Result<Duration, BoundNotApplicable> {
    if !enforcement.checks_leases {
        return Err(BoundNotApplicable::RemoteDoesNotCheckLeases);
    }
    if enforcement.can_mint_renewals {
        return Err(BoundNotApplicable::RemoteCanMintRenewals);
    }
    Ok(authorized_time_bound(lease_ttl, skew).saturating_sub(elapsed))
}

/// The second §2.5 bound: `remaining_effects <= outstanding_reserved_effects +
/// valid_lease_budget`.
pub fn remaining_effects_bound(outstanding_reserved_effects: u64, valid_lease_budget: u64) -> u64 {
    outstanding_reserved_effects.saturating_add(valid_lease_budget)
}

/// What a remote point may still do after a disconnection (§2.5), checked against the
/// effects bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectExposure {
    pub outstanding_reserved_effects: u64,
    pub valid_lease_budget: u64,
}

impl EffectExposure {
    /// Whether `remaining_effects` stays within the bound.
    pub fn admits(&self, remaining_effects: u64) -> bool {
        remaining_effects
            <= remaining_effects_bound(self.outstanding_reserved_effects, self.valid_lease_budget)
    }
}

/// A lease as a remote enforcement point holds it: issued on the remote's own clock, with
/// a TTL. The remote honours it until `issued_at + ttl` on that clock; the issuer's
/// accounting adds the skew policy's uncertainty.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteLease {
    pub issued_at_remote: MonotonicTime,
    pub ttl: Duration,
}

impl RemoteLease {
    /// Whether the remote point honours the lease at its own reading `remote_now`.
    pub fn honoured_at(&self, remote_now: MonotonicTime) -> bool {
        remote_now < self.issued_at_remote.saturating_add(self.ttl)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: Duration = Duration::from_secs(3600);

    fn at(seconds: u64) -> MonotonicTime {
        MonotonicTime::from_nanos(seconds * 1_000_000_000)
    }

    fn session() -> ClockSession {
        ClockSession::from_uuid(uuid::Uuid::from_u128(7))
    }

    #[test]
    fn vm_d12_starting_values_are_the_documented_defaults() {
        let task = LeaseLimits::defaults(SandboxClass::Task);
        assert_eq!(task.idle.duration, Duration::from_secs(12 * 3600));
        assert_eq!(
            task.absolute.map(|limit| limit.duration),
            Some(Duration::from_secs(24 * 3600))
        );
        assert_eq!(task.service_renewal, None);
        assert_eq!(task.idle.origin, LimitOrigin::DocumentedDefault);
        let service = LeaseLimits::defaults(SandboxClass::Service);
        assert_eq!(
            service.service_renewal.map(|limit| limit.duration),
            Some(Duration::from_secs(7 * 24 * 3600))
        );
        assert_eq!(service.absolute, None);
        assert_eq!(task.authority_lifetime(), DEFAULT_TASK_ABSOLUTE);
        assert_eq!(service.authority_lifetime(), DEFAULT_SERVICE_RENEWAL);
    }

    #[test]
    fn owner_managed_workloads_have_no_idle_or_absolute_expiry() {
        let limits = LeaseLimits::defaults(SandboxClass::Task)
            .without_timeout(LimitKind::Idle).unwrap()
            .without_timeout(LimitKind::Absolute).unwrap();
        assert_eq!(limits.absolute, None);
        assert_eq!(limits.idle.origin, LimitOrigin::DisabledByOwner);
        assert_eq!(limits.authority_lifetime(), Duration::MAX);
        let mut lease = SandboxLease::new(limits, session(), at(0));
        for days in [1, 7, 30, 365] {
            let remaining = lease.check(at(days * 86400)).unwrap();
            assert_eq!(remaining.absolute, None);
            assert_eq!(remaining.service_renewal, None);
            assert!(!remaining.idle.is_zero());
        }
        // Opting out of the absolute timer must not remove a requested idle timer.
        let limits = LeaseLimits::defaults(SandboxClass::Task)
            .without_timeout(LimitKind::Absolute).unwrap();
        let mut lease = SandboxLease::new(limits, session(), at(0));
        assert!(lease.check(at(13 * 3600)).is_err());
    }

    #[test]
    fn a_caller_may_lower_a_default_but_never_raise_it() {
        let lowered = LeaseLimits::defaults(SandboxClass::Task)
            .lower(LimitKind::Idle, HOUR)
            .unwrap();
        assert_eq!(
            lowered.idle,
            Limit {
                duration: HOUR,
                origin: LimitOrigin::LoweredByCaller
            }
        );
        assert_eq!(
            lowered.absolute.map(|limit| limit.origin),
            Some(LimitOrigin::DocumentedDefault),
            "the record shows which limit the caller changed"
        );
        assert_eq!(
            LeaseLimits::defaults(SandboxClass::Task).lower(LimitKind::Absolute, 25 * HOUR),
            Err(LimitRefusal::CannotRaise {
                kind: LimitKind::Absolute,
                default: DEFAULT_TASK_ABSOLUTE,
                requested: 25 * HOUR
            })
        );
        assert_eq!(
            LeaseLimits::defaults(SandboxClass::Task).lower(LimitKind::Idle, Duration::ZERO),
            Err(LimitRefusal::Zero {
                kind: LimitKind::Idle
            })
        );
        assert_eq!(
            LeaseLimits::defaults(SandboxClass::Task).lower(LimitKind::ServiceRenewal, HOUR),
            Err(LimitRefusal::NotApplicable {
                kind: LimitKind::ServiceRenewal,
                class: SandboxClass::Task
            })
        );
        assert_eq!(
            LeaseLimits::defaults(SandboxClass::Service).lower(LimitKind::Absolute, HOUR),
            Err(LimitRefusal::NotApplicable {
                kind: LimitKind::Absolute,
                class: SandboxClass::Service
            })
        );
        assert!(LeaseLimits::defaults(SandboxClass::Service)
            .lower(LimitKind::ServiceRenewal, 24 * HOUR)
            .is_ok());
    }

    #[test]
    fn per_call_and_task_limits_become_lease_terms() {
        let terms = child_lease_terms(
            CallTerms {
                per_call: Duration::from_secs(30),
                task: HOUR,
            },
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(terms.term, Duration::from_secs(30));
        assert_eq!(terms.max_lifetime, HOUR);
        assert_eq!(
            child_lease_terms(
                CallTerms {
                    per_call: HOUR,
                    task: Duration::from_secs(30)
                },
                Duration::from_secs(5)
            ),
            Err(TermsProblem::LifetimeShorterThanTerm)
        );
    }

    #[test]
    fn only_typed_activity_resets_the_idle_limit() {
        let mut lease =
            SandboxLease::new(LeaseLimits::defaults(SandboxClass::Task), session(), at(0));
        for kind in [
            ActivityKind::NetworkTraffic,
            ActivityKind::Heartbeat,
            ActivityKind::GuiPresence,
        ] {
            assert_eq!(
                lease.activity(kind, at(3600)),
                Err(ActivityRefusal::NotActivity { kind })
            );
        }
        assert_eq!(lease.last_activity_at(), at(0));
        lease.activity(ActivityKind::Command, at(3600)).unwrap();
        assert_eq!(lease.last_activity_at(), at(3600));
        let remaining = lease.check(at(3600)).unwrap();
        assert_eq!(remaining.idle, DEFAULT_IDLE);
        assert_eq!(remaining.absolute, Some(DEFAULT_TASK_ABSOLUTE - HOUR));
    }

    #[test]
    fn expiry_is_durable_and_the_clock_cannot_revive_it() {
        let mut lease =
            SandboxLease::new(LeaseLimits::defaults(SandboxClass::Task), session(), at(0));
        let idle_out = at(12 * 3600);
        assert_eq!(
            lease.check(idle_out),
            Err(LeaseRestoreRefusal::AlreadyExpired {
                expiry: Expiry {
                    kind: LimitKind::Idle,
                    at: idle_out
                }
            })
        );
        assert_eq!(
            lease.activity(ActivityKind::Command, at(12 * 3600 + 1)),
            Err(ActivityRefusal::Expired {
                expiry: Expiry {
                    kind: LimitKind::Idle,
                    at: idle_out
                }
            })
        );
        let json = serde_json::to_string(&lease).unwrap();
        let persisted: SandboxLease = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            SandboxLease::restore(persisted.clone(), session(), at(1)),
            Err(LeaseRestoreRefusal::AlreadyExpired { .. })
        ));
        let mut live =
            SandboxLease::new(LeaseLimits::defaults(SandboxClass::Task), session(), at(0));
        live.check(at(100)).unwrap();
        assert_eq!(
            SandboxLease::restore(live.clone(), session(), at(50)),
            Err(LeaseRestoreRefusal::ClockRolledBack {
                reading: at(50),
                high_water: at(100)
            })
        );
        let other = ClockSession::from_uuid(uuid::Uuid::from_u128(8));
        assert_eq!(
            SandboxLease::restore(live.clone(), other, at(200)),
            Err(LeaseRestoreRefusal::OtherClockSession)
        );
        assert!(SandboxLease::restore(live.clone(), session(), at(200)).is_ok());
        assert_eq!(
            live.check(at(50)),
            Err(LeaseRestoreRefusal::ClockRolledBack {
                reading: at(50),
                high_water: at(100)
            })
        );
    }

    #[test]
    fn the_absolute_limit_ends_a_busy_task_and_renewal_bounds_a_service() {
        let mut task =
            SandboxLease::new(LeaseLimits::defaults(SandboxClass::Task), session(), at(0));
        for hour in 1..24 {
            task.activity(ActivityKind::Command, at(hour * 3600))
                .unwrap();
            task.check(at(hour * 3600)).unwrap();
        }
        task.activity(ActivityKind::Command, at(24 * 3600)).unwrap();
        assert_eq!(
            task.check(at(24 * 3600)).unwrap_err(),
            LeaseRestoreRefusal::AlreadyExpired {
                expiry: Expiry {
                    kind: LimitKind::Absolute,
                    at: at(24 * 3600)
                }
            }
        );
        assert_eq!(
            task.renew(at(24 * 3600)),
            Err(RenewalRefusal::NotAService {
                class: SandboxClass::Task
            })
        );
        let mut service = SandboxLease::new(
            LeaseLimits::defaults(SandboxClass::Service),
            session(),
            at(0),
        );
        for day in 1..=20 {
            let now = at(day * 24 * 3600);
            service
                .activity(ActivityKind::AuthorizedRequestServed, now)
                .unwrap();
            if day == 6 {
                service.renew(now).unwrap();
            }
            if day >= 13 {
                assert!(service.check(now).is_err(), "day {day}: renewal lapsed");
                break;
            }
            service.check(now).unwrap();
        }
        assert_eq!(
            service.expired().map(|expiry| expiry.kind),
            Some(LimitKind::ServiceRenewal)
        );
    }

    #[test]
    fn the_2_5_bound_holds_for_every_elapsed_time_and_only_where_it_applies() {
        let skew = SkewPolicy {
            allowed_clock_uncertainty: Duration::from_secs(30),
        };
        let ttl = Duration::from_secs(600);
        let bound = authorized_time_bound(ttl, &skew);
        assert_eq!(bound, Duration::from_secs(630));
        let remote = RemoteEnforcement {
            checks_leases: true,
            can_mint_renewals: false,
        };
        for elapsed in (0..1000).map(Duration::from_secs) {
            let remaining = remaining_authorized_time(ttl, elapsed, &skew, &remote).unwrap();
            assert!(remaining <= bound);
            assert_eq!(remaining, bound.saturating_sub(elapsed));
        }
        assert_eq!(
            remaining_authorized_time(
                ttl,
                Duration::ZERO,
                &skew,
                &RemoteEnforcement {
                    checks_leases: false,
                    can_mint_renewals: false
                }
            ),
            Err(BoundNotApplicable::RemoteDoesNotCheckLeases)
        );
        assert_eq!(
            remaining_authorized_time(
                ttl,
                Duration::ZERO,
                &skew,
                &RemoteEnforcement {
                    checks_leases: true,
                    can_mint_renewals: true
                }
            ),
            Err(BoundNotApplicable::RemoteCanMintRenewals)
        );
        let exposure = EffectExposure {
            outstanding_reserved_effects: 3,
            valid_lease_budget: 4,
        };
        assert_eq!(remaining_effects_bound(3, 4), 7);
        assert!(exposure.admits(7));
        assert!(!exposure.admits(8));
        let lease = RemoteLease {
            issued_at_remote: at(1000),
            ttl,
        };
        assert!(lease.honoured_at(at(1599)));
        assert!(!lease.honoured_at(at(1600)));
    }
}
