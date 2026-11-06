//! Run plans of BENCH-05 and BENCH-06 (S7 lines 296–297; S10 line 351; S11 lines 361,
//! 197–198 and 207; §6.6 lines 2336–2353).
//!
//! Every plan measures one clock, S8's VM provisioning clock: create initiated to the
//! first successful command inside the intended guest (line 317). Sequential, staggered
//! and burst plans differ only in how creates arrive. A plan whose peak of concurrent
//! creates reaches [`AUTHORIZED_HOST_CONCURRENCY`] needs an isolated host or provider
//! that is sized and authorized for it, and the fake substrate refuses it. A plan retries
//! refused creates only under the explicit [`RetryPolicy`] it is given (S8 line 321);
//! without one it never retries.

use std::fmt;

use serde::Serialize;

use super::retry::RetryPolicy;
use super::BenchError;
use crate::foundation::report::{ArrivalMode, BenchId, Label, LoadDescription};

/// S11 BENCH-05: "100 concurrent only when the isolated host/provider is sized and
/// authorized". A plan with this many concurrent creates or more is never run on the
/// fake substrate or on an unauthorized host.
pub const AUTHORIZED_HOST_CONCURRENCY: u32 = 100;

/// How the creates of one burst arrive (S7 line 296: sequential, staggered and burst).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ArrivalPattern {
    /// One create at a time: the next starts once the previous VM is stopped or its
    /// attempt failed.
    Sequential,
    /// A create every `interval_nanos`, whatever the earlier ones are doing.
    Staggered { interval_nanos: u64 },
    /// Every create of the burst at the same instant.
    Burst,
}

/// The per-attempt limits of a plan, on the first-command clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct AttemptLimits {
    /// The declared deadline: a first command after it is a deadline failure (S8).
    pub deadline_nanos: u64,
    /// The harness gives up this long after create initiated: a timeout (S8).
    pub timeout_nanos: u64,
    /// How long a VM stays up after its first command before the runner stops it.
    pub hold_nanos: u64,
    /// The quiet time between independent bursts, with every VM stopped (S11 line 379).
    pub burst_gap_nanos: u64,
}

impl AttemptLimits {
    fn check(&self) -> Result<(), BenchError> {
        if self.deadline_nanos == 0 {
            return Err(BenchError::InvalidParameter {
                field: "deadline_nanos",
                reason: "a deadline is declared and positive",
            });
        }
        if self.timeout_nanos < self.deadline_nanos {
            return Err(BenchError::InvalidParameter {
                field: "timeout_nanos",
                reason: "the harness waits at least until the deadline",
            });
        }
        Ok(())
    }
}

/// What a plan needs of the host it runs on (S11 lines 361 and 369).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HostRequirement {
    /// Any substrate, the fake one included.
    AnySubstrate,
    /// An isolated host or provider, sized and authorized for this many concurrent
    /// creates.
    AuthorizedSizedHost { concurrent_creates: u32 },
}

/// Where a plan is asked to run. There is no variant for the owner's active machine
/// (S11 line 361: such runs "are not commands to run on the active laptop").
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BenchHost {
    /// The fake, time-controlled substrate of this module.
    FakeTimeControlled,
    /// An authorized disposable host or provider, sized for at most
    /// `sized_for_concurrent_creates` concurrent creates.
    AuthorizedDisposable {
        authorization: Label,
        sized_for_concurrent_creates: u32,
    },
}

/// One validated run: which case, how creates arrive, how many, and their limits. Built
/// only by [`Bench05Plan`] and [`Bench06Plan`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RunSpec {
    bench: BenchId,
    variant: Label,
    arrival: ArrivalPattern,
    attempts_per_burst: u32,
    bursts: u32,
    limits: AttemptLimits,
    retries: RetryPolicy,
}

impl RunSpec {
    fn new(
        bench: BenchId,
        variant: Label,
        arrival: ArrivalPattern,
        attempts_per_burst: u32,
        bursts: u32,
        limits: AttemptLimits,
    ) -> Result<Self, BenchError> {
        if attempts_per_burst == 0 {
            return Err(BenchError::InvalidParameter {
                field: "attempts_per_burst",
                reason: "a burst has at least one create",
            });
        }
        if bursts == 0 {
            return Err(BenchError::InvalidParameter {
                field: "bursts",
                reason: "a run has at least one burst",
            });
        }
        if let ArrivalPattern::Staggered { interval_nanos: 0 } = arrival {
            return Err(BenchError::InvalidParameter {
                field: "interval_nanos",
                reason: "a staggered plan spaces its creates; a zero interval is a burst",
            });
        }
        limits.check()?;
        attempts_per_burst
            .checked_mul(bursts)
            .ok_or(BenchError::Overflow)?;
        Ok(Self {
            bench,
            variant,
            arrival,
            attempts_per_burst,
            bursts,
            limits,
            retries: RetryPolicy::off(),
        })
    }

    /// The same run under `policy`. A retrying run's variant names its retry bound, so its
    /// attempts form their own ledger, apart from the same case run without retries. The
    /// policy is set once; an off policy leaves the plan as it was.
    fn with_retries(mut self, policy: RetryPolicy) -> Result<Self, BenchError> {
        if !self.retries.is_off() {
            return Err(BenchError::InvalidParameter {
                field: "retries",
                reason: "a plan's retry policy is set once",
            });
        }
        if policy.is_off() {
            return Ok(self);
        }
        self.variant = Label::new(format!("{}-retry-{}x", self.variant, policy.max_retries()))?;
        self.retries = policy;
        Ok(self)
    }

    pub fn bench(&self) -> BenchId {
        self.bench
    }

    /// The case variant every record carries; one variant is one attempt ledger.
    pub fn variant(&self) -> &Label {
        &self.variant
    }

    pub fn arrival(&self) -> ArrivalPattern {
        self.arrival
    }

    pub fn attempts_per_burst(&self) -> u32 {
        self.attempts_per_burst
    }

    /// Independent bursts (S8 line 321; S11 line 379).
    pub fn bursts(&self) -> u32 {
        self.bursts
    }

    pub fn limits(&self) -> AttemptLimits {
        self.limits
    }

    /// The plan's retry policy; off unless one was set.
    pub fn retries(&self) -> &RetryPolicy {
        &self.retries
    }

    /// Every initial attempt of the run: the success-rate denominator (S8 line 321).
    /// Retries never add to it.
    pub fn total_attempts(&self) -> u32 {
        self.attempts_per_burst.saturating_mul(self.bursts)
    }

    /// How long one first attempt and its retries can take from its create: a timeout
    /// for each, and the policy's delay before each retry. One timeout without retries.
    fn attempt_span_nanos(&self) -> u64 {
        let retries = u64::from(self.retries.max_retries());
        self.limits
            .timeout_nanos
            .saturating_mul(retries.saturating_add(1))
            .saturating_add(self.retries.delay_nanos().saturating_mul(retries))
    }

    /// The most creates that can be in flight at once: one when sequential, the burst
    /// size for a burst, and for a staggered plan every create started within one
    /// attempt's span of another: one timeout, or with retries the span of a first
    /// attempt and all of its retries. A first attempt and its retries are never in
    /// flight together, and a sequential plan waits for a first attempt's retries before
    /// its next create.
    pub fn concurrent_creates(&self) -> u32 {
        match self.arrival {
            ArrivalPattern::Sequential => 1,
            ArrivalPattern::Burst => self.attempts_per_burst,
            ArrivalPattern::Staggered { interval_nanos } => {
                let overlapping = (self.attempt_span_nanos() / interval_nanos).saturating_add(1);
                u32::try_from(overlapping)
                    .unwrap_or(u32::MAX)
                    .min(self.attempts_per_burst)
            }
        }
    }

    /// What the plan needs of its host (S11 line 369).
    pub fn host_requirement(&self) -> HostRequirement {
        let concurrent_creates = self.concurrent_creates();
        if concurrent_creates >= AUTHORIZED_HOST_CONCURRENCY {
            HostRequirement::AuthorizedSizedHost { concurrent_creates }
        } else {
            HostRequirement::AnySubstrate
        }
    }

    /// Whether the plan may run on `host`: a plan that needs an authorized, sized host is
    /// refused on the fake substrate and on a host sized for fewer creates.
    pub fn admit(&self, host: &BenchHost) -> Result<(), BenchError> {
        match (self.host_requirement(), host) {
            (HostRequirement::AnySubstrate, _) => Ok(()),
            (
                HostRequirement::AuthorizedSizedHost { concurrent_creates },
                BenchHost::FakeTimeControlled,
            ) => Err(BenchError::NeedsAuthorizedSizedHost { concurrent_creates }),
            (
                HostRequirement::AuthorizedSizedHost { concurrent_creates },
                BenchHost::AuthorizedDisposable {
                    sized_for_concurrent_creates,
                    ..
                },
            ) => {
                if *sized_for_concurrent_creates >= concurrent_creates {
                    Ok(())
                } else {
                    Err(BenchError::HostUndersized {
                        concurrent_creates,
                        sized_for: *sized_for_concurrent_creates,
                    })
                }
            }
        }
    }

    /// The concurrent load every record of the run carries (S8 "concurrent load").
    pub fn load(&self) -> LoadDescription {
        LoadDescription {
            concurrent_requests: self.concurrent_creates(),
            arrival: match self.arrival {
                ArrivalPattern::Sequential => ArrivalMode::Sequential,
                ArrivalPattern::Staggered { interval_nanos } => {
                    ArrivalMode::Staggered { interval_nanos }
                }
                ArrivalPattern::Burst => ArrivalMode::Burst {
                    size: self.attempts_per_burst,
                },
            },
        }
    }
}

/// A BENCH-05 plan: VM creates on the first-command clock (S11 line 369; VM-W49 line
/// 2497).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Bench05Plan {
    spec: RunSpec,
}

impl Bench05Plan {
    /// `attempts` creates one after another, in each of `bursts` independent runs.
    pub fn sequential(
        attempts: u32,
        bursts: u32,
        limits: AttemptLimits,
    ) -> Result<Self, BenchError> {
        let variant = Label::new(format!("bench-05-sequential-x{attempts}"))?;
        Self::new(
            variant,
            ArrivalPattern::Sequential,
            attempts,
            bursts,
            limits,
        )
    }

    /// `attempts` creates `interval_nanos` apart, in each of `bursts` independent runs.
    pub fn staggered(
        interval_nanos: u64,
        attempts: u32,
        bursts: u32,
        limits: AttemptLimits,
    ) -> Result<Self, BenchError> {
        let variant = Label::new(format!("bench-05-staggered-{interval_nanos}ns-x{attempts}"))?;
        Self::new(
            variant,
            ArrivalPattern::Staggered { interval_nanos },
            attempts,
            bursts,
            limits,
        )
    }

    /// `size` creates at one instant, in each of `bursts` independent bursts.
    pub fn burst(size: u32, bursts: u32, limits: AttemptLimits) -> Result<Self, BenchError> {
        let variant = Label::new(format!("bench-05-burst-{size}"))?;
        Self::new(variant, ArrivalPattern::Burst, size, bursts, limits)
    }

    /// The S11 case of 100 concurrent creates. It exists as a plan so a release profile
    /// can select it, and it needs an isolated, sized and authorized host: the fake
    /// runner refuses it.
    pub fn concurrent_100(bursts: u32, limits: AttemptLimits) -> Result<Self, BenchError> {
        Self::burst(AUTHORIZED_HOST_CONCURRENCY, bursts, limits)
    }

    fn new(
        variant: Label,
        arrival: ArrivalPattern,
        attempts: u32,
        bursts: u32,
        limits: AttemptLimits,
    ) -> Result<Self, BenchError> {
        Ok(Self {
            spec: RunSpec::new(BenchId::Bench05, variant, arrival, attempts, bursts, limits)?,
        })
    }

    pub fn spec(&self) -> &RunSpec {
        &self.spec
    }

    /// The same plan with an explicit retry policy (S8 line 321): its variant names the
    /// retry bound; set once.
    pub fn with_retries(self, policy: RetryPolicy) -> Result<Self, BenchError> {
        Ok(Self {
            spec: self.spec.with_retries(policy)?,
        })
    }
}

/// The four BENCH-06 cases (S11 line 370).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Bench06Case {
    /// New executions, each launched cold.
    ColdVm,
    /// Stopped sandboxes checked out of a pool with fewer clones than checkouts.
    LimitedWarmPool,
    /// Stopped sandboxes each restored from the clean golden snapshot.
    CleanSnapshot,
    /// A pool drained by staggered checkouts and refilled on a schedule.
    PoolDepletionReplenishment,
}

impl fmt::Display for Bench06Case {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ColdVm => "cold VM",
            Self::LimitedWarmPool => "limited warm pool",
            Self::CleanSnapshot => "clean snapshot",
            Self::PoolDepletionReplenishment => "pool depletion and replenishment",
        })
    }
}

/// How a pool is refilled during a burst; every prepared clone is charged to the
/// measured path (S10 line 353).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ReplenishmentSchedule {
    pub every_nanos: u64,
    pub clones: u32,
}

/// A BENCH-06 plan (S11 line 370; S10 line 351: "VM-W27's clean snapshot path is
/// measured against cold boot and a limited warm pool").
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Bench06Plan {
    case: Bench06Case,
    spec: RunSpec,
    pool_capacity: u32,
    initial_clones: u32,
    replenishment: Option<ReplenishmentSchedule>,
}

impl Bench06Plan {
    /// `attempts` new executions launched cold, one after another.
    pub fn cold_vm(attempts: u32, bursts: u32, limits: AttemptLimits) -> Result<Self, BenchError> {
        Self::new(
            Bench06Case::ColdVm,
            Label::new("bench-06-cold-vm")?,
            ArrivalPattern::Sequential,
            attempts,
            bursts,
            limits,
            0,
            None,
        )
    }

    /// `attempts` sequential checkouts from a pool of `pool_capacity` clones, filled at
    /// the start of each burst and never refilled within it, so it runs out.
    pub fn limited_warm_pool(
        pool_capacity: u32,
        attempts: u32,
        bursts: u32,
        limits: AttemptLimits,
    ) -> Result<Self, BenchError> {
        if pool_capacity == 0 || pool_capacity >= attempts {
            return Err(BenchError::InvalidParameter {
                field: "pool_capacity",
                reason: "a limited pool holds at least one clone and fewer than its checkouts",
            });
        }
        Self::new(
            Bench06Case::LimitedWarmPool,
            Label::new(format!("bench-06-limited-warm-pool-k{pool_capacity}"))?,
            ArrivalPattern::Sequential,
            attempts,
            bursts,
            limits,
            pool_capacity,
            None,
        )
    }

    /// `attempts` sequential checkouts, each restored from the clean golden snapshot:
    /// the pool holds one clone per checkout.
    pub fn clean_snapshot(
        attempts: u32,
        bursts: u32,
        limits: AttemptLimits,
    ) -> Result<Self, BenchError> {
        Self::new(
            Bench06Case::CleanSnapshot,
            Label::new("bench-06-clean-snapshot")?,
            ArrivalPattern::Sequential,
            attempts,
            bursts,
            limits,
            attempts,
            None,
        )
    }

    /// `attempts` checkouts `interval_nanos` apart from a pool of `pool_capacity` clones,
    /// refilled by `schedule`.
    pub fn pool_depletion_replenishment(
        pool_capacity: u32,
        interval_nanos: u64,
        schedule: ReplenishmentSchedule,
        attempts: u32,
        bursts: u32,
        limits: AttemptLimits,
    ) -> Result<Self, BenchError> {
        if pool_capacity == 0 || pool_capacity >= attempts {
            return Err(BenchError::InvalidParameter {
                field: "pool_capacity",
                reason: "the pool must run out before its checkouts end",
            });
        }
        if schedule.every_nanos == 0 || schedule.clones == 0 {
            return Err(BenchError::InvalidParameter {
                field: "replenishment",
                reason: "a replenishment schedule adds clones at a positive interval",
            });
        }
        Self::new(
            Bench06Case::PoolDepletionReplenishment,
            Label::new(format!(
                "bench-06-depletion-k{pool_capacity}-r{}",
                schedule.clones
            ))?,
            ArrivalPattern::Staggered { interval_nanos },
            attempts,
            bursts,
            limits,
            pool_capacity,
            Some(schedule),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        case: Bench06Case,
        variant: Label,
        arrival: ArrivalPattern,
        attempts: u32,
        bursts: u32,
        limits: AttemptLimits,
        pool_capacity: u32,
        replenishment: Option<ReplenishmentSchedule>,
    ) -> Result<Self, BenchError> {
        let spec = RunSpec::new(BenchId::Bench06, variant, arrival, attempts, bursts, limits)?;
        // S10 line 351: no preallocated pool beyond what the measured checkouts use.
        if pool_capacity > attempts {
            return Err(BenchError::InvalidParameter {
                field: "pool_capacity",
                reason:
                    "a pool larger than its checkouts is preallocation the run does not measure",
            });
        }
        Ok(Self {
            case,
            spec,
            pool_capacity,
            initial_clones: pool_capacity,
            replenishment,
        })
    }

    pub fn case(&self) -> Bench06Case {
        self.case
    }

    pub fn spec(&self) -> &RunSpec {
        &self.spec
    }

    /// The same case with an explicit retry policy (S8 line 321): its variant names the
    /// retry bound; set once.
    pub fn with_retries(mut self, policy: RetryPolicy) -> Result<Self, BenchError> {
        self.spec = self.spec.with_retries(policy)?;
        Ok(self)
    }

    /// Clones the pool holds at most; zero for the cold VM case.
    pub fn pool_capacity(&self) -> u32 {
        self.pool_capacity
    }

    /// Clones prepared at the start of every burst.
    pub fn initial_clones(&self) -> u32 {
        self.initial_clones
    }

    pub fn replenishment(&self) -> Option<ReplenishmentSchedule> {
        self.replenishment
    }

    /// Whether the case checks stopped sandboxes out of a warm pool.
    pub fn uses_pool(&self) -> bool {
        self.case != Bench06Case::ColdVm
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MILLI: u64 = 1_000_000;

    fn limits() -> AttemptLimits {
        AttemptLimits {
            deadline_nanos: 2_000 * MILLI,
            timeout_nanos: 5_000 * MILLI,
            hold_nanos: 100 * MILLI,
            burst_gap_nanos: 1_000 * MILLI,
        }
    }

    fn authorized(sized_for: u32) -> BenchHost {
        BenchHost::AuthorizedDisposable {
            authorization: Label::new("disposable-burst-host").unwrap(),
            sized_for_concurrent_creates: sized_for,
        }
    }

    #[test]
    fn the_three_arrival_modes_declare_their_concurrent_load() {
        let sequential = Bench05Plan::sequential(20, 3, limits()).unwrap();
        assert_eq!(sequential.spec().concurrent_creates(), 1);
        assert_eq!(sequential.spec().load().arrival, ArrivalMode::Sequential);
        assert_eq!(sequential.spec().total_attempts(), 60);
        // Creates 1 s apart under a 5 s timeout overlap six at a time.
        let staggered = Bench05Plan::staggered(1_000 * MILLI, 20, 3, limits()).unwrap();
        assert_eq!(staggered.spec().concurrent_creates(), 6);
        assert_eq!(
            staggered.spec().load().arrival,
            ArrivalMode::Staggered {
                interval_nanos: 1_000 * MILLI
            }
        );
        let burst = Bench05Plan::burst(8, 3, limits()).unwrap();
        assert_eq!(burst.spec().load().concurrent_requests, 8);
        assert_eq!(burst.spec().load().arrival, ArrivalMode::Burst { size: 8 });
        for plan in [&sequential, &staggered, &burst] {
            assert_eq!(plan.spec().bench(), BenchId::Bench05);
            assert_eq!(
                plan.spec().host_requirement(),
                HostRequirement::AnySubstrate
            );
            plan.spec().admit(&BenchHost::FakeTimeControlled).unwrap();
        }
        // Each mode is its own variant, so its attempts form their own ledger.
        assert_ne!(sequential.spec().variant(), burst.spec().variant());
        assert_ne!(staggered.spec().variant(), burst.spec().variant());
    }

    #[test]
    fn one_hundred_concurrent_creates_need_an_authorized_sized_host() {
        let plan = Bench05Plan::concurrent_100(3, limits()).unwrap();
        assert_eq!(
            plan.spec().host_requirement(),
            HostRequirement::AuthorizedSizedHost {
                concurrent_creates: 100
            }
        );
        assert_eq!(
            plan.spec().admit(&BenchHost::FakeTimeControlled),
            Err(BenchError::NeedsAuthorizedSizedHost {
                concurrent_creates: 100
            })
        );
        assert_eq!(
            plan.spec().admit(&authorized(64)),
            Err(BenchError::HostUndersized {
                concurrent_creates: 100,
                sized_for: 64
            })
        );
        plan.spec().admit(&authorized(100)).unwrap();
        // A staggered plan that overlaps 100 creates or more is the same case: creates
        // 50 ms apart under a 5 s timeout overlap 5000 / 50 + 1 = 101 at a time.
        let dense = Bench05Plan::staggered(50 * MILLI, 200, 1, limits()).unwrap();
        assert_eq!(dense.spec().concurrent_creates(), 101);
        assert!(matches!(
            dense.spec().admit(&BenchHost::FakeTimeControlled),
            Err(BenchError::NeedsAuthorizedSizedHost { .. })
        ));
        // 99 at once runs anywhere.
        Bench05Plan::burst(99, 1, limits())
            .unwrap()
            .spec()
            .admit(&BenchHost::FakeTimeControlled)
            .unwrap();
    }

    #[test]
    fn malformed_plans_are_refused() {
        let mut no_deadline = limits();
        no_deadline.deadline_nanos = 0;
        let mut short_timeout = limits();
        short_timeout.timeout_nanos = short_timeout.deadline_nanos - 1;
        for (result, field) in [
            (
                Bench05Plan::sequential(0, 1, limits()),
                "attempts_per_burst",
            ),
            (Bench05Plan::sequential(5, 0, limits()), "bursts"),
            (Bench05Plan::staggered(0, 5, 1, limits()), "interval_nanos"),
            (Bench05Plan::burst(4, 1, no_deadline), "deadline_nanos"),
            (Bench05Plan::burst(4, 1, short_timeout), "timeout_nanos"),
        ] {
            assert!(
                matches!(result, Err(BenchError::InvalidParameter { field: found, .. }) if found == field),
                "{field}"
            );
        }
        assert_eq!(
            Bench05Plan::sequential(u32::MAX, 2, limits()),
            Err(BenchError::Overflow)
        );
    }

    #[test]
    fn bench_06_cases_have_their_pool_shapes() {
        let cold = Bench06Plan::cold_vm(6, 3, limits()).unwrap();
        assert!(!cold.uses_pool());
        assert_eq!(cold.pool_capacity(), 0);
        let limited = Bench06Plan::limited_warm_pool(2, 6, 3, limits()).unwrap();
        assert_eq!((limited.pool_capacity(), limited.initial_clones()), (2, 2));
        assert_eq!(limited.replenishment(), None);
        let clean = Bench06Plan::clean_snapshot(6, 3, limits()).unwrap();
        assert_eq!(clean.pool_capacity(), 6);
        let schedule = ReplenishmentSchedule {
            every_nanos: 2_000 * MILLI,
            clones: 1,
        };
        let depletion =
            Bench06Plan::pool_depletion_replenishment(2, 500 * MILLI, schedule, 8, 3, limits())
                .unwrap();
        assert_eq!(depletion.replenishment(), Some(schedule));
        assert_eq!(depletion.case(), Bench06Case::PoolDepletionReplenishment);
        for plan in [&cold, &limited, &clean, &depletion] {
            assert_eq!(plan.spec().bench(), BenchId::Bench06);
        }
        // A limited pool must run out; one as large as its checkouts is the clean case.
        assert!(Bench06Plan::limited_warm_pool(6, 6, 1, limits()).is_err());
        assert!(Bench06Plan::limited_warm_pool(0, 6, 1, limits()).is_err());
        assert!(Bench06Plan::pool_depletion_replenishment(
            2,
            500 * MILLI,
            ReplenishmentSchedule {
                every_nanos: 0,
                clones: 1
            },
            8,
            1,
            limits()
        )
        .is_err());
    }

    #[test]
    fn a_plan_retries_only_under_an_explicit_policy_and_says_so() {
        use super::super::report::RejectionKind;
        let plan = Bench05Plan::staggered(1_000 * MILLI, 20, 1, limits()).unwrap();
        assert!(plan.spec().retries().is_off());
        let policy = RetryPolicy::new([RejectionKind::HostCapacity], 1, 1_000 * MILLI).unwrap();
        let retrying = plan.clone().with_retries(policy.clone()).unwrap();
        assert_eq!(retrying.spec().retries(), &policy);
        // Its attempts form their own ledger.
        assert_eq!(
            retrying.spec().variant().as_str(),
            "bench-05-staggered-1000000000ns-x20-retry-1x"
        );
        assert_eq!(retrying.spec().total_attempts(), 20);
        // A first attempt and its retry span 5 + 1 + 5 s; creates 1 s apart overlap 12.
        assert_eq!(plan.spec().concurrent_creates(), 6);
        assert_eq!(retrying.spec().concurrent_creates(), 12);
        assert_eq!(retrying.spec().load().concurrent_requests, 12);
        // Sequential and burst plans keep their peak: retries of one create never overlap.
        let burst = Bench05Plan::burst(8, 1, limits())
            .unwrap()
            .with_retries(policy.clone())
            .unwrap();
        assert_eq!(burst.spec().concurrent_creates(), 8);
        let sequential = Bench06Plan::cold_vm(4, 1, limits())
            .unwrap()
            .with_retries(policy.clone())
            .unwrap();
        assert_eq!(sequential.spec().concurrent_creates(), 1);
        assert_eq!(
            sequential.spec().variant().as_str(),
            "bench-06-cold-vm-retry-1x"
        );
        // Set once; an off policy changes nothing.
        assert!(matches!(
            retrying.with_retries(policy),
            Err(BenchError::InvalidParameter {
                field: "retries",
                ..
            })
        ));
        assert_eq!(plan.clone().with_retries(RetryPolicy::off()).unwrap(), plan);
    }

    #[test]
    fn no_preallocated_pool_beyond_the_measured_checkouts() {
        // S10 line 351: "do not add a preallocated 1,000-slot pool".
        assert!(matches!(
            Bench06Plan::new(
                Bench06Case::LimitedWarmPool,
                Label::new("bench-06-oversized").unwrap(),
                ArrivalPattern::Sequential,
                10,
                1,
                limits(),
                1_000,
                None,
            ),
            Err(BenchError::InvalidParameter {
                field: "pool_capacity",
                ..
            })
        ));
    }
}
