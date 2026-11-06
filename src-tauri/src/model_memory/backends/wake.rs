//! Wake ordering, declared per backend and checked against the pinned release's queried
//! capabilities (GPU part §3.8: "Query the pinned backend's capabilities and test wake
//! ordering").
//!
//! A sleep level's semantics decide the steps. Weights offloaded to the host are restored
//! from there, discarded weights are reloaded from a verified copy, and a discarded KV
//! cache is reallocated empty; no step restores KV, so no wake order can assume KV the
//! level did not keep. Weight steps finish before the KV cache is reallocated (vLLM's
//! staged wake order), readiness is checked after both, and requests are admitted last.
//! A reload between the weight and KV wakes needs a release that wakes them separately.

use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::capabilities::{
    KvRetention, LevelSemantics, PinnedCapabilities, SleepLevel, WeightRetention,
};
use super::declarations::PinnedFeature;
use super::runtime::SleepPlan;
use crate::foundation::evidence::{Backend, BackendRelease, Remedy};
use crate::foundation::ids::{Clock, MonotonicTime};

/// One step of waking a sleeping backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WakeStep {
    /// Copy the weights back from the host copy made at sleep.
    RestoreWeightsFromHost,
    /// Allocate weight memory and fill it from the sleep plan's reconstructible copy,
    /// verified for exactly these weights.
    ReloadWeightsFromVerifiedSource,
    /// Allocate the KV cache again, empty.
    ReallocateKvCache,
    /// Check readiness for the supported request shape.
    CheckReadiness,
    /// Start serving requests.
    AdmitRequests,
}

impl WakeStep {
    /// Steps of a lower phase finish before steps of a higher one.
    const fn phase(self) -> u8 {
        match self {
            Self::RestoreWeightsFromHost | Self::ReloadWeightsFromVerifiedSource => 0,
            Self::ReallocateKvCache => 1,
            Self::CheckReadiness => 2,
            Self::AdmitRequests => 3,
        }
    }
}

impl fmt::Display for WakeStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RestoreWeightsFromHost => "restore the weights from host memory",
            Self::ReloadWeightsFromVerifiedSource => "reload the weights from the verified copy",
            Self::ReallocateKvCache => "reallocate the KV cache",
            Self::CheckReadiness => "check readiness",
            Self::AdmitRequests => "admit requests",
        })
    }
}

/// The steps a level's semantics call for, in order.
fn steps_for(semantics: LevelSemantics) -> Vec<WakeStep> {
    let weights = match semantics.weights {
        WeightRetention::OnDevice => None,
        WeightRetention::OffloadedToHost => Some(WakeStep::RestoreWeightsFromHost),
        WeightRetention::Discarded => Some(WakeStep::ReloadWeightsFromVerifiedSource),
    };
    let kv_cache = match semantics.kv_cache {
        KvRetention::Retained => None,
        KvRetention::Discarded => Some(WakeStep::ReallocateKvCache),
    };
    weights
        .into_iter()
        .chain(kv_cache)
        .chain([WakeStep::CheckReadiness, WakeStep::AdmitRequests])
        .collect()
}

/// The order a backend wakes from one sleep level in (GPU part §3.8).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WakeOrder {
    pub release: BackendRelease,
    pub level: SleepLevel,
    pub steps: Vec<WakeStep>,
}

impl WakeOrder {
    /// The order the pinned release's backend declares for `level`. vLLM declares one per
    /// level its release reports; Transformers and llama.cpp have no sleep levels, so they
    /// declare none.
    pub fn declared(
        pinned: &PinnedCapabilities,
        level: SleepLevel,
    ) -> Result<Self, WakeOrderRefusal> {
        let release = pinned.release();
        if release.backend != Backend::Vllm {
            return Err(WakeOrderRefusal::NoDeclaredOrder {
                backend: release.backend,
            });
        }
        let semantics = pinned
            .level(level)
            .ok_or_else(|| WakeOrderRefusal::UnknownLevel {
                level,
                release: release.clone(),
            })?;
        Ok(Self {
            release: release.clone(),
            level,
            steps: steps_for(semantics),
        })
    }

    /// Checks this order against `pinned`: the same release, a level it reports, each
    /// step the level's semantics call for exactly once and nothing else, in phase order,
    /// and staged wake where a reload sits between the weight and KV wakes.
    pub fn check(&self, pinned: &PinnedCapabilities) -> Result<CheckedWakeOrder, WakeOrderRefusal> {
        if self.release != *pinned.release() {
            return Err(WakeOrderRefusal::ReleaseMismatch {
                order: self.release.clone(),
                pinned: pinned.release().clone(),
            });
        }
        let level = self.level;
        let semantics = pinned
            .level(level)
            .ok_or_else(|| WakeOrderRefusal::UnknownLevel {
                level,
                release: self.release.clone(),
            })?;
        let mut seen = BTreeSet::new();
        if let Some(&step) = self.steps.iter().find(|step| !seen.insert(**step)) {
            return Err(WakeOrderRefusal::RepeatedStep { step });
        }
        let required = steps_for(semantics);
        if let Some(&step) = self.steps.iter().find(|step| !required.contains(step)) {
            return Err(WakeOrderRefusal::StepNotCalledFor { step, level });
        }
        if let Some(&step) = required.iter().find(|step| !self.steps.contains(step)) {
            return Err(WakeOrderRefusal::MissingStep { step, level });
        }
        for pair in self.steps.windows(2) {
            if let [earlier, later] = pair {
                if earlier.phase() > later.phase() {
                    return Err(WakeOrderRefusal::OutOfOrder {
                        step: *later,
                        must_precede: *earlier,
                    });
                }
            }
        }
        if self
            .steps
            .contains(&WakeStep::ReloadWeightsFromVerifiedSource)
            && self.steps.contains(&WakeStep::ReallocateKvCache)
            && !pinned.supports(PinnedFeature::StagedWake)
        {
            return Err(WakeOrderRefusal::NeedsStagedWake {
                release: self.release.clone(),
                level,
            });
        }
        Ok(CheckedWakeOrder {
            release: self.release.clone(),
            level,
            steps: self.steps.clone(),
        })
    }
}

/// Why a wake order was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum WakeOrderRefusal {
    /// The backend declares no wake order because it has no sleep levels.
    NoDeclaredOrder { backend: Backend },
    /// The order is for another release than the pinned one.
    ReleaseMismatch {
        order: BackendRelease,
        pinned: BackendRelease,
    },
    /// The pinned release did not report this level.
    UnknownLevel {
        level: SleepLevel,
        release: BackendRelease,
    },
    /// The order names a step twice.
    RepeatedStep { step: WakeStep },
    /// The level's semantics do not call for this step, such as restoring weights from a
    /// host copy that a weight-discarding level never made.
    StepNotCalledFor { step: WakeStep, level: SleepLevel },
    /// The level's semantics call for this step and the order lacks it.
    MissingStep { step: WakeStep, level: SleepLevel },
    /// `step` comes after `must_precede` but has to finish before it.
    OutOfOrder {
        step: WakeStep,
        must_precede: WakeStep,
    },
    /// A reload between the weight and KV wakes needs a release that wakes them
    /// separately.
    NeedsStagedWake {
        release: BackendRelease,
        level: SleepLevel,
    },
}

impl fmt::Display for WakeOrderRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoDeclaredOrder { backend } => {
                write!(
                    f,
                    "{backend} has no sleep levels, so it declares no wake order"
                )
            }
            Self::ReleaseMismatch { order, pinned } => {
                write!(
                    f,
                    "the wake order is for {order}, but the pinned release is {pinned}"
                )
            }
            Self::UnknownLevel { level, release } => {
                write!(f, "{release} did not report sleep level {level}")
            }
            Self::RepeatedStep { step } => write!(f, "the wake order repeats: {step}"),
            Self::StepNotCalledFor { step, level } => write!(
                f,
                "sleep level {level} does not call for this step, which would assume state the \
                 level did not keep: {step}"
            ),
            Self::MissingStep { step, level } => {
                write!(f, "waking from sleep level {level} must {step}")
            }
            Self::OutOfOrder { step, must_precede } => {
                write!(f, "\"{step}\" must finish before \"{must_precede}\"")
            }
            Self::NeedsStagedWake { release, level } => write!(
                f,
                "waking from sleep level {level} reloads the weights before the KV cache, which \
                 needs staged wake, and {release} does not report it"
            ),
        }
    }
}

impl std::error::Error for WakeOrderRefusal {}

/// A wake order that passed [`WakeOrder::check`]. Only that check makes one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CheckedWakeOrder {
    release: BackendRelease,
    level: SleepLevel,
    steps: Vec<WakeStep>,
}

impl CheckedWakeOrder {
    /// The release the order was checked for.
    pub fn release(&self) -> &BackendRelease {
        &self.release
    }

    /// The sleep level it wakes from.
    pub fn level(&self) -> SleepLevel {
        self.level
    }

    /// The steps, in the order they must complete.
    pub fn steps(&self) -> &[WakeStep] {
        &self.steps
    }
}

/// Why a wake step was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum WakeProgressRefusal {
    /// The order was checked for another release or level than the runtime slept at.
    OtherSleep {
        slept: SleepLevel,
        order: SleepLevel,
        release: BackendRelease,
    },
    /// Steps complete only in the checked order; `expected` is `None` once the wake ended.
    OutOfOrder {
        expected: Option<WakeStep>,
        found: WakeStep,
    },
    /// The wake already failed at this step.
    Failed { at: WakeStep },
}

impl fmt::Display for WakeProgressRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OtherSleep {
                slept,
                order,
                release,
            } => write!(
                f,
                "the runtime slept at level {slept}, but the wake order is for level {order} of \
                 {release}"
            ),
            Self::OutOfOrder {
                expected: Some(expected),
                found,
            } => write!(f, "the next step is to {expected}, not to {found}"),
            Self::OutOfOrder {
                expected: None,
                found,
            } => write!(f, "the wake has no step left, so it cannot {found}"),
            Self::Failed { at } => write!(f, "the wake already failed at: {at}"),
        }
    }
}

impl std::error::Error for WakeProgressRefusal {}

/// A failed wake: requests are never admitted, and the model loads again through the
/// ordinary loader (GPU-W01 acceptance: "failures fall back to the previous supported
/// loader").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct WakeFailure {
    at: WakeStep,
}

impl WakeFailure {
    /// The step that failed.
    pub fn at(&self) -> WakeStep {
        self.at
    }

    /// What follows: the ordinary loader.
    pub fn remedy(&self) -> Remedy {
        Remedy::UseOrdinaryLoader
    }
}

/// One wake in progress, following a checked order step by step on an injected clock.
pub struct WakeProgress<C: Clock> {
    order: CheckedWakeOrder,
    clock: C,
    started_at: MonotonicTime,
    completed: Vec<(WakeStep, MonotonicTime)>,
    failed_at: Option<WakeStep>,
}

impl<C: Clock> WakeProgress<C> {
    /// Starts waking the runtime that entered `sleep`, along `order`, which must have been
    /// checked for the same release and level.
    pub fn start(
        sleep: &SleepPlan,
        order: CheckedWakeOrder,
        clock: C,
    ) -> Result<Self, WakeProgressRefusal> {
        if order.release != *sleep.release() || order.level != sleep.level() {
            return Err(WakeProgressRefusal::OtherSleep {
                slept: sleep.level(),
                order: order.level,
                release: order.release,
            });
        }
        let started_at = clock.now();
        Ok(Self {
            order,
            clock,
            started_at,
            completed: Vec::new(),
            failed_at: None,
        })
    }

    /// The step that must complete next; `None` once the wake ended or failed.
    pub fn next_step(&self) -> Option<WakeStep> {
        if self.failed_at.is_some() {
            return None;
        }
        self.order.steps.get(self.completed.len()).copied()
    }

    /// Records that `step` completed; it must be the next step.
    pub fn complete(&mut self, step: WakeStep) -> Result<(), WakeProgressRefusal> {
        self.check_next(step)?;
        self.completed.push((step, self.clock.now()));
        Ok(())
    }

    /// Records that `step`, the next one, failed. Nothing is admitted afterwards.
    pub fn fail(&mut self, step: WakeStep) -> Result<WakeFailure, WakeProgressRefusal> {
        self.check_next(step)?;
        self.failed_at = Some(step);
        Ok(WakeFailure { at: step })
    }

    /// Whether requests were admitted: every step completed and nothing failed.
    pub fn is_serving(&self) -> bool {
        self.failed_at.is_none() && self.completed.len() == self.order.steps.len()
    }

    /// How long each completed step took, measured from the end of the one before.
    pub fn stage_durations(&self) -> Vec<(WakeStep, Duration)> {
        let mut previous = self.started_at;
        self.completed
            .iter()
            .map(|&(step, at)| {
                let duration = at.saturating_duration_since(previous);
                previous = at;
                (step, duration)
            })
            .collect()
    }

    fn check_next(&self, step: WakeStep) -> Result<(), WakeProgressRefusal> {
        if let Some(at) = self.failed_at {
            return Err(WakeProgressRefusal::Failed { at });
        }
        let expected = self.next_step();
        if expected == Some(step) {
            Ok(())
        } else {
            Err(WakeProgressRefusal::OutOfOrder {
                expected,
                found: step,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::super::test_support::{
        documented_vllm_levels, llama_cpp, local_copy, pinned, transformers, vllm_0_31_0, Fixture,
    };
    use super::*;
    use crate::foundation::evidence::Optimization;
    use crate::foundation::ids::ManualClock;

    use WakeStep::{
        AdmitRequests, CheckReadiness, ReallocateKvCache, ReloadWeightsFromVerifiedSource,
        RestoreWeightsFromHost,
    };

    fn level(number: u8) -> SleepLevel {
        SleepLevel::new(number)
    }

    fn staged() -> PinnedCapabilities {
        pinned(
            vllm_0_31_0(),
            documented_vllm_levels(),
            &[PinnedFeature::StagedWake],
        )
    }

    fn order(number: u8, steps: &[WakeStep]) -> WakeOrder {
        WakeOrder {
            release: vllm_0_31_0(),
            level: level(number),
            steps: steps.to_vec(),
        }
    }

    #[test]
    fn wake_orders_are_declared_per_backend() {
        let pinned_vllm = staged();
        let one = WakeOrder::declared(&pinned_vllm, level(1)).unwrap();
        let two = WakeOrder::declared(&pinned_vllm, level(2)).unwrap();
        assert_eq!(
            one.steps,
            [
                RestoreWeightsFromHost,
                ReallocateKvCache,
                CheckReadiness,
                AdmitRequests
            ]
        );
        assert_eq!(
            two.steps,
            [
                ReloadWeightsFromVerifiedSource,
                ReallocateKvCache,
                CheckReadiness,
                AdmitRequests
            ]
        );
        assert_eq!(
            WakeOrder::declared(&pinned_vllm, level(3)),
            Err(WakeOrderRefusal::UnknownLevel {
                level: level(3),
                release: vllm_0_31_0()
            })
        );
        for (release, backend) in [
            (transformers(), Backend::Transformers),
            (llama_cpp(), Backend::LlamaCpp),
        ] {
            assert_eq!(
                WakeOrder::declared(&pinned(release, BTreeMap::new(), &[]), level(1)),
                Err(WakeOrderRefusal::NoDeclaredOrder { backend })
            );
        }
    }

    #[test]
    fn declared_orders_pass_against_the_pinned_capabilities() {
        let pinned_vllm = staged();
        for number in [1, 2] {
            let declared = WakeOrder::declared(&pinned_vllm, level(number)).unwrap();
            let checked = declared.check(&pinned_vllm).unwrap();
            assert_eq!(checked.steps(), declared.steps.as_slice());
            assert_eq!(checked.level(), level(number));
            assert_eq!(checked.release(), &vllm_0_31_0());
        }
        // Without staged wake, level 1 still wakes: restoring from the host is the weight
        // wake itself. Level 2 would reallocate the KV cache before the reload.
        let unstaged = pinned(vllm_0_31_0(), documented_vllm_levels(), &[]);
        assert!(WakeOrder::declared(&unstaged, level(1))
            .unwrap()
            .check(&unstaged)
            .is_ok());
        assert_eq!(
            WakeOrder::declared(&unstaged, level(2))
                .unwrap()
                .check(&unstaged),
            Err(WakeOrderRefusal::NeedsStagedWake {
                release: vllm_0_31_0(),
                level: level(2)
            })
        );
        // A level that keeps the weights and the KV cache needs no memory step at all.
        let mut levels = documented_vllm_levels();
        levels.insert(
            level(3),
            LevelSemantics {
                weights: WeightRetention::OnDevice,
                kv_cache: KvRetention::Retained,
            },
        );
        let kept = pinned(vllm_0_31_0(), levels, &[]);
        assert_eq!(
            WakeOrder::declared(&kept, level(3)).unwrap().steps,
            [CheckReadiness, AdmitRequests]
        );
    }

    #[test]
    fn orders_that_assume_retention_or_skip_steps_are_refused() {
        let pinned_vllm = staged();
        let cases = [
            (
                order(
                    2,
                    &[
                        RestoreWeightsFromHost,
                        ReallocateKvCache,
                        CheckReadiness,
                        AdmitRequests,
                    ],
                ),
                WakeOrderRefusal::StepNotCalledFor {
                    step: RestoreWeightsFromHost,
                    level: level(2),
                },
            ),
            (
                order(1, &[RestoreWeightsFromHost, CheckReadiness, AdmitRequests]),
                WakeOrderRefusal::MissingStep {
                    step: ReallocateKvCache,
                    level: level(1),
                },
            ),
            (
                order(2, &[ReallocateKvCache, CheckReadiness, AdmitRequests]),
                WakeOrderRefusal::MissingStep {
                    step: ReloadWeightsFromVerifiedSource,
                    level: level(2),
                },
            ),
            (
                order(
                    1,
                    &[
                        ReallocateKvCache,
                        RestoreWeightsFromHost,
                        CheckReadiness,
                        AdmitRequests,
                    ],
                ),
                WakeOrderRefusal::OutOfOrder {
                    step: RestoreWeightsFromHost,
                    must_precede: ReallocateKvCache,
                },
            ),
            (
                order(
                    1,
                    &[
                        RestoreWeightsFromHost,
                        ReallocateKvCache,
                        AdmitRequests,
                        CheckReadiness,
                    ],
                ),
                WakeOrderRefusal::OutOfOrder {
                    step: CheckReadiness,
                    must_precede: AdmitRequests,
                },
            ),
            (
                order(
                    1,
                    &[
                        RestoreWeightsFromHost,
                        CheckReadiness,
                        ReallocateKvCache,
                        AdmitRequests,
                    ],
                ),
                WakeOrderRefusal::OutOfOrder {
                    step: ReallocateKvCache,
                    must_precede: CheckReadiness,
                },
            ),
            (
                order(
                    1,
                    &[
                        RestoreWeightsFromHost,
                        ReallocateKvCache,
                        ReallocateKvCache,
                        CheckReadiness,
                        AdmitRequests,
                    ],
                ),
                WakeOrderRefusal::RepeatedStep {
                    step: ReallocateKvCache,
                },
            ),
            (
                order(4, &[CheckReadiness, AdmitRequests]),
                WakeOrderRefusal::UnknownLevel {
                    level: level(4),
                    release: vllm_0_31_0(),
                },
            ),
        ];
        for (order, refusal) in cases {
            assert_eq!(order.check(&pinned_vllm), Err(refusal), "{order:?}");
        }

        let mut other = order(
            1,
            &[
                RestoreWeightsFromHost,
                ReallocateKvCache,
                CheckReadiness,
                AdmitRequests,
            ],
        );
        other.release = llama_cpp();
        assert!(matches!(
            other.check(&pinned_vllm),
            Err(WakeOrderRefusal::ReleaseMismatch { .. })
        ));
        let json = serde_json::to_value(order(1, &[CheckReadiness])).unwrap();
        let mut extra = json.clone();
        extra["skip_readiness"] = true.into();
        assert!(serde_json::from_value::<WakeOrder>(extra).is_err());
        assert!(serde_json::from_value::<WakeOrder>(json).is_ok());
    }

    #[test]
    fn a_wake_follows_its_checked_order() {
        let loaded = Fixture::discarding()
            .features(&[PinnedFeature::StagedWake])
            .build()
            .unwrap();
        let sleep = loaded.sleep(2, Some(local_copy())).unwrap();
        assert_eq!(sleep.reconstructible_copy(), Some(local_copy()));
        let checked = WakeOrder::declared(loaded.pinned(), level(2))
            .unwrap()
            .check(loaded.pinned())
            .unwrap();
        let level_one = WakeOrder::declared(loaded.pinned(), level(1))
            .unwrap()
            .check(loaded.pinned())
            .unwrap();
        let clock = ManualClock::new(MonotonicTime::from_nanos(1_000));
        assert!(matches!(
            WakeProgress::start(&sleep, level_one, &clock),
            Err(WakeProgressRefusal::OtherSleep { .. })
        ));

        let mut wake = WakeProgress::start(&sleep, checked, &clock).unwrap();
        assert_eq!(
            wake.complete(AdmitRequests),
            Err(WakeProgressRefusal::OutOfOrder {
                expected: Some(ReloadWeightsFromVerifiedSource),
                found: AdmitRequests
            })
        );
        assert_eq!(
            wake.complete(ReallocateKvCache),
            Err(WakeProgressRefusal::OutOfOrder {
                expected: Some(ReloadWeightsFromVerifiedSource),
                found: ReallocateKvCache
            })
        );
        for (step, seconds) in [
            (ReloadWeightsFromVerifiedSource, 4),
            (ReallocateKvCache, 1),
            (CheckReadiness, 2),
        ] {
            assert!(!wake.is_serving());
            clock.advance(Duration::from_secs(seconds));
            wake.complete(step).unwrap();
        }
        assert_eq!(wake.next_step(), Some(AdmitRequests));
        wake.complete(AdmitRequests).unwrap();
        assert!(wake.is_serving());
        assert_eq!(wake.next_step(), None);
        assert_eq!(
            wake.complete(AdmitRequests),
            Err(WakeProgressRefusal::OutOfOrder {
                expected: None,
                found: AdmitRequests
            })
        );
        assert_eq!(
            wake.stage_durations(),
            [
                (ReloadWeightsFromVerifiedSource, Duration::from_secs(4)),
                (ReallocateKvCache, Duration::from_secs(1)),
                (CheckReadiness, Duration::from_secs(2)),
                (AdmitRequests, Duration::ZERO),
            ]
        );
    }

    #[test]
    fn a_failed_wake_never_admits_requests() {
        let loaded = Fixture::new(vllm_0_31_0())
            .modes(&[Optimization::SleepWeightOffload])
            .build()
            .unwrap();
        let sleep = loaded.sleep(1, None).unwrap();
        let checked = WakeOrder::declared(loaded.pinned(), level(1))
            .unwrap()
            .check(loaded.pinned())
            .unwrap();
        let clock = ManualClock::default();
        let mut wake = WakeProgress::start(&sleep, checked, &clock).unwrap();
        wake.complete(RestoreWeightsFromHost).unwrap();
        assert_eq!(
            wake.fail(CheckReadiness),
            Err(WakeProgressRefusal::OutOfOrder {
                expected: Some(ReallocateKvCache),
                found: CheckReadiness
            })
        );
        let failure = wake.fail(ReallocateKvCache).unwrap();
        assert_eq!(failure.at(), ReallocateKvCache);
        assert_eq!(failure.remedy(), Remedy::UseOrdinaryLoader);
        for step in [ReallocateKvCache, CheckReadiness, AdmitRequests] {
            assert_eq!(
                wake.complete(step),
                Err(WakeProgressRefusal::Failed {
                    at: ReallocateKvCache
                })
            );
        }
        assert_eq!(wake.next_step(), None);
        assert!(!wake.is_serving());
        assert_eq!(
            wake.fail(ReallocateKvCache),
            Err(WakeProgressRefusal::Failed {
                at: ReallocateKvCache
            })
        );
    }
}
