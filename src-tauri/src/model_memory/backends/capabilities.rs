//! The pinned backend release's capabilities, as queried from it (GPU part §3.8: "vLLM
//! sleep levels have different retention semantics; weight retention does not imply KV
//! retention. Query the pinned backend's capabilities").
//!
//! No release's sleep semantics are written into this module: the plan cites only the
//! unversioned vLLM sleep documentation, so what each level keeps comes from querying the
//! exact pinned release. A release may report sleep levels only when evidence's mode rules
//! record a sleep mode for it, weight offloading or weight discarding, so vLLM 0.29.0,
//! pinned today, has none (rollout decision for T01: its sleep mode stays off until a rule
//! is recorded). Each level then runs as the mode its semantics name
//! ([`LevelSemantics::mode`]).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::declarations::PinnedFeature;
use crate::foundation::evidence::{
    BackendModeRules, BackendRelease, Capability, ModeRefusal, Optimization, Remedy, SourceClass,
};

/// A sleep level, numbered as the pinned backend numbers it (vLLM uses 1 and 2). What a
/// level keeps comes only from the queried [`LevelSemantics`], never from its number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SleepLevel(u8);

impl SleepLevel {
    /// The level the backend calls `level`.
    pub const fn new(level: u8) -> Self {
        Self(level)
    }

    /// The backend's number for the level.
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl fmt::Display for SleepLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Where a sleeping backend keeps its weights (GPU part §3.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WeightRetention {
    /// The weights stay in GPU memory.
    OnDevice,
    /// The weights are copied to host memory, and back on wake.
    OffloadedToHost,
    /// The weights are dropped; wake reloads them from a verified copy.
    Discarded,
}

impl WeightRetention {
    /// Whether the weights survive the sleep somewhere.
    pub const fn is_retained(self) -> bool {
        !matches!(self, Self::Discarded)
    }
}

impl fmt::Display for WeightRetention {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::OnDevice => "kept in GPU memory",
            Self::OffloadedToHost => "offloaded to host memory",
            Self::Discarded => "discarded",
        })
    }
}

/// Whether a sleeping backend keeps its KV cache. Every level states it on its own; it
/// never follows from weight retention (GPU part §3.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KvRetention {
    /// The KV cache is dropped.
    Discarded,
    /// The KV cache stays in GPU memory.
    Retained,
}

/// What one sleep level keeps (GPU part §3.8). Both parts are required, so KV retention is
/// never left to be inferred from weight retention.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LevelSemantics {
    pub weights: WeightRetention,
    pub kv_cache: KvRetention,
}

impl LevelSemantics {
    /// The backend mode the level runs as, which gates it: weight discarding when the level
    /// drops the weights, weight offloading when it keeps them on the device or in host
    /// memory (CORE-01 `SleepWeightDiscard` and `SleepWeightOffload`; S7 keeps the two
    /// apart).
    pub const fn mode(self) -> Optimization {
        if self.weights.is_retained() {
            Optimization::SleepWeightOffload
        } else {
            Optimization::SleepWeightDiscard
        }
    }
}

/// Whether `rules` record a sleep mode for exactly `release`: weight offloading or weight
/// discarding. The refusal is offloading's when neither is recorded.
pub(super) fn sleep_recorded(
    rules: &BackendModeRules,
    release: &BackendRelease,
) -> Result<(), ModeRefusal> {
    rules
        .check_mode(release, Optimization::SleepWeightOffload)
        .or_else(|offload| {
            rules
                .check_mode(release, Optimization::SleepWeightDiscard)
                .map_err(|_| offload)
        })
}

/// The weakest source a capability answer may come from: the floor evidence sets for the
/// runtime's backend modes, a live report from the runtime. A recorded declaration or a
/// fixture is not a query of the pinned release.
pub const QUERY_MINIMUM_SOURCE: SourceClass = Capability::SleepWeightOffload.weakest_source();

/// The answer the pinned backend release gave when its capabilities were queried (GPU
/// part §3.8).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueriedCapabilities {
    /// The exact release that answered.
    pub release: BackendRelease,
    /// Where the answer came from.
    pub source: SourceClass,
    /// The sleep levels the release offers, with what each keeps.
    pub sleep_levels: BTreeMap<SleepLevel, LevelSemantics>,
    /// The other features the release reports.
    pub features: BTreeSet<PinnedFeature>,
}

/// Why an answer was not accepted as the pinned release's capabilities.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityRefusal {
    /// The answer did not come from querying the runtime.
    SourceTooWeak {
        observed: SourceClass,
        required: SourceClass,
    },
    /// The release reports sleep levels, but evidence's rules record no sleep mode for it,
    /// so sleep stays off: an unrecorded release gets no assumed compatibility.
    SleepNotRecorded { cause: ModeRefusal },
}

impl CapabilityRefusal {
    /// What the user can do: query the runtime itself, or use a release with a recorded
    /// sleep rule.
    pub fn remedy(&self) -> Remedy {
        match self {
            Self::SourceTooWeak { required, .. } => Remedy::ObtainStrongerEvidence {
                required: *required,
            },
            Self::SleepNotRecorded { cause } => cause.remedy(),
        }
    }
}

impl fmt::Display for CapabilityRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceTooWeak { observed, required } => write!(
                f,
                "backend capabilities must be queried from the runtime (a {required} or \
                 stronger), not taken from a {observed}; {}",
                self.remedy()
            ),
            Self::SleepNotRecorded { cause } => {
                write!(f, "the reported sleep levels cannot be used: {cause}")
            }
        }
    }
}

impl std::error::Error for CapabilityRefusal {}

/// The capabilities of one exact pinned backend release, accepted from a query (GPU part
/// §3.8). Only [`PinnedCapabilities::new`] makes one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PinnedCapabilities {
    release: BackendRelease,
    source: SourceClass,
    sleep_levels: BTreeMap<SleepLevel, LevelSemantics>,
    features: BTreeSet<PinnedFeature>,
}

impl PinnedCapabilities {
    /// Accepts `answer` when it is a live report from the runtime and, if it lists sleep
    /// levels, `rules` record a sleep mode for the exact release. Whether a level may run
    /// is decided when it is planned, by its own mode.
    pub fn new(
        answer: QueriedCapabilities,
        rules: &BackendModeRules,
    ) -> Result<Self, CapabilityRefusal> {
        if !answer.source.satisfies(QUERY_MINIMUM_SOURCE) {
            return Err(CapabilityRefusal::SourceTooWeak {
                observed: answer.source,
                required: QUERY_MINIMUM_SOURCE,
            });
        }
        if !answer.sleep_levels.is_empty() {
            sleep_recorded(rules, &answer.release)
                .map_err(|cause| CapabilityRefusal::SleepNotRecorded { cause })?;
        }
        Ok(Self {
            release: answer.release,
            source: answer.source,
            sleep_levels: answer.sleep_levels,
            features: answer.features,
        })
    }

    /// The exact release the capabilities belong to.
    pub fn release(&self) -> &BackendRelease {
        &self.release
    }

    /// Where the answer came from.
    pub fn source(&self) -> SourceClass {
        self.source
    }

    /// What `level` keeps, if the release offers it.
    pub fn level(&self, level: SleepLevel) -> Option<LevelSemantics> {
        self.sleep_levels.get(&level).copied()
    }

    /// Every sleep level the release offers, in order.
    pub fn levels(&self) -> impl Iterator<Item = (SleepLevel, LevelSemantics)> + '_ {
        self.sleep_levels
            .iter()
            .map(|(level, semantics)| (*level, *semantics))
    }

    /// Whether the release reported `feature`.
    pub fn supports(&self, feature: PinnedFeature) -> bool {
        self.features.contains(&feature)
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{
        answer, discard_sleep_rules, documented_vllm_levels, llama_cpp, release, transformers,
        vllm_0_29_0, vllm_0_31_0,
    };
    use super::*;
    use crate::foundation::evidence::{Backend, BackendModeRule};

    #[test]
    fn capabilities_are_queried_from_the_runtime() {
        assert_eq!(QUERY_MINIMUM_SOURCE, SourceClass::GuestReport);
        assert_eq!(
            QUERY_MINIMUM_SOURCE,
            Capability::ZeroCopyPreload.weakest_source()
        );
        let rules = BackendModeRules::recorded();
        for source in [SourceClass::Fixture, SourceClass::RecordedDeclaration] {
            let mut weak = answer(vllm_0_31_0(), documented_vllm_levels(), &[]);
            weak.source = source;
            let refusal = PinnedCapabilities::new(weak, &rules).unwrap_err();
            assert_eq!(
                refusal,
                CapabilityRefusal::SourceTooWeak {
                    observed: source,
                    required: SourceClass::GuestReport
                }
            );
            assert_eq!(
                refusal.remedy(),
                Remedy::ObtainStrongerEvidence {
                    required: SourceClass::GuestReport
                }
            );
        }
        for source in [
            SourceClass::GuestReport,
            SourceClass::ProviderApi,
            SourceClass::HostProbe,
        ] {
            let mut live = answer(vllm_0_31_0(), documented_vllm_levels(), &[]);
            live.source = source;
            assert_eq!(
                PinnedCapabilities::new(live, &rules).unwrap().source(),
                source
            );
        }
    }

    #[test]
    fn sleep_levels_need_a_recorded_sleep_rule_for_the_exact_release() {
        let rules = BackendModeRules::recorded();
        for release in [vllm_0_29_0(), llama_cpp(), transformers()] {
            let refusal = PinnedCapabilities::new(
                answer(release.clone(), documented_vllm_levels(), &[]),
                &rules,
            )
            .unwrap_err();
            assert_eq!(
                refusal,
                CapabilityRefusal::SleepNotRecorded {
                    cause: ModeRefusal::UnknownRelease {
                        release: release.clone()
                    }
                }
            );
            assert_eq!(refusal.remedy(), Remedy::UseRecordedBackendRelease);
            assert!(refusal.to_string().contains("no recorded mode rules"));

            let without_sleep =
                PinnedCapabilities::new(answer(release.clone(), BTreeMap::new(), &[]), &rules)
                    .unwrap();
            assert_eq!(without_sleep.levels().count(), 0);
            assert_eq!(without_sleep.level(SleepLevel::new(1)), None);
        }
        let pinned =
            PinnedCapabilities::new(answer(vllm_0_31_0(), documented_vllm_levels(), &[]), &rules)
                .unwrap();
        assert_eq!(pinned.release().backend, Backend::Vllm);
        assert_eq!(pinned.levels().count(), 2);

        // A release whose own rule table records only discard-mode sleep reports levels
        // too; each level is gated by its own mode when planned.
        let discard_only = release(Backend::Vllm, "9.9.9");
        let rules = BackendModeRules::new([BackendModeRule {
            release: discard_only.clone(),
            supported: [Optimization::SleepWeightDiscard].into(),
            tested_together: Default::default(),
            conflicts: Vec::new(),
        }])
        .unwrap();
        assert_eq!(
            PinnedCapabilities::new(answer(discard_only, documented_vllm_levels(), &[]), &rules)
                .unwrap()
                .levels()
                .count(),
            2
        );
        assert!(PinnedCapabilities::new(
            answer(vllm_0_31_0(), documented_vllm_levels(), &[]),
            &discard_sleep_rules(&vllm_0_31_0())
        )
        .is_ok());
    }

    #[test]
    fn a_level_runs_as_the_mode_its_semantics_name() {
        let levels = documented_vllm_levels();
        assert_eq!(
            levels[&SleepLevel::new(1)].mode(),
            Optimization::SleepWeightOffload
        );
        assert_eq!(
            levels[&SleepLevel::new(2)].mode(),
            Optimization::SleepWeightDiscard
        );
        let on_device = LevelSemantics {
            weights: WeightRetention::OnDevice,
            kv_cache: KvRetention::Retained,
        };
        assert_eq!(on_device.mode(), Optimization::SleepWeightOffload);
    }

    #[test]
    fn levels_state_kv_retention_on_their_own() {
        let levels = documented_vllm_levels();
        let one = levels[&SleepLevel::new(1)];
        let two = levels[&SleepLevel::new(2)];
        assert_ne!(one, two);
        assert!(one.weights.is_retained());
        assert_eq!(one.kv_cache, KvRetention::Discarded);
        assert!(!two.weights.is_retained());

        assert!(
            serde_json::from_str::<LevelSemantics>(r#"{"weights": "offloaded_to_host"}"#).is_err()
        );
        assert!(serde_json::from_str::<LevelSemantics>(
            r#"{"weights": "offloaded_to_host", "kv_cache": "discarded", "sessions": "kept"}"#
        )
        .is_err());
        assert_eq!(
            serde_json::from_str::<LevelSemantics>(
                r#"{"weights": "offloaded_to_host", "kv_cache": "discarded"}"#
            )
            .unwrap(),
            one
        );
    }

    #[test]
    fn answers_round_trip_and_refuse_unknown_fields() {
        let answer = answer(
            vllm_0_31_0(),
            documented_vllm_levels(),
            &[PinnedFeature::StagedWake],
        );
        let json = serde_json::to_value(&answer).unwrap();
        assert_eq!(
            json["sleep_levels"]["2"],
            serde_json::json!({"weights": "discarded", "kv_cache": "discarded"})
        );
        assert_eq!(json["features"], serde_json::json!(["staged_wake"]));
        assert_eq!(
            serde_json::from_value::<QueriedCapabilities>(json.clone()).unwrap(),
            answer
        );
        let mut extra = json;
        extra["kv_retained"] = true.into();
        assert!(serde_json::from_value::<QueriedCapabilities>(extra).is_err());
    }
}
