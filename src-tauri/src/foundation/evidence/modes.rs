//! Backend-mode compatibility rules per exact backend release (GPU part §1.1–§1.2; S7
//! "Sleep, preload, model switching").
//!
//! Rules are a whitelist. A backend mode is used only with a release recorded as
//! supporting it ("version-supported sleep", "eligible preload"). Switching modes stay
//! separate unless a tested release supports them together (GPU part §1.1). A release
//! without a rule gets no assumed compatibility.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::optimization::Optimization;
use super::remedy::Remedy;
use super::subject::{Backend, BackendRelease, BackendVersion};

/// The vLLM 0.31.0 preload documentation, which records that zero-copy preloaded weights
/// cannot use sleep-mode weight offloading (S7; GPU part §1.1–§1.2).
pub const VLLM_0_31_0_PRELOAD_DOC: &str = "https://docs.vllm.ai/en/v0.31.0/features/preload/";

/// Two different switching modes, in a fixed order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "[Optimization; 2]", into = "[Optimization; 2]")]
pub struct ModePair {
    first: Optimization,
    second: Optimization,
}

impl ModePair {
    /// Pairs two different switching modes; anything else is refused.
    pub fn new(one: Optimization, other: Optimization) -> Result<Self, ModeRuleError> {
        for mode in [one, other] {
            if !mode.is_switching_mode() {
                return Err(ModeRuleError::NotASwitchingMode { optimization: mode });
            }
        }
        if one == other {
            return Err(ModeRuleError::SameMode { mode: one });
        }
        Ok(Self::ordered(one, other))
    }

    /// Orders a pair the caller has already checked.
    fn ordered(one: Optimization, other: Optimization) -> Self {
        Self {
            first: one.min(other),
            second: one.max(other),
        }
    }

    pub fn first(self) -> Optimization {
        self.first
    }

    pub fn second(self) -> Optimization {
        self.second
    }
}

impl TryFrom<[Optimization; 2]> for ModePair {
    type Error = ModeRuleError;

    fn try_from([one, other]: [Optimization; 2]) -> Result<Self, Self::Error> {
        Self::new(one, other)
    }
}

impl From<ModePair> for [Optimization; 2] {
    fn from(pair: ModePair) -> Self {
        [pair.first, pair.second]
    }
}

impl fmt::Display for ModePair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} and {}", self.first, self.second)
    }
}

/// A combination a source documents as incompatible.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentedConflict {
    pub pair: ModePair,
    /// Where the incompatibility is documented.
    pub source: String,
}

/// What one exact backend release supports.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendModeRule {
    pub release: BackendRelease,
    /// Backend modes the release supports on their own.
    pub supported: BTreeSet<Optimization>,
    /// Switching-mode pairs tested together on this release.
    pub tested_together: BTreeSet<ModePair>,
    /// Pairs documented as incompatible on this release.
    pub conflicts: Vec<DocumentedConflict>,
}

/// Why a rule table was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ModeRuleError {
    NotASwitchingMode {
        optimization: Optimization,
    },
    SameMode {
        mode: Optimization,
    },
    /// `supported` lists something that is not a backend mode.
    NotABackendMode {
        optimization: Optimization,
    },
    DuplicateRelease {
        release: BackendRelease,
    },
    /// A pair cannot be both tested together and documented as incompatible.
    TestedAndConflicting {
        release: BackendRelease,
        pair: ModePair,
    },
    /// A tested pair includes a backend mode the release does not support.
    TestedWithoutSupport {
        release: BackendRelease,
        pair: ModePair,
    },
}

impl fmt::Display for ModeRuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotASwitchingMode { optimization } => {
                write!(f, "{optimization} is not a switching mode")
            }
            Self::SameMode { mode } => write!(f, "a mode pair names {mode} twice"),
            Self::NotABackendMode { optimization } => {
                write!(f, "{optimization} is not a backend mode")
            }
            Self::DuplicateRelease { release } => write!(f, "{release} has two rules"),
            Self::TestedAndConflicting { release, pair } => write!(
                f,
                "{release} lists {pair} as both tested together and incompatible"
            ),
            Self::TestedWithoutSupport { release, pair } => write!(
                f,
                "{release} lists {pair} as tested together without supporting both"
            ),
        }
    }
}

impl std::error::Error for ModeRuleError {}

strict_evidence_enum! {
    /// Why a mode or a combination of modes is not allowed on a release.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum ModeRefusal tag "refusal" {
        /// No rule exists for this release, so no compatibility is assumed.
        UnknownRelease { release: BackendRelease },
        /// The release's rule does not list this backend mode.
        ModeNotSupported {
            release: BackendRelease,
            mode: Optimization,
        },
        /// The combination is documented as incompatible.
        DocumentedConflict {
            release: BackendRelease,
            pair: ModePair,
            source: String,
        },
        /// The combination was not tested together on this release.
        NotTestedTogether {
            release: BackendRelease,
            pair: ModePair,
        },
    }
}

impl ModeRefusal {
    /// What the user can do: use a release with recorded support, or one mode at a time.
    pub fn remedy(&self) -> Remedy {
        match self {
            Self::UnknownRelease { .. } | Self::ModeNotSupported { .. } => {
                Remedy::UseRecordedBackendRelease
            }
            Self::DocumentedConflict { .. } | Self::NotTestedTogether { .. } => {
                Remedy::UseOneModeAtATime
            }
        }
    }
}

impl fmt::Display for ModeRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let remedy = self.remedy();
        match self {
            Self::UnknownRelease { release } => write!(
                f,
                "{release} has no recorded mode rules, so no compatibility is assumed; {remedy}"
            ),
            Self::ModeNotSupported { release, mode } => {
                write!(f, "{release} has no recorded support for {mode}; {remedy}")
            }
            Self::DocumentedConflict {
                release,
                pair,
                source,
            } => write!(
                f,
                "{pair} must not be combined on {release} ({source}); {remedy}"
            ),
            Self::NotTestedTogether { release, pair } => write!(
                f,
                "{pair} were not tested together on {release}, so they stay separate; {remedy}"
            ),
        }
    }
}

impl std::error::Error for ModeRefusal {}

/// Backend-mode rules keyed by exact release.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct BackendModeRules {
    rules: BTreeMap<BackendRelease, BackendModeRule>,
}

impl BackendModeRules {
    /// Builds a validated rule table. The recorded conflicts of [`Self::recorded`] are
    /// always merged into the rule for their release, so no table can combine a pair the
    /// plan records as incompatible: a rule that lists such a pair as tested together is
    /// refused.
    pub fn new(rules: impl IntoIterator<Item = BackendModeRule>) -> Result<Self, ModeRuleError> {
        let recorded = Self::recorded();
        let mut table = BTreeMap::new();
        for mut rule in rules {
            if let Some(known) = recorded.rules.get(&rule.release) {
                for conflict in &known.conflicts {
                    if !rule
                        .conflicts
                        .iter()
                        .any(|listed| listed.pair == conflict.pair)
                    {
                        rule.conflicts.push(conflict.clone());
                    }
                }
            }
            if let Some(optimization) = rule
                .supported
                .iter()
                .copied()
                .find(|optimization| !optimization.is_backend_mode())
            {
                return Err(ModeRuleError::NotABackendMode { optimization });
            }
            for pair in &rule.tested_together {
                if rule.conflicts.iter().any(|conflict| conflict.pair == *pair) {
                    return Err(ModeRuleError::TestedAndConflicting {
                        release: rule.release.clone(),
                        pair: *pair,
                    });
                }
                if [pair.first, pair.second]
                    .into_iter()
                    .any(|mode| mode.is_backend_mode() && !rule.supported.contains(&mode))
                {
                    return Err(ModeRuleError::TestedWithoutSupport {
                        release: rule.release.clone(),
                        pair: *pair,
                    });
                }
            }
            if table.contains_key(&rule.release) {
                return Err(ModeRuleError::DuplicateRelease {
                    release: rule.release,
                });
            }
            table.insert(rule.release.clone(), rule);
        }
        Ok(Self { rules: table })
    }

    /// The rules this plan records: vLLM 0.31.0 supports zero-copy preload and sleep-mode
    /// weight offloading, but not together (S7; GPU part §1.1–§1.2). The pinned vLLM
    /// 0.29.0 has no rule: adding preload flags to it is insufficient (GPU part §1.2), and
    /// no other release is assumed compatible.
    pub fn recorded() -> Self {
        let release = BackendRelease {
            backend: Backend::Vllm,
            version: BackendVersion::known("0.31.0"),
        };
        let rule = BackendModeRule {
            release: release.clone(),
            supported: BTreeSet::from([
                Optimization::ZeroCopyPreload,
                Optimization::SleepWeightOffload,
            ]),
            tested_together: BTreeSet::new(),
            conflicts: vec![DocumentedConflict {
                pair: ModePair::ordered(
                    Optimization::ZeroCopyPreload,
                    Optimization::SleepWeightOffload,
                ),
                source: VLLM_0_31_0_PRELOAD_DOC.to_owned(),
            }],
        };
        Self {
            rules: BTreeMap::from([(release, rule)]),
        }
    }

    /// The rule for exactly `release`, if one is recorded.
    pub fn rule(&self, release: &BackendRelease) -> Option<&BackendModeRule> {
        self.rules.get(release)
    }

    /// Every recorded rule, ordered by release.
    pub fn rules(&self) -> impl Iterator<Item = &BackendModeRule> {
        self.rules.values()
    }

    /// Whether `release` may run `mode` on its own. Only backend modes need a rule.
    pub fn check_mode(
        &self,
        release: &BackendRelease,
        mode: Optimization,
    ) -> Result<(), ModeRefusal> {
        if !mode.is_backend_mode() {
            return Ok(());
        }
        let rule = self.known(release)?;
        if rule.supported.contains(&mode) {
            Ok(())
        } else {
            Err(ModeRefusal::ModeNotSupported {
                release: release.clone(),
                mode,
            })
        }
    }

    /// Whether `release` may run two optimizations together. Only pairs of different
    /// switching modes are constrained, and only a tested pair is allowed.
    pub fn check_pair(
        &self,
        release: &BackendRelease,
        one: Optimization,
        other: Optimization,
    ) -> Result<(), ModeRefusal> {
        if one == other || !one.is_switching_mode() || !other.is_switching_mode() {
            return Ok(());
        }
        let pair = ModePair::ordered(one, other);
        let rule = self.known(release)?;
        if let Some(conflict) = rule.conflicts.iter().find(|conflict| conflict.pair == pair) {
            return Err(ModeRefusal::DocumentedConflict {
                release: release.clone(),
                pair,
                source: conflict.source.clone(),
            });
        }
        if rule.tested_together.contains(&pair) {
            Ok(())
        } else {
            Err(ModeRefusal::NotTestedTogether {
                release: release.clone(),
                pair,
            })
        }
    }

    /// Whether `release` may run all of `modes` at once.
    pub fn check(
        &self,
        release: &BackendRelease,
        modes: &BTreeSet<Optimization>,
    ) -> Result<(), ModeRefusal> {
        for mode in modes {
            self.check_mode(release, *mode)?;
        }
        for (index, one) in modes.iter().enumerate() {
            for other in modes.iter().skip(index + 1) {
                self.check_pair(release, *one, *other)?;
            }
        }
        Ok(())
    }

    fn known(&self, release: &BackendRelease) -> Result<&BackendModeRule, ModeRefusal> {
        self.rules
            .get(release)
            .ok_or_else(|| ModeRefusal::UnknownRelease {
                release: release.clone(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vllm(version: &str) -> BackendRelease {
        BackendRelease::new(Backend::Vllm, version).unwrap()
    }

    fn modes(list: &[Optimization]) -> BTreeSet<Optimization> {
        list.iter().copied().collect()
    }

    #[test]
    fn vllm_0_31_0_preload_and_sleep_offload_are_never_combined() {
        let rules = BackendModeRules::recorded();
        let release = vllm("0.31.0");
        let refusal = rules
            .check(
                &release,
                &modes(&[
                    Optimization::ZeroCopyPreload,
                    Optimization::SleepWeightOffload,
                ]),
            )
            .unwrap_err();
        assert!(matches!(
            &refusal,
            ModeRefusal::DocumentedConflict { source, .. } if source == VLLM_0_31_0_PRELOAD_DOC
        ));
        assert_eq!(refusal.remedy(), Remedy::UseOneModeAtATime);
        let message = refusal.to_string();
        assert!(message.contains("zero-copy preload and sleep-mode weight offloading"));
        assert!(message.contains("vLLM 0.31.0"));

        assert!(rules
            .check(&release, &modes(&[Optimization::ZeroCopyPreload]))
            .is_ok());
        assert!(rules
            .check(&release, &modes(&[Optimization::SleepWeightOffload]))
            .is_ok());
        assert!(rules
            .check(
                &release,
                &modes(&[Optimization::SleepWeightOffload, Optimization::IoUring])
            )
            .is_ok());
    }

    #[test]
    fn an_unknown_release_gets_no_assumed_compatibility() {
        let rules = BackendModeRules::recorded();
        for release in [
            vllm("0.29.0"),
            vllm("0.31.1"),
            vllm("0.31"),
            BackendRelease::new(Backend::LlamaCpp, "b4568").unwrap(),
        ] {
            for mode in [
                Optimization::ZeroCopyPreload,
                Optimization::SleepWeightOffload,
            ] {
                assert_eq!(
                    rules.check_mode(&release, mode),
                    Err(ModeRefusal::UnknownRelease {
                        release: release.clone()
                    })
                );
            }
            assert!(matches!(
                rules.check_pair(
                    &release,
                    Optimization::CudaCheckpoint,
                    Optimization::SleepWeightOffload
                ),
                Err(ModeRefusal::UnknownRelease { .. })
            ));
            assert!(rules
                .check_mode(&release, Optimization::CudaCheckpoint)
                .is_ok());
            assert!(rules.check_mode(&release, Optimization::IoUring).is_ok());
        }
    }

    #[test]
    fn untested_switching_mode_pairs_stay_separate() {
        let rules = BackendModeRules::recorded();
        let release = vllm("0.31.0");
        for mode in [
            Optimization::ZeroCopyPreload,
            Optimization::SleepWeightOffload,
        ] {
            let refusal = rules
                .check_pair(&release, Optimization::CudaCheckpoint, mode)
                .unwrap_err();
            assert!(matches!(refusal, ModeRefusal::NotTestedTogether { .. }));
        }
        assert!(rules
            .check_pair(
                &release,
                Optimization::CudaIpcLegacy,
                Optimization::GpuDirectStorage
            )
            .is_ok());
    }

    #[test]
    fn a_tested_pair_is_allowed_only_where_recorded() {
        let tested = vllm("9.9.9");
        let pair = ModePair::new(
            Optimization::SleepWeightOffload,
            Optimization::ZeroCopyPreload,
        )
        .unwrap();
        let rules = BackendModeRules::new([BackendModeRule {
            release: tested.clone(),
            supported: modes(&[
                Optimization::ZeroCopyPreload,
                Optimization::SleepWeightOffload,
            ]),
            tested_together: BTreeSet::from([pair]),
            conflicts: Vec::new(),
        }])
        .unwrap();
        assert!(rules
            .check(
                &tested,
                &modes(&[
                    Optimization::ZeroCopyPreload,
                    Optimization::SleepWeightOffload
                ])
            )
            .is_ok());
        assert!(rules
            .check(&vllm("0.31.0"), &modes(&[Optimization::ZeroCopyPreload]))
            .is_err());
    }

    #[test]
    fn rule_tables_are_validated() {
        let release = vllm("9.9.9");
        let pair = ModePair::new(
            Optimization::ZeroCopyPreload,
            Optimization::SleepWeightOffload,
        )
        .unwrap();
        let rule = |supported: &[Optimization], tested: &[ModePair], conflicts: &[ModePair]| {
            BackendModeRule {
                release: release.clone(),
                supported: modes(supported),
                tested_together: tested.iter().copied().collect(),
                conflicts: conflicts
                    .iter()
                    .map(|pair| DocumentedConflict {
                        pair: *pair,
                        source: "doc".to_owned(),
                    })
                    .collect(),
            }
        };
        let both = [
            Optimization::ZeroCopyPreload,
            Optimization::SleepWeightOffload,
        ];
        assert!(matches!(
            BackendModeRules::new([rule(&both, &[pair], &[pair])]),
            Err(ModeRuleError::TestedAndConflicting { .. })
        ));
        assert!(matches!(
            BackendModeRules::new([rule(&[Optimization::ZeroCopyPreload], &[pair], &[])]),
            Err(ModeRuleError::TestedWithoutSupport { .. })
        ));
        assert_eq!(
            BackendModeRules::new([rule(&[Optimization::IoUring], &[], &[])]),
            Err(ModeRuleError::NotABackendMode {
                optimization: Optimization::IoUring
            })
        );
        assert!(matches!(
            BackendModeRules::new([rule(&both, &[], &[]), rule(&both, &[], &[])]),
            Err(ModeRuleError::DuplicateRelease { .. })
        ));
        assert_eq!(
            ModePair::new(Optimization::IoUring, Optimization::ZeroCopyPreload),
            Err(ModeRuleError::NotASwitchingMode {
                optimization: Optimization::IoUring
            })
        );
        assert_eq!(
            ModePair::new(Optimization::CudaCheckpoint, Optimization::CudaCheckpoint),
            Err(ModeRuleError::SameMode {
                mode: Optimization::CudaCheckpoint
            })
        );
        assert!(serde_json::from_str::<ModePair>("[\"io_uring\", \"zero_copy_preload\"]").is_err());
    }

    /// Review finding 2: a custom table could mark the recorded vLLM 0.31.0 conflict as
    /// tested together, and a table without conflicts dropped it.
    #[test]
    fn no_custom_table_reopens_a_recorded_conflict() {
        let tested: BackendModeRule = serde_json::from_value(serde_json::json!({
            "release": {"backend": "vllm", "version": "0.31.0"},
            "supported": ["zero_copy_preload", "sleep_weight_offload"],
            "tested_together": [["zero_copy_preload", "sleep_weight_offload"]],
            "conflicts": []
        }))
        .unwrap();
        assert!(matches!(
            BackendModeRules::new([tested]),
            Err(ModeRuleError::TestedAndConflicting { .. })
        ));

        let silent = BackendModeRule {
            release: vllm("0.31.0"),
            supported: modes(&[
                Optimization::ZeroCopyPreload,
                Optimization::SleepWeightOffload,
            ]),
            tested_together: BTreeSet::new(),
            conflicts: Vec::new(),
        };
        let rules = BackendModeRules::new([silent]).unwrap();
        assert_eq!(rules, BackendModeRules::recorded());
        assert!(matches!(
            rules.check(
                &vllm("0.31.0"),
                &modes(&[
                    Optimization::ZeroCopyPreload,
                    Optimization::SleepWeightOffload
                ])
            ),
            Err(ModeRefusal::DocumentedConflict { source, .. }) if source == VLLM_0_31_0_PRELOAD_DOC
        ));
    }

    #[test]
    fn mode_refusals_refuse_unknown_fields() {
        let refusal = ModeRefusal::UnknownRelease {
            release: vllm("0.29.0"),
        };
        let mut json = serde_json::to_value(&refusal).unwrap();
        assert_eq!(
            serde_json::from_value::<ModeRefusal>(json.clone()).unwrap(),
            refusal
        );
        json["assumed"] = true.into();
        assert!(serde_json::from_value::<ModeRefusal>(json).is_err());
    }

    #[test]
    fn the_recorded_table_passes_its_own_validation() {
        let recorded = BackendModeRules::recorded();
        let rebuilt = BackendModeRules::new(recorded.rules().cloned()).unwrap();
        assert_eq!(rebuilt, recorded);
        for rule in recorded.rules() {
            assert_eq!(
                BackendVersion::new(rule.release.version.as_str()).as_ref(),
                Ok(&rule.release.version)
            );
            for conflict in &rule.conflicts {
                assert_eq!(
                    ModePair::new(conflict.pair.second(), conflict.pair.first()),
                    Ok(conflict.pair)
                );
            }
        }
        assert_eq!(recorded.rules().count(), 1);
        let json = serde_json::to_value(recorded.rule(&vllm("0.31.0")).unwrap()).unwrap();
        assert_eq!(
            json["conflicts"][0]["pair"],
            serde_json::json!(["zero_copy_preload", "sleep_weight_offload"])
        );
    }
}
