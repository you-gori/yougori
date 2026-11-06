//! Calibration (VM-W10 acceptance "benign tooling false positives measured; no claimed
//! probabilistic detector guarantee"; §8.2 line 2274 "Calibrate false positives ... No
//! geometric detection probability is assumed"; VM-R43; VM-R86 "controlled false-positive
//! handling").
//!
//! A [`CalibrationRecord`] holds counts and their sample sizes, nothing else. It has no
//! probability, rate, score, confidence or guarantee field and no method that returns
//! one, and reading a record with any extra field is refused. Counts describe one corpus
//! against one canary profile; they do not predict detection elsewhere.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use super::canary::{CanaryKind, SandboxBinding};
use super::observe::Observation;
use super::registry::{CanaryRegistry, ProfileDigest};
use crate::foundation::ids::{validate_identifier, Clock, Digest, DigestBuilder, IdError};

/// Most samples in one calibration.
pub const MAX_CALIBRATION_SAMPLES: usize = 4_096;
/// Most benign tools a record names as having produced hits; the rest are counted.
pub const MAX_LISTED_TOOLS: usize = 64;

const CORPUS_DOMAIN: &str = "yougori/sandbox/canary/calibration-corpus/v1";
const RECORD_DOMAIN: &str = "yougori/sandbox/canary/calibration-record/v1";

/// The name of a benign tool run or an adversarial fixture, in the ids.rs identifier
/// grammar.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct SampleName(String);

impl SampleName {
    /// Accepts the ids.rs identifier grammar.
    pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
        let value = value.into();
        validate_identifier(&value)?;
        Ok(Self(value))
    }

    /// The name as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for SampleName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for SampleName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

strict_canary_enum! {
    /// What a calibration sample is known to be.
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    pub enum SampleLabel tag "label" {
        /// Normal tooling (an editor indexing the workspace, an SDK call, a package
        /// install); any hit it produces is a false positive.
        BenignTooling {
            /// The tool run.
            tool: SampleName,
        },
        /// A harmless fixture that uses a canary as a leak would (VM-R43 "harmless
        /// fixtures"); it executes nothing.
        AdversarialFixture {
            /// The fixture.
            fixture: SampleName,
        },
    }
}

/// One labelled sample: the observations one benign run or one fixture produces.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CalibrationSample {
    /// What the sample is known to be.
    pub label: SampleLabel,
    /// The observations the run or fixture produced, all from the calibrated binding.
    pub observations: Vec<Observation>,
}

/// What a record's numbers are: counts on its corpus only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalibrationMeaning {
    /// The counts hold for this corpus and canary profile only.
    CountsOnThisCorpusOnly,
}

/// Samples of one label, those with at least one hit, and all hits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "RawSampleCounts")]
pub struct SampleCounts {
    /// Samples with this label.
    pub samples: u64,
    /// Samples that produced at least one hit.
    pub samples_with_hits: u64,
    /// Every hit those samples produced.
    pub hits: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSampleCounts {
    samples: u64,
    samples_with_hits: u64,
    hits: u64,
}

impl TryFrom<RawSampleCounts> for SampleCounts {
    type Error = String;

    fn try_from(raw: RawSampleCounts) -> Result<Self, Self::Error> {
        let consistent = raw.samples_with_hits <= raw.samples
            && raw.samples_with_hits <= raw.hits
            && (raw.samples_with_hits > 0 || raw.hits == 0);
        if !consistent {
            return Err("inconsistent sample counts".to_owned());
        }
        Ok(Self {
            samples: raw.samples,
            samples_with_hits: raw.samples_with_hits,
            hits: raw.hits,
        })
    }
}

/// Hits per canary kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KindCounts {
    /// The canary kind.
    pub kind: CanaryKind,
    /// Hits from benign tooling samples: false positives.
    pub benign_hits: u64,
    /// Hits from adversarial fixtures.
    pub adversarial_hits: u64,
}

/// A count with the sample size it was counted over. It deliberately has no ratio.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Counted {
    /// What was counted.
    pub count: u64,
    /// The samples it was counted over.
    pub sample_size: u64,
}

/// The identity of a calibration record.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CalibrationId(Digest);

impl CalibrationId {
    /// The digest the identity is.
    pub const fn digest(&self) -> &Digest {
        &self.0
    }
}

impl fmt::Debug for CalibrationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CalibrationId({})", self.0)
    }
}

/// Measured counts for one canary profile on one labelled corpus (VM-W10). Reading one
/// back refuses unknown fields and counts that do not add up.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawCalibrationRecord")]
pub struct CalibrationRecord {
    /// Always counts on this corpus only.
    pub meaning: CalibrationMeaning,
    /// The kinds and locations measured.
    pub profile: ProfileDigest,
    /// The digest of the labelled corpus.
    pub corpus: Digest,
    /// `samples_with_hits` are the false positives.
    pub benign_tooling: SampleCounts,
    /// `samples_with_hits` are the detections.
    pub adversarial_fixtures: SampleCounts,
    /// One entry per kind, in kind order.
    pub by_kind: Vec<KindCounts>,
    /// Benign tools that produced at least one hit, sorted, at most [`MAX_LISTED_TOOLS`].
    pub benign_tools_with_hits: Vec<SampleName>,
    /// Benign tools with hits beyond the listed ones.
    pub benign_tools_omitted: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCalibrationRecord {
    meaning: CalibrationMeaning,
    profile: ProfileDigest,
    corpus: Digest,
    benign_tooling: SampleCounts,
    adversarial_fixtures: SampleCounts,
    by_kind: Vec<KindCounts>,
    benign_tools_with_hits: Vec<SampleName>,
    benign_tools_omitted: u64,
}

impl TryFrom<RawCalibrationRecord> for CalibrationRecord {
    type Error = &'static str;

    fn try_from(raw: RawCalibrationRecord) -> Result<Self, Self::Error> {
        let record = Self {
            meaning: raw.meaning,
            profile: raw.profile,
            corpus: raw.corpus,
            benign_tooling: raw.benign_tooling,
            adversarial_fixtures: raw.adversarial_fixtures,
            by_kind: raw.by_kind,
            benign_tools_with_hits: raw.benign_tools_with_hits,
            benign_tools_omitted: raw.benign_tools_omitted,
        };
        record.check()?;
        Ok(record)
    }
}

impl CalibrationRecord {
    /// What [`calibrate`] guarantees: one entry per kind in kind order, per-kind hits that
    /// add up to the label totals, and a sorted tool list no longer than the benign samples
    /// with hits.
    fn check(&self) -> Result<(), &'static str> {
        let kinds: Vec<CanaryKind> = self.by_kind.iter().map(|entry| entry.kind).collect();
        if kinds != CanaryKind::ALL {
            return Err("by_kind must hold one entry per kind, in kind order");
        }
        let sum = |pick: fn(&KindCounts) -> u64| {
            self.by_kind
                .iter()
                .try_fold(0u64, |total, entry| total.checked_add(pick(entry)))
        };
        if sum(|entry| entry.benign_hits) != Some(self.benign_tooling.hits)
            || sum(|entry| entry.adversarial_hits) != Some(self.adversarial_fixtures.hits)
        {
            return Err("per-kind hits do not add up to the label totals");
        }
        let sorted = self
            .benign_tools_with_hits
            .windows(2)
            .all(|pair| matches!(pair, [first, second] if first < second));
        let listed = u64::try_from(self.benign_tools_with_hits.len()).unwrap_or(u64::MAX);
        let within_count = listed
            .checked_add(self.benign_tools_omitted)
            .is_some_and(|tools| tools <= self.benign_tooling.samples_with_hits);
        if !sorted || self.benign_tools_with_hits.len() > MAX_LISTED_TOOLS || !within_count {
            return Err("the benign tool list is unsorted, too long or larger than its count");
        }
        Ok(())
    }

    /// Benign samples with a hit, over benign samples.
    pub fn false_positives(&self) -> Counted {
        Counted {
            count: self.benign_tooling.samples_with_hits,
            sample_size: self.benign_tooling.samples,
        }
    }

    /// Adversarial fixtures with a hit, over adversarial fixtures.
    pub fn detections(&self) -> Counted {
        Counted {
            count: self.adversarial_fixtures.samples_with_hits,
            sample_size: self.adversarial_fixtures.samples,
        }
    }

    /// The record's identity, over every field.
    pub fn id(&self) -> CalibrationId {
        let counts = |builder: DigestBuilder, counts: &SampleCounts| {
            builder
                .u64(counts.samples)
                .u64(counts.samples_with_hits)
                .u64(counts.hits)
        };
        let builder = DigestBuilder::new(RECORD_DOMAIN)
            .str("counts_on_this_corpus_only")
            .digest(self.profile.digest())
            .digest(&self.corpus);
        let builder = counts(
            counts(builder, &self.benign_tooling),
            &self.adversarial_fixtures,
        );
        let builder = self.by_kind.iter().fold(
            builder.u64(u64::try_from(self.by_kind.len()).unwrap_or(u64::MAX)),
            |builder, entry| {
                builder
                    .str(entry.kind.label())
                    .u64(entry.benign_hits)
                    .u64(entry.adversarial_hits)
            },
        );
        let builder = self.benign_tools_with_hits.iter().fold(
            builder.u64(u64::try_from(self.benign_tools_with_hits.len()).unwrap_or(u64::MAX)),
            |builder, tool| builder.str(tool.as_str()),
        );
        CalibrationId(builder.u64(self.benign_tools_omitted).finish())
    }

    /// A plain statement of the counts and what they are not.
    pub fn summary(&self) -> String {
        format!(
            "benign tooling: {} of {} samples produced a canary hit ({} hits, false \
             positives); adversarial fixtures: {} of {} samples produced a canary hit ({} \
             hits). Counts on this corpus only: not a detection probability, a score or a \
             guarantee.",
            self.benign_tooling.samples_with_hits,
            self.benign_tooling.samples,
            self.benign_tooling.hits,
            self.adversarial_fixtures.samples_with_hits,
            self.adversarial_fixtures.samples,
            self.adversarial_fixtures.hits,
        )
    }
}

/// Why a calibration was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CalibrationRefusal {
    /// The binding has no plan to calibrate.
    NoPlan,
    /// Without benign samples no false positive is measured.
    NoBenignSamples,
    /// Without adversarial fixtures no detection is counted.
    NoAdversarialSamples,
    /// More than [`MAX_CALIBRATION_SAMPLES`] samples.
    TooManySamples {
        /// The bound.
        max: u64,
    },
    /// A sample with no observations measures nothing.
    EmptySample,
    /// An observation came from another binding than the one calibrated.
    ForeignObservation,
    /// A hit on a canary outside the calibrated plan.
    HitOutsidePlan,
}

impl fmt::Display for CalibrationRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoPlan => f.write_str("the binding has no canary plan"),
            Self::NoBenignSamples => {
                f.write_str("no benign tooling samples: false positives would be unmeasured")
            }
            Self::NoAdversarialSamples => f.write_str("no adversarial fixtures"),
            Self::TooManySamples { max } => write!(f, "more than {max} samples"),
            Self::EmptySample => f.write_str("a sample has no observations"),
            Self::ForeignObservation => {
                f.write_str("an observation came from another binding than the one calibrated")
            }
            Self::HitOutsidePlan => f.write_str("a hit on a canary outside the calibrated plan"),
        }
    }
}

impl std::error::Error for CalibrationRefusal {}

/// Runs every sample's observations through the matcher against `binding`'s plan and
/// counts hits per label and kind (VM-W10). Every sample must be labelled, non-empty and
/// observed in `binding`; both labels must be present.
pub fn calibrate(
    registry: &CanaryRegistry,
    binding: &SandboxBinding,
    samples: &[CalibrationSample],
    clock: &dyn Clock,
) -> Result<CalibrationRecord, CalibrationRefusal> {
    let profile = registry
        .plan_profile(binding)
        .ok_or(CalibrationRefusal::NoPlan)?;
    if samples.len() > MAX_CALIBRATION_SAMPLES {
        return Err(CalibrationRefusal::TooManySamples {
            max: u64::try_from(MAX_CALIBRATION_SAMPLES).unwrap_or(u64::MAX),
        });
    }
    let is_benign =
        |sample: &CalibrationSample| matches!(sample.label, SampleLabel::BenignTooling { .. });
    if !samples.iter().any(is_benign) {
        return Err(CalibrationRefusal::NoBenignSamples);
    }
    if samples.iter().all(is_benign) {
        return Err(CalibrationRefusal::NoAdversarialSamples);
    }

    let mut benign = SampleCounts::default();
    let mut adversarial = SampleCounts::default();
    let mut by_kind: BTreeMap<CanaryKind, (u64, u64)> =
        CanaryKind::ALL.iter().map(|kind| (*kind, (0, 0))).collect();
    let mut tools = std::collections::BTreeSet::new();
    let mut corpus =
        DigestBuilder::new(CORPUS_DOMAIN).u64(u64::try_from(samples.len()).unwrap_or(u64::MAX));

    for sample in samples {
        if sample.observations.is_empty() {
            return Err(CalibrationRefusal::EmptySample);
        }
        corpus = match &sample.label {
            SampleLabel::BenignTooling { tool } => corpus.str("benign_tooling").str(tool.as_str()),
            SampleLabel::AdversarialFixture { fixture } => {
                corpus.str("adversarial_fixture").str(fixture.as_str())
            }
        }
        .u64(u64::try_from(sample.observations.len()).unwrap_or(u64::MAX));
        let mut sample_hits = 0u64;
        for observation in &sample.observations {
            if observation.origin() != binding {
                return Err(CalibrationRefusal::ForeignObservation);
            }
            corpus = corpus
                .str(observation.source().label())
                .digest(&observation.digest());
            let report = registry.match_observation(observation, clock);
            if report.omitted_hits > 0 || report.hits.iter().any(|hit| hit.planted_in() != binding)
            {
                return Err(CalibrationRefusal::HitOutsidePlan);
            }
            for hit in &report.hits {
                if let Some(entry) = by_kind.get_mut(&hit.kind()) {
                    if is_benign(sample) {
                        entry.0 = entry.0.saturating_add(1);
                    } else {
                        entry.1 = entry.1.saturating_add(1);
                    }
                }
            }
            sample_hits = sample_hits.saturating_add(report.total_hits());
        }
        let counts = if is_benign(sample) {
            &mut benign
        } else {
            &mut adversarial
        };
        counts.samples = counts.samples.saturating_add(1);
        counts.hits = counts.hits.saturating_add(sample_hits);
        if sample_hits > 0 {
            counts.samples_with_hits = counts.samples_with_hits.saturating_add(1);
            if let SampleLabel::BenignTooling { tool } = &sample.label {
                tools.insert(tool.clone());
            }
        }
    }

    let listed: Vec<SampleName> = tools.iter().take(MAX_LISTED_TOOLS).cloned().collect();
    let omitted = tools.len().saturating_sub(listed.len());
    Ok(CalibrationRecord {
        meaning: CalibrationMeaning::CountsOnThisCorpusOnly,
        profile,
        corpus: corpus.finish(),
        benign_tooling: benign,
        adversarial_fixtures: adversarial,
        by_kind: by_kind
            .into_iter()
            .map(|(kind, (benign_hits, adversarial_hits))| KindCounts {
                kind,
                benign_hits,
                adversarial_hits,
            })
            .collect(),
        benign_tools_with_hits: listed,
        benign_tools_omitted: u64::try_from(omitted).unwrap_or(u64::MAX),
    })
}
