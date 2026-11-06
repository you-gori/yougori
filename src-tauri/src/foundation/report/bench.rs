//! BENCH-01–BENCH-13 identifiers, the per-profile applicability record (S11:
//! "Inapplicable hardware, unavailable vendor reference APIs and untested combinations
//! are recorded as such") and the BENCH-13 reproducibility record.

use std::collections::BTreeSet;

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

use super::claims::ThirdPartyClaim;
use super::error::ReportError;
use super::events::IntervalKind;
use super::ledger::AttemptLedger;
use super::measured::NonNegative;
use super::record::{RunRecord, RunSubstrate};
use super::stats::{
    ConfidenceLevel, LatencySummary, PercentileMethod, Quantile, Resolution,
    MIN_INDEPENDENT_BURSTS, MIN_TAIL_SAMPLES,
};
use super::text::Label;
use super::SchemaVersion;
use crate::foundation::ids::{Digest, DigestBuilder};

/// Domain of [`ReproducibilityRecord::digest`].
pub const REPRODUCIBILITY_DIGEST_DOMAIN: &str = "yougori/report/bench-13/v1";

/// BENCH-01 loads before the measured saturation point (S7, S11).
pub const BENCH_01_CONCURRENCY_LEVELS: [u32; 3] = [1, 8, 32];

/// The S11 evaluation cases. They reuse this report schema and create no production
/// component (S1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BenchId {
    #[serde(rename = "BENCH-01")]
    Bench01,
    #[serde(rename = "BENCH-02")]
    Bench02,
    #[serde(rename = "BENCH-03")]
    Bench03,
    #[serde(rename = "BENCH-04")]
    Bench04,
    #[serde(rename = "BENCH-05")]
    Bench05,
    #[serde(rename = "BENCH-06")]
    Bench06,
    #[serde(rename = "BENCH-07")]
    Bench07,
    #[serde(rename = "BENCH-08")]
    Bench08,
    #[serde(rename = "BENCH-09")]
    Bench09,
    #[serde(rename = "BENCH-10")]
    Bench10,
    #[serde(rename = "BENCH-11")]
    Bench11,
    #[serde(rename = "BENCH-12")]
    Bench12,
    #[serde(rename = "BENCH-13")]
    Bench13,
}

impl BenchId {
    /// BENCH-01 to BENCH-13 in order.
    pub const ALL: [Self; 13] = [
        Self::Bench01,
        Self::Bench02,
        Self::Bench03,
        Self::Bench04,
        Self::Bench05,
        Self::Bench06,
        Self::Bench07,
        Self::Bench08,
        Self::Bench09,
        Self::Bench10,
        Self::Bench11,
        Self::Bench12,
        Self::Bench13,
    ];

    pub const fn code(self) -> &'static str {
        match self {
            Self::Bench01 => "BENCH-01",
            Self::Bench02 => "BENCH-02",
            Self::Bench03 => "BENCH-03",
            Self::Bench04 => "BENCH-04",
            Self::Bench05 => "BENCH-05",
            Self::Bench06 => "BENCH-06",
            Self::Bench07 => "BENCH-07",
            Self::Bench08 => "BENCH-08",
            Self::Bench09 => "BENCH-09",
            Self::Bench10 => "BENCH-10",
            Self::Bench11 => "BENCH-11",
            Self::Bench12 => "BENCH-12",
            Self::Bench13 => "BENCH-13",
        }
    }

    /// The S11 case, in brief.
    pub const fn case(self) -> &'static str {
        match self {
            Self::Bench01 => {
                "compatible engine modes at load 1, 8 and 32, then measured saturation"
            }
            Self::Bench02 => "A/B/A model switches across the modes each runtime supports",
            Self::Bench03 => "agent, model, dialect and streaming protocol conformance",
            Self::Bench04 => "paired reference and controlled baseline fidelity",
            Self::Bench05 => {
                "sequential, staggered and burst VM creates on the first-command clock"
            }
            Self::Bench06 => "cold VM, limited warm pool, clean snapshot and pool depletion",
            Self::Bench07 => "repeated switches and wakes and a multi-day soak",
            Self::Bench08 => "cost curve at fixed model, mix, user speed and concurrency",
            Self::Bench09 => "supported operating systems and consumer GPU configurations",
            Self::Bench10 => "an existing Hub setup on each supported fresh environment",
            Self::Bench11 => "removal of that disposable setup",
            Self::Bench12 => "optional local foreground return",
            Self::Bench13 => "independent reproducibility of a shared benchmark claim",
        }
    }

    /// The owning packages S11 names.
    pub const fn owners(self) -> &'static [&'static str] {
        match self {
            Self::Bench01 | Self::Bench08 => &["GPU-W00", "GPU-W11", "CORE-03"],
            Self::Bench02 => &["GPU-W01", "GPU-W05"],
            Self::Bench03 => &["GPU-W11", "VM-W32", "CORE-07"],
            Self::Bench04 => &["GPU-W00", "GPU-W11", "CORE-08"],
            Self::Bench05 => &["VM-W24", "VM-W26", "VM-W49", "VM-W51"],
            Self::Bench06 => &["VM-W27", "VM-W29", "VM-CP-21"],
            Self::Bench07 => &["GPU-W05", "GPU-W10", "CORE-06"],
            Self::Bench09 => &["GPU-W00", "GPU-W11", "VM-W23"],
            Self::Bench10 => &["CORE-07", "CORE-08", "VM-W56"],
            Self::Bench11 => &["VM-W24", "VM-W56", "CORE-07"],
            Self::Bench12 => &["GPU-W05", "CORE-03", "CORE-04"],
            Self::Bench13 => &["CORE-08", "EVIDENCE"],
        }
    }
}

strict_tagged_enum! {
/// Whether a case applies to a release profile, and why not when it does not (S11, S12).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Applicability (tag = "kind", wire = ApplicabilityWire, wire_name = "ApplicabilityWire") {
    Selected,
    InapplicableHardware { requirement: Label },
    ReferenceUnavailable { reference: Label },
    UntestedCombination { combination: Label },
    /// S12: e.g. a local model runner needs no 1,000-VM stress result.
    NotRequiredByProfile { reason: Label },
}
}

/// One case's applicability to a release profile (S11).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicabilityEntry {
    pub bench: BenchId,
    pub applicability: Applicability,
}

/// Every BENCH case for one release profile, each recorded exactly once, so a skipped
/// case is reported rather than silently missing (S2 CORE-08: "skipped hardware checks
/// are reported consistently").
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ApplicabilityMatrixWire")]
pub struct ApplicabilityMatrix {
    release_profile: Label,
    entries: Vec<ApplicabilityEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplicabilityMatrixWire {
    release_profile: Label,
    entries: Vec<ApplicabilityEntry>,
}

impl TryFrom<ApplicabilityMatrixWire> for ApplicabilityMatrix {
    type Error = ReportError;

    fn try_from(wire: ApplicabilityMatrixWire) -> Result<Self, Self::Error> {
        Self::new(wire.release_profile, wire.entries)
    }
}

impl ApplicabilityMatrix {
    /// Refuses a case recorded twice or missing, so every case is accounted for.
    pub fn new(
        release_profile: Label,
        mut entries: Vec<ApplicabilityEntry>,
    ) -> Result<Self, ReportError> {
        let mut seen = BTreeSet::new();
        for entry in &entries {
            if !seen.insert(entry.bench) {
                return Err(ReportError::DuplicateApplicability { bench: entry.bench });
            }
        }
        if let Some(missing) = BenchId::ALL.iter().find(|bench| !seen.contains(bench)) {
            return Err(ReportError::IncompleteApplicability { missing: *missing });
        }
        entries.sort_by_key(|entry| entry.bench);
        Ok(Self {
            release_profile,
            entries,
        })
    }

    pub fn release_profile(&self) -> &Label {
        &self.release_profile
    }

    pub fn entries(&self) -> &[ApplicabilityEntry] {
        &self.entries
    }

    pub fn get(&self, bench: BenchId) -> Option<&Applicability> {
        self.entries
            .iter()
            .find(|entry| entry.bench == bench)
            .map(|entry| &entry.applicability)
    }

    /// The cases the profile selected.
    pub fn selected(&self) -> impl Iterator<Item = BenchId> + '_ {
        self.entries
            .iter()
            .filter(|entry| entry.applicability == Applicability::Selected)
            .map(|entry| entry.bench)
    }
}

/// The claim a BENCH-13 record reproduces.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[serde(remote = "Self")]
pub enum ClaimUnderTest {
    /// A Yougori benchmark claim, stated as a label.
    Yougori { bench: BenchId, statement: Label },
    /// A published third-party claim with its date, source and configuration, and how
    /// the record compares its value with the record's own measurement.
    ThirdParty {
        bench: BenchId,
        claim: ThirdPartyClaim,
        comparison: ClaimComparison,
    },
}

crate::foundation::strict_serde::strict_tag!(ClaimUnderTest, "kind");

impl ClaimUnderTest {
    pub fn bench(&self) -> BenchId {
        match self {
            Self::Yougori { bench, .. } | Self::ThirdParty { bench, .. } => *bench,
        }
    }
}

strict_tagged_enum! {
/// A statistic a BENCH-13 record measured, to which a reproduced claim or a release
/// requirement is bound (BENCH-13; S11 "no unverified third-party score becomes a release
/// requirement").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordStatistic (tag = "kind", wire = RecordStatisticWire, wire_name = "RecordStatisticWire") {
    /// A reported percentile of one declared interval over the successful initial
    /// attempts, in nanoseconds; it must be resolved (S8, S11).
    Percentile { interval: IntervalKind, quantile: Quantile },
    /// The success rate over every initial attempt, as a fraction (S8).
    SuccessRate,
}
}

/// The unit a third-party claim states its value in (BENCH-13 comparison).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimUnit {
    Nanoseconds,
    Microseconds,
    Milliseconds,
    Seconds,
    Fraction,
    Percent,
}

impl ClaimUnit {
    /// The label a claim must state this unit with.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Nanoseconds => "ns",
            Self::Microseconds => "us",
            Self::Milliseconds => "ms",
            Self::Seconds => "s",
            Self::Fraction => "fraction",
            Self::Percent => "percent",
        }
    }

    /// The factor from this unit to the statistic's own: nanoseconds for a percentile, a
    /// fraction for a success rate.
    pub const fn to_statistic(self) -> f64 {
        match self {
            Self::Nanoseconds | Self::Fraction => 1.0,
            Self::Microseconds => 1e3,
            Self::Milliseconds => 1e6,
            Self::Seconds => 1e9,
            Self::Percent => 0.01,
        }
    }

    /// Time units fit a percentile; a fraction or percentage fits a success rate.
    pub const fn fits(self, statistic: RecordStatistic) -> bool {
        match statistic {
            RecordStatistic::Percentile { .. } => matches!(
                self,
                Self::Nanoseconds | Self::Microseconds | Self::Milliseconds | Self::Seconds
            ),
            RecordStatistic::SuccessRate => matches!(self, Self::Fraction | Self::Percent),
        }
    }
}

/// How a BENCH-13 record compares a third-party claim with its own measurement, declared
/// in the record: which statistic reproduces the claim, the claim's unit, and the relative
/// tolerance within which the measured value reproduces the claimed one.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimComparison {
    pub statistic: RecordStatistic,
    pub unit: ClaimUnit,
    pub relative_tolerance: NonNegative,
}

impl ClaimComparison {
    /// The claim must state its value in this comparison's unit, the unit must fit the
    /// statistic, and the statistic must be one the record reports: a declared interval
    /// at a reported percentile.
    fn check(
        &self,
        claim: &ThirdPartyClaim,
        method: &StatisticalMethod,
    ) -> Result<(), ReportError> {
        if claim.unit.as_str() != self.unit.label() || !self.unit.fits(self.statistic) {
            return Err(ReportError::ClaimUnitMismatch);
        }
        match self.statistic {
            RecordStatistic::Percentile { interval, quantile }
                if !method.intervals.contains(&interval)
                    || !Quantile::REPORTED.contains(&quantile) =>
            {
                Err(ReportError::StatisticNotInRecord)
            }
            _ => Ok(()),
        }
    }
}

/// The statistical method a record used (BENCH-13). The resolution thresholds and the
/// Wilson level are those of this schema version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatisticalMethod {
    pub percentile_method: PercentileMethod,
    pub intervals: Vec<IntervalKind>,
    pub success_rate_interval: ConfidenceLevel,
    pub min_tail_samples: u64,
    pub min_independent_bursts: u64,
}

impl StatisticalMethod {
    /// The method of this schema version for `intervals`: 95% Wilson intervals and the
    /// resolution thresholds of [`MIN_TAIL_SAMPLES`] and [`MIN_INDEPENDENT_BURSTS`].
    pub fn new(percentile_method: PercentileMethod, intervals: Vec<IntervalKind>) -> Self {
        Self {
            percentile_method,
            intervals,
            success_rate_interval: ConfidenceLevel::NinetyFive,
            min_tail_samples: MIN_TAIL_SAMPLES,
            min_independent_bursts: MIN_INDEPENDENT_BURSTS,
        }
    }

    fn check(&self) -> Result<(), ReportError> {
        if self.intervals.is_empty() {
            return Err(ReportError::NoIntervalsDeclared);
        }
        let current = Self::new(self.percentile_method, self.intervals.clone());
        if *self == current {
            Ok(())
        } else {
            Err(ReportError::StatisticalMethodMismatch)
        }
    }
}

/// The kinds of BENCH-13 limitation; the first three are derived from the raw records.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitationKind {
    LowResolutionTail,
    FakeRunner,
    NoSuccessfulRuns,
    ReferenceUnavailable,
    InapplicableHardware,
    UntestedCombination,
    NonEquivalentConfiguration,
    Other,
}

/// A limitation of a reproduction (BENCH-13 "limitations").
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limitation {
    pub kind: LimitationKind,
    pub detail: Label,
}

/// S12: "Publishable BENCH-13 output requires a separate review for data licensing,
/// permitted disclosure and current comparison evidence."
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationReview {
    pub reviewer: Label,
    pub reviewed_on: NaiveDate,
    pub data_licensing_cleared: bool,
    pub disclosure_permitted: bool,
    pub comparison_evidence_current: bool,
}

strict_tagged_enum! {
/// Publishing itself is a separate authorized release action (S7); this only records
/// whether the review happened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicationStatus (tag = "kind", wire = PublicationStatusWire, wire_name = "PublicationStatusWire") {
    Internal,
    Reviewed { review: PublicationReview },
}
}

/// BENCH-13: "Raw events and failures, configuration and fixture hashes, statistical
/// method, source/date, untrimmed distributions and limitations."
///
/// The digests, distributions and derived limitations are computed from the raw records
/// and recomputed when a record is read, so a trimmed or edited record is refused.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "ReproducibilityRecordWire")]
pub struct ReproducibilityRecord {
    schema_version: SchemaVersion,
    claim: ClaimUnderTest,
    method: StatisticalMethod,
    reproduced_on: NaiveDate,
    /// The harness build that produced the raw records.
    harness: Digest,
    /// Every attempt, failed ones and retries included, with raw events.
    raw_records: Vec<RunRecord>,
    configuration_digests: Vec<Digest>,
    fixture_digests: Vec<Digest>,
    /// One untrimmed summary per declared interval.
    distributions: Vec<LatencySummary>,
    limitations: Vec<Limitation>,
    publication: PublicationStatus,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReproducibilityRecordWire {
    schema_version: SchemaVersion,
    claim: ClaimUnderTest,
    method: StatisticalMethod,
    reproduced_on: NaiveDate,
    harness: Digest,
    raw_records: Vec<RunRecord>,
    configuration_digests: Vec<Digest>,
    fixture_digests: Vec<Digest>,
    distributions: Vec<LatencySummary>,
    limitations: Vec<Limitation>,
    publication: PublicationStatus,
}

impl TryFrom<ReproducibilityRecordWire> for ReproducibilityRecord {
    type Error = ReportError;

    fn try_from(wire: ReproducibilityRecordWire) -> Result<Self, Self::Error> {
        // The version was checked when the field was read.
        let SchemaVersion = wire.schema_version;
        let mut rebuilt = Self::new(
            wire.claim,
            wire.method,
            wire.reproduced_on,
            wire.harness,
            wire.raw_records,
            wire.limitations.clone(),
        )?;
        if rebuilt.configuration_digests != wire.configuration_digests
            || rebuilt.fixture_digests != wire.fixture_digests
            || rebuilt.distributions != wire.distributions
            || rebuilt.limitations != wire.limitations
        {
            return Err(ReportError::InconsistentRecord);
        }
        if let PublicationStatus::Reviewed { review } = wire.publication {
            rebuilt = rebuilt.with_publication_review(review)?;
        }
        Ok(rebuilt)
    }
}

impl ReproducibilityRecord {
    /// Reads a record from JSON, recomputing what it derives from its raw records. A
    /// record of another schema version is refused with
    /// [`ReportError::UnsupportedSchemaVersion`] and never reinterpreted; a refused
    /// record keeps its own typed error, and text that does not parse as a record is
    /// [`ReportError::Malformed`].
    pub fn from_json(json: &str) -> Result<Self, ReportError> {
        super::check_schema_version(json)?;
        let wire: ReproducibilityRecordWire =
            serde_json::from_str(json).map_err(super::malformed)?;
        Self::try_from(wire)
    }

    /// Builds the record from every raw attempt of one case variant. The records must
    /// belong to the claim's case; a third-party claim must be well formed, and its
    /// comparison must name a statistic the record reports in a unit that fits it.
    pub fn new(
        claim: ClaimUnderTest,
        method: StatisticalMethod,
        reproduced_on: NaiveDate,
        harness: Digest,
        raw_records: Vec<RunRecord>,
        declared_limitations: Vec<Limitation>,
    ) -> Result<Self, ReportError> {
        method.check()?;
        if let ClaimUnderTest::ThirdParty {
            claim, comparison, ..
        } = &claim
        {
            claim.check()?;
            comparison.check(claim, &method)?;
        }
        if raw_records
            .iter()
            .any(|record| record.attempt.bench != claim.bench())
        {
            return Err(ReportError::ReproductionMismatch);
        }
        let ledger = AttemptLedger::from_records(raw_records.iter().cloned())?;
        if ledger.is_empty() {
            return Err(ReportError::NoAttempts);
        }
        let distributions = method
            .intervals
            .iter()
            .map(|interval| {
                LatencySummary::from_ledger(&ledger, *interval, method.percentile_method)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let configuration_digests = raw_records
            .iter()
            .map(RunRecord::configuration_digest)
            .collect::<Result<BTreeSet<_>, _>>()?
            .into_iter()
            .collect();
        let fixture_digests = raw_records
            .iter()
            .flat_map(RunRecord::fixtures)
            .map(|fixture| fixture.digest)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let mut limitations: BTreeSet<Limitation> = declared_limitations.into_iter().collect();
        if raw_records
            .iter()
            .any(|record| record.substrate == RunSubstrate::FakeTimeControlled)
        {
            limitations.insert(Limitation {
                kind: LimitationKind::FakeRunner,
                detail: Label::new("fake-time-controlled-runner")?,
            });
        }
        for summary in &distributions {
            if summary.success_rate().successes() == 0 {
                limitations.insert(Limitation {
                    kind: LimitationKind::NoSuccessfulRuns,
                    detail: Label::new(summary.interval().as_str())?,
                });
            }
            for estimate in summary.percentiles() {
                if matches!(estimate.resolution, Resolution::LowResolution { .. }) {
                    limitations.insert(Limitation {
                        kind: LimitationKind::LowResolutionTail,
                        detail: Label::new(format!(
                            "{}-p{}",
                            summary.interval().as_str(),
                            estimate.quantile.basis_points()
                        ))?,
                    });
                }
            }
        }
        Ok(Self {
            schema_version: SchemaVersion,
            claim,
            method,
            reproduced_on,
            harness,
            raw_records,
            configuration_digests,
            fixture_digests,
            distributions,
            limitations: limitations.into_iter().collect(),
            publication: PublicationStatus::Internal,
        })
    }

    /// Records a completed publication review. Every review question must be cleared,
    /// the review cannot precede the reproduction, and every fixture must be
    /// publishable (S8, S12).
    pub fn with_publication_review(
        mut self,
        review: PublicationReview,
    ) -> Result<Self, ReportError> {
        if !(review.data_licensing_cleared
            && review.disclosure_permitted
            && review.comparison_evidence_current)
            || review.reviewed_on < self.reproduced_on
        {
            return Err(ReportError::PublicationReviewIncomplete);
        }
        for record in &self.raw_records {
            record.check_publishable()?;
        }
        self.publication = PublicationStatus::Reviewed { review };
        Ok(self)
    }

    pub fn claim(&self) -> &ClaimUnderTest {
        &self.claim
    }

    pub fn method(&self) -> &StatisticalMethod {
        &self.method
    }

    pub fn raw_records(&self) -> &[RunRecord] {
        &self.raw_records
    }

    pub fn configuration_digests(&self) -> &[Digest] {
        &self.configuration_digests
    }

    pub fn fixture_digests(&self) -> &[Digest] {
        &self.fixture_digests
    }

    pub fn distributions(&self) -> &[LatencySummary] {
        &self.distributions
    }

    pub fn limitations(&self) -> &[Limitation] {
        &self.limitations
    }

    pub fn publication(&self) -> &PublicationStatus {
        &self.publication
    }

    /// The value of `statistic` as this record measured it, from its untrimmed
    /// distributions: a resolved percentile in nanoseconds (a low-resolution one is
    /// refused, S8, S11) or the success rate over every initial attempt.
    pub fn statistic(&self, statistic: RecordStatistic) -> Result<f64, ReportError> {
        match statistic {
            RecordStatistic::Percentile { interval, quantile } => {
                let estimate = self
                    .distributions
                    .iter()
                    .find(|summary| summary.interval() == interval)
                    .and_then(|summary| summary.percentile(quantile))
                    .ok_or(ReportError::StatisticNotInRecord)?;
                let value = *estimate
                    .value_nanos
                    .value()
                    .ok_or(ReportError::NoSuccessfulRuns)?;
                match estimate.resolution {
                    Resolution::Resolved => Ok(value),
                    Resolution::LowResolution {
                        tail_samples,
                        bursts,
                        ..
                    } => Err(ReportError::LowResolution {
                        tail_samples,
                        bursts,
                    }),
                }
            }
            RecordStatistic::SuccessRate => self
                .distributions
                .first()
                .map(|summary| summary.success_rate().rate())
                .ok_or(ReportError::StatisticNotInRecord),
        }
    }

    /// The identity of this record, for provenance (BENCH-13).
    pub fn digest(&self) -> Result<Digest, ReportError> {
        serde_json::to_vec(self)
            .map(|bytes| {
                DigestBuilder::new(REPRODUCIBILITY_DIGEST_DOMAIN)
                    .bytes(&bytes)
                    .finish()
            })
            .map_err(|_| ReportError::Encoding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::digest;
    use crate::foundation::report::claims::{ClaimConfiguration, ConfigurationEntry, Provenance};
    use crate::foundation::report::fixtures::{
        failed, label, real_serving_records, reproduction, serving_record, vendor_claim,
    };
    use crate::foundation::report::measured::{Measured, NonNegative};
    use crate::foundation::report::record::FailureKind;
    use crate::foundation::report::text::Disclosure;
    use crate::foundation::report::SCHEMA_VERSION;

    #[test]
    fn bench_identifiers_are_stable() {
        for (index, bench) in BenchId::ALL.iter().enumerate() {
            assert_eq!(bench.code(), format!("BENCH-{:02}", index + 1));
            assert_eq!(
                serde_json::to_string(bench).unwrap(),
                format!("\"{}\"", bench.code())
            );
            assert!(!bench.owners().is_empty());
            assert!(!bench.case().is_empty());
        }
        assert_eq!(BENCH_01_CONCURRENCY_LEVELS, [1, 8, 32]);
        assert!(BenchId::Bench13.owners().contains(&"CORE-08"));
        assert!(serde_json::from_str::<BenchId>("\"BENCH-14\"").is_err());
    }

    fn full_matrix() -> Vec<ApplicabilityEntry> {
        BenchId::ALL
            .iter()
            .map(|bench| ApplicabilityEntry {
                bench: *bench,
                applicability: match bench {
                    BenchId::Bench04 => Applicability::ReferenceUnavailable {
                        reference: label("vendor-reference-api"),
                    },
                    BenchId::Bench05 | BenchId::Bench06 => Applicability::NotRequiredByProfile {
                        reason: label("local-model-runner-profile"),
                    },
                    BenchId::Bench09 => Applicability::InapplicableHardware {
                        requirement: label("amd-rocm-gpu"),
                    },
                    BenchId::Bench12 => Applicability::UntestedCombination {
                        combination: label("wsl2-display-gpu-return"),
                    },
                    _ => Applicability::Selected,
                },
            })
            .collect()
    }

    #[test]
    fn every_case_is_recorded_even_when_skipped() {
        let matrix = ApplicabilityMatrix::new(label("local-model-runner"), full_matrix()).unwrap();
        assert_eq!(matrix.entries().len(), 13);
        assert_eq!(
            matrix.get(BenchId::Bench09),
            Some(&Applicability::InapplicableHardware {
                requirement: label("amd-rocm-gpu")
            })
        );
        assert!(!matrix.selected().any(|bench| bench == BenchId::Bench04));

        let mut missing = full_matrix();
        missing.retain(|entry| entry.bench != BenchId::Bench12);
        assert_eq!(
            ApplicabilityMatrix::new(label("p"), missing),
            Err(ReportError::IncompleteApplicability {
                missing: BenchId::Bench12
            })
        );
        let mut duplicated = full_matrix();
        duplicated.push(duplicated[0].clone());
        assert_eq!(
            ApplicabilityMatrix::new(label("p"), duplicated),
            Err(ReportError::DuplicateApplicability {
                bench: BenchId::Bench01
            })
        );
        let json = serde_json::to_value(&matrix).unwrap();
        assert_eq!(
            serde_json::from_value::<ApplicabilityMatrix>(json.clone()).unwrap(),
            matrix
        );
        let mut truncated = json;
        truncated["entries"].as_array_mut().unwrap().pop();
        assert!(serde_json::from_value::<ApplicabilityMatrix>(truncated).is_err());
    }

    fn raw_records() -> Vec<RunRecord> {
        let mut records: Vec<RunRecord> = (0..6)
            .map(|index| {
                let mut record = serving_record(&format!("op-{index}"), 100 + 10 * index as u64);
                record.attempt.burst = index as u32 % 3;
                record
            })
            .collect();
        let mut rejected = serving_record("op-rejected", 100);
        rejected.outcome = failed(FailureKind::Rejected);
        rejected.events.truncate(1);
        records.push(rejected);
        records
    }

    fn yougori_record() -> ReproducibilityRecord {
        ReproducibilityRecord::new(
            ClaimUnderTest::Yougori {
                bench: BenchId::Bench01,
                statement: label("ttft-at-load-8"),
            },
            StatisticalMethod::new(
                PercentileMethod::NearestRank,
                vec![IntervalKind::TimeToFirstToken, IntervalKind::QueueWait],
            ),
            NaiveDate::from_ymd_opt(2026, 10, 27).unwrap(),
            digest("yougori/test/v1", &[b"harness"]),
            raw_records(),
            vec![],
        )
        .unwrap()
    }

    #[test]
    fn the_record_keeps_raw_failures_digests_method_and_untrimmed_distributions() {
        let record = yougori_record();
        assert_eq!(record.raw_records().len(), 7);
        assert!(record.raw_records().iter().any(|run| !run.is_success()));
        assert_eq!(record.configuration_digests().len(), 1);
        assert_eq!(record.fixture_digests().len(), 1);
        let ttft = &record.distributions()[0];
        assert_eq!(ttft.samples().len(), 6);
        assert_eq!(ttft.success_rate().attempts(), 7);
        assert_eq!(ttft.failures().rejected, 1);
        assert!(record
            .limitations()
            .iter()
            .any(|limitation| limitation.kind == LimitationKind::FakeRunner));
        assert!(record.limitations().iter().any(|limitation| {
            limitation.kind == LimitationKind::LowResolutionTail
                && limitation.detail.as_str() == "time_to_first_token-p9900"
        }));
        assert_eq!(record.method().min_tail_samples, MIN_TAIL_SAMPLES);
    }

    #[test]
    fn digests_survive_a_round_trip_with_awkward_numbers() {
        // Values that serde_json's default number parsing reads back one unit in the
        // last place off; written as canonical strings they read back exactly.
        let records: Vec<RunRecord> = raw_records()
            .into_iter()
            .map(|mut record| {
                if let Measured::Measured { value } = &mut record.workload {
                    value.sampling.temperature = NonNegative::new(0.1 + 0.2).unwrap();
                }
                record.measurements.prefill_tokens_per_second =
                    Measured::measured(NonNegative::new(55350.263109369596).unwrap());
                record
            })
            .collect();
        let record = ReproducibilityRecord::new(
            ClaimUnderTest::Yougori {
                bench: BenchId::Bench01,
                statement: label("ttft"),
            },
            StatisticalMethod::new(
                PercentileMethod::NearestRank,
                vec![IntervalKind::TimeToFirstToken],
            ),
            NaiveDate::from_ymd_opt(2026, 10, 27).unwrap(),
            digest("yougori/test/v1", &[b"harness"]),
            records,
            vec![],
        )
        .unwrap();
        let text = serde_json::to_string(&record).unwrap();
        let read: ReproducibilityRecord = serde_json::from_str(&text).unwrap();
        assert_eq!(read, record);
        assert_eq!(read.digest().unwrap(), record.digest().unwrap());
        assert_eq!(serde_json::to_string(&read).unwrap(), text);
    }

    #[test]
    fn a_record_round_trips_and_refuses_tampering() {
        let record = yougori_record();
        let json = serde_json::to_value(&record).unwrap();
        let read: ReproducibilityRecord = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(read.distributions(), record.distributions());
        assert_eq!(read.digest().unwrap(), record.digest().unwrap());

        // Dropping a failed attempt changes the denominators: refused.
        let mut without_failure = json.clone();
        without_failure["raw_records"].as_array_mut().unwrap().pop();
        assert!(serde_json::from_value::<ReproducibilityRecord>(without_failure).is_err());
        // Trimming the slowest sample from a stored distribution: refused.
        let mut trimmed = json.clone();
        trimmed["distributions"][0]["samples"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert!(serde_json::from_value::<ReproducibilityRecord>(trimmed).is_err());
        // Removing a derived limitation: refused.
        let mut unlimited = json.clone();
        unlimited["limitations"] = serde_json::json!([]);
        assert!(serde_json::from_value::<ReproducibilityRecord>(unlimited).is_err());
        // A record of another schema version is not read as this one.
        for other in [SCHEMA_VERSION - 1, SCHEMA_VERSION + 1] {
            let mut versioned = json.clone();
            versioned["schema_version"] = other.into();
            assert!(serde_json::from_value::<ReproducibilityRecord>(versioned).is_err());
        }
    }

    #[test]
    fn records_must_match_the_claimed_case_and_method() {
        let mut other_case = raw_records();
        other_case[0].attempt.bench = BenchId::Bench02;
        assert!(ReproducibilityRecord::new(
            ClaimUnderTest::Yougori {
                bench: BenchId::Bench01,
                statement: label("ttft"),
            },
            StatisticalMethod::new(
                PercentileMethod::NearestRank,
                vec![IntervalKind::TimeToFirstToken]
            ),
            NaiveDate::from_ymd_opt(2026, 10, 27).unwrap(),
            digest("yougori/test/v1", &[b"harness"]),
            other_case,
            vec![],
        )
        .is_err());
        let mut method = StatisticalMethod::new(
            PercentileMethod::NearestRank,
            vec![IntervalKind::TimeToFirstToken],
        );
        method.min_tail_samples = 1;
        assert_eq!(method.check(), Err(ReportError::StatisticalMethodMismatch));
        assert_eq!(
            StatisticalMethod::new(PercentileMethod::NearestRank, vec![]).check(),
            Err(ReportError::NoIntervalsDeclared)
        );
    }

    #[test]
    fn publication_needs_a_complete_review_and_public_fixtures() {
        let review = PublicationReview {
            reviewer: label("evidence-owner"),
            reviewed_on: NaiveDate::from_ymd_opt(2026, 10, 28).unwrap(),
            data_licensing_cleared: true,
            disclosure_permitted: true,
            comparison_evidence_current: false,
        };
        assert_eq!(
            yougori_record().with_publication_review(review.clone()),
            Err(ReportError::PublicationReviewIncomplete)
        );
        let cleared = PublicationReview {
            comparison_evidence_current: true,
            ..review
        };
        let published = yougori_record()
            .with_publication_review(cleared.clone())
            .unwrap();
        assert!(matches!(
            published.publication(),
            PublicationStatus::Reviewed { .. }
        ));
        let json = serde_json::to_value(&published).unwrap();
        assert!(serde_json::from_value::<ReproducibilityRecord>(json).is_ok());

        let mut private = raw_records();
        if let Measured::Measured { value } = &mut private[0].workload {
            value.fixture.disclosure = Disclosure::Private;
        }
        let record = ReproducibilityRecord::new(
            ClaimUnderTest::Yougori {
                bench: BenchId::Bench01,
                statement: label("ttft"),
            },
            StatisticalMethod::new(
                PercentileMethod::NearestRank,
                vec![IntervalKind::TimeToFirstToken],
            ),
            NaiveDate::from_ymd_opt(2026, 10, 27).unwrap(),
            digest("yougori/test/v1", &[b"harness"]),
            private,
            vec![],
        )
        .unwrap();
        assert_eq!(
            record.with_publication_review(cleared),
            Err(ReportError::NotPublishable {
                fixture: label("code-fixture-1")
            })
        );
    }

    /// First-token p50 in milliseconds within 10%, the comparison the vendor tests use.
    fn p50_within_ten_percent() -> ClaimComparison {
        ClaimComparison {
            statistic: RecordStatistic::Percentile {
                interval: IntervalKind::TimeToFirstToken,
                quantile: Quantile::P50,
            },
            unit: ClaimUnit::Milliseconds,
            relative_tolerance: NonNegative::new(0.1).unwrap(),
        }
    }

    fn declared_vendor_claim() -> ThirdPartyClaim {
        vendor_claim(ClaimConfiguration::Declared {
            entries: vec![ConfigurationEntry {
                key: label("model"),
                value: label("llama-3.1-8b"),
            }],
        })
    }

    fn third_party(claim: ThirdPartyClaim, comparison: ClaimComparison) -> ClaimUnderTest {
        ClaimUnderTest::ThirdParty {
            bench: BenchId::Bench01,
            claim,
            comparison,
        }
    }

    /// First tokens at 88–92 ms: a resolved p50 of 90 ms.
    fn near_ninety(index: usize) -> u64 {
        88 + index as u64 % 5
    }

    #[test]
    fn a_third_party_claim_needs_an_independent_real_reproduction() {
        let declared = declared_vendor_claim();
        let claim_under_test =
            |claim: ThirdPartyClaim| third_party(claim, p50_within_ten_percent());

        // Fake runners do not reproduce a real-world claim.
        let fake_records: Vec<RunRecord> = real_serving_records(30, near_ninety)
            .into_iter()
            .map(|mut record| {
                record.substrate = RunSubstrate::FakeTimeControlled;
                record
            })
            .collect();
        let fake = reproduction(claim_under_test(declared.clone()), fake_records).unwrap();
        assert_eq!(
            declared.reproduced_by(&fake),
            Err(ReportError::FakeRunnerIsNotReproduction)
        );

        let real_records = real_serving_records(30, near_ninety);
        let real = reproduction(claim_under_test(declared.clone()), real_records.clone()).unwrap();
        // A record's own provenance follows the substrate of its raw records.
        let simulated = Provenance::of_reproduction(&fake).unwrap();
        assert!(simulated.is_fake_substrate());
        assert_eq!(
            simulated.yougori_evidence(),
            Err(ReportError::FakeSubstrateIsNotEvidence)
        );
        assert_eq!(
            simulated.comparable_evidence().unwrap(),
            fake.digest().unwrap()
        );
        assert_eq!(
            Provenance::of_reproduction(&real)
                .unwrap()
                .yougori_evidence()
                .unwrap(),
            real.digest().unwrap()
        );
        let provenance = declared.reproduced_by(&real).unwrap();
        assert_eq!(
            provenance.yougori_evidence().unwrap(),
            real.digest().unwrap()
        );
        let Provenance::ThirdPartyReproduced(reproduced) = &provenance else {
            panic!("not a reproduction: {provenance:?}");
        };
        // The provenance carries the statistic as measured and how it was compared.
        assert_eq!(reproduced.measured(), 90e6);
        assert_eq!(reproduced.comparison(), p50_within_ten_percent());

        // A record of another claim does not reproduce this one.
        let mut other = declared.clone();
        other.value = NonNegative::new(45.0).unwrap();
        assert_eq!(
            other.reproduced_by(&real),
            Err(ReportError::ReproductionMismatch)
        );

        // A claim with no stated configuration cannot be reproduced.
        let unspecified = vendor_claim(ClaimConfiguration::Unspecified);
        let record = reproduction(claim_under_test(unspecified.clone()), real_records).unwrap();
        assert_eq!(
            unspecified.reproduced_by(&record),
            Err(ReportError::UnspecifiedClaimConfiguration)
        );
    }

    #[test]
    fn a_reproduction_compares_the_claimed_value_with_the_measured_statistic() {
        // Review finding: reproduced_by never compared the claim's value with the
        // reproduction. The record declares the statistic, unit and tolerance, and only a
        // measurement within that tolerance reproduces the claim.
        let declared = declared_vendor_claim();
        let record_measuring = |ttft_millis: fn(usize) -> u64| {
            reproduction(
                third_party(declared.clone(), p50_within_ten_percent()),
                real_serving_records(30, ttft_millis),
            )
            .unwrap()
        };
        // The vendor claims a 90 ms p50; Yougori measured 150 ms.
        assert_eq!(
            declared.reproduced_by(&record_measuring(|i| 148 + i as u64 % 5)),
            Err(ReportError::NotReproduced {
                claimed: 90e6,
                measured: 150e6
            })
        );
        // 10% of 90 ms is 9 ms: a p50 of 99 ms reproduces the claim, 101 ms does not, and
        // neither does a faster 60 ms.
        assert!(declared
            .reproduced_by(&record_measuring(|i| 97 + i as u64 % 5))
            .is_ok());
        assert_eq!(
            declared.reproduced_by(&record_measuring(|i| 99 + i as u64 % 5)),
            Err(ReportError::NotReproduced {
                claimed: 90e6,
                measured: 101e6
            })
        );
        assert!(matches!(
            declared.reproduced_by(&record_measuring(|i| 58 + i as u64 % 5)),
            Err(ReportError::NotReproduced { .. })
        ));
        // A low-resolution statistic reproduces nothing: six attempts give no resolved p50.
        let few = reproduction(
            third_party(declared.clone(), p50_within_ten_percent()),
            real_serving_records(6, near_ninety),
        )
        .unwrap();
        assert!(matches!(
            declared.reproduced_by(&few),
            Err(ReportError::LowResolution { .. })
        ));

        // The comparison is checked when the record is built: the claim's unit must be the
        // declared one and fit the statistic, and the statistic must be reported.
        let records = || real_serving_records(30, near_ninety);
        let seconds = ClaimComparison {
            unit: ClaimUnit::Seconds,
            ..p50_within_ten_percent()
        };
        let rate_in_ms = ClaimComparison {
            statistic: RecordStatistic::SuccessRate,
            ..p50_within_ten_percent()
        };
        for comparison in [seconds, rate_in_ms] {
            assert_eq!(
                reproduction(third_party(declared.clone(), comparison), records()).err(),
                Some(ReportError::ClaimUnitMismatch)
            );
        }
        let undeclared_interval = ClaimComparison {
            statistic: RecordStatistic::Percentile {
                interval: IntervalKind::QueueWait,
                quantile: Quantile::P50,
            },
            ..p50_within_ten_percent()
        };
        let unreported_percentile = ClaimComparison {
            statistic: RecordStatistic::Percentile {
                interval: IntervalKind::TimeToFirstToken,
                quantile: Quantile::from_basis_points(9000).unwrap(),
            },
            ..p50_within_ten_percent()
        };
        for comparison in [undeclared_interval, unreported_percentile] {
            assert_eq!(
                reproduction(third_party(declared.clone(), comparison), records()).err(),
                Some(ReportError::StatisticNotInRecord)
            );
        }

        // A reliability claim in percent compares with the success rate of every initial
        // attempt.
        let reliability = ThirdPartyClaim {
            metric: label("create-success"),
            value: NonNegative::new(100.0).unwrap(),
            unit: label("percent"),
            ..declared.clone()
        };
        let exact_rate = ClaimComparison {
            statistic: RecordStatistic::SuccessRate,
            unit: ClaimUnit::Percent,
            relative_tolerance: NonNegative::ZERO,
        };
        let record = reproduction(third_party(reliability.clone(), exact_rate), records()).unwrap();
        assert!(reliability.reproduced_by(&record).is_ok());
        let mut with_failure = records();
        with_failure[0].outcome = failed(FailureKind::Timeout);
        with_failure[0].events.truncate(1);
        let record =
            reproduction(third_party(reliability.clone(), exact_rate), with_failure).unwrap();
        assert!(matches!(
            reliability.reproduced_by(&record),
            Err(ReportError::NotReproduced { .. })
        ));

        // The declared comparison is part of the record and is read back with it.
        let slow = record_measuring(|i| 148 + i as u64 % 5);
        let read: ReproducibilityRecord =
            serde_json::from_str(&serde_json::to_string(&slow).unwrap()).unwrap();
        assert_eq!(read.claim(), slow.claim());
        assert_eq!(declared.reproduced_by(&read), declared.reproduced_by(&slow));
    }
}
