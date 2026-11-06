//! Provenance and claim gates (S7 public comparison, S8, S11, S12, BENCH-13): a
//! third-party number is never a Yougori measurement unless independently reproduced; no
//! unverified third-party score becomes a release requirement; a trimmed external score
//! is not release evidence; a low-resolution percentile is not claimed; a burst-scale
//! claim needs a burst of that scale; and no no-leak claim comes from a short run.

use std::collections::BTreeSet;

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

use super::bench::{ClaimComparison, ClaimUnderTest, RecordStatistic, ReproducibilityRecord};
use super::error::ReportError;
use super::events::IntervalKind;
use super::ledger::AttemptLedger;
use super::measured::NonNegative;
use super::record::{RunRecord, RunSubstrate, Scenario};
use super::stats::{LatencySummary, PercentileMethod, Quantile, Resolution, SuccessRate};
use super::text::{Label, PublicUrl};
use crate::foundation::ids::{Digest, DigestBuilder};

/// Domain of [`ThirdPartyClaim::digest`].
pub const THIRD_PARTY_CLAIM_DOMAIN: &str = "yougori/report/third-party-claim/v1";

/// Domain of the raw-record evidence digest of [`Provenance::of_records`].
pub const RAW_RECORDS_DIGEST_DOMAIN: &str = "yougori/report/raw-records/v1";

/// The shortest soak that may support a no-leak claim: two days (S7 "multi-day soak";
/// "No process or snapshot mode receives a no-leak claim from a short run").
pub const MIN_SOAK_SECONDS: u64 = 2 * 86_400;

/// A number published by someone else, with its original date, source and configuration
/// (S7 "Public comparison"). It is a lead for reproduction, never a Yougori result.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThirdPartyClaim {
    pub source: PublicUrl,
    pub published_on: NaiveDate,
    pub retrieved_on: NaiveDate,
    pub configuration: ClaimConfiguration,
    pub metric: Label,
    pub value: NonNegative,
    pub unit: Label,
}

strict_tagged_enum! {
/// The configuration a claim states, or that it stated none (S7: vendor benchmarks with
/// unspecified model or precision are not adopted).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClaimConfiguration (tag = "kind", wire = ClaimConfigurationWire, wire_name = "ClaimConfigurationWire") {
    Declared { entries: Vec<ConfigurationEntry> },
    Unspecified,
}
}

/// One stated configuration value of a claim, such as model or precision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurationEntry {
    pub key: Label,
    pub value: Label,
}

impl ThirdPartyClaim {
    /// A retrieval no earlier than publication, and a non-empty declared configuration
    /// when one is declared.
    pub fn check(&self) -> Result<(), ReportError> {
        if self.retrieved_on < self.published_on {
            return Err(ReportError::InvalidClaimDates);
        }
        if matches!(&self.configuration, ClaimConfiguration::Declared { entries } if entries.is_empty())
        {
            return Err(ReportError::UnspecifiedClaimConfiguration);
        }
        Ok(())
    }

    /// The identity of the claim under [`THIRD_PARTY_CLAIM_DOMAIN`].
    pub fn digest(&self) -> Result<Digest, ReportError> {
        serde_json::to_vec(self)
            .map(|bytes| {
                DigestBuilder::new(THIRD_PARTY_CLAIM_DOMAIN)
                    .bytes(&bytes)
                    .finish()
            })
            .map_err(|_| ReportError::Encoding)
    }

    /// The clear historical label S7 requires for an unreproduced claim.
    pub fn historical_label(&self) -> String {
        format!(
            "third-party claim from {} published {}, not a Yougori measurement",
            self.source, self.published_on
        )
    }

    /// Provenance for a number Yougori reproduced independently (BENCH-13): the record
    /// tests this claim, the claim declares its configuration, every raw run is a real
    /// run in an authorized disposable environment, and the statistic the record declares
    /// for the claim, as measured, lies within the declared relative tolerance of the
    /// claimed value. A record that measured something else documents a claim that was
    /// not reproduced.
    pub fn reproduced_by(&self, record: &ReproducibilityRecord) -> Result<Provenance, ReportError> {
        self.check()?;
        if matches!(self.configuration, ClaimConfiguration::Unspecified) {
            return Err(ReportError::UnspecifiedClaimConfiguration);
        }
        let comparison = match record.claim() {
            ClaimUnderTest::ThirdParty {
                claim, comparison, ..
            } if claim == self => *comparison,
            _ => return Err(ReportError::ReproductionMismatch),
        };
        if record.raw_records().iter().any(on_fake_substrate) {
            return Err(ReportError::FakeRunnerIsNotReproduction);
        }
        let measured = record.statistic(comparison.statistic)?;
        let claimed = self.value.get() * comparison.unit.to_statistic();
        if (measured - claimed).abs() > comparison.relative_tolerance.get() * claimed {
            return Err(ReportError::NotReproduced { claimed, measured });
        }
        Ok(Provenance::ThirdPartyReproduced(ReproducedClaim {
            claim: self.clone(),
            comparison,
            measured,
            reproduction: record.digest()?,
        }))
    }
}

/// A third-party claim, the statistic that reproduced it as measured, and the digest of
/// the BENCH-13 record it was measured in. Built only by
/// [`ThirdPartyClaim::reproduced_by`]; it is never read back (rebuild it from the record).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ReproducedClaim {
    claim: ThirdPartyClaim,
    comparison: ClaimComparison,
    /// In nanoseconds for a percentile, a fraction for a success rate.
    measured: f64,
    reproduction: Digest,
}

impl ReproducedClaim {
    pub fn claim(&self) -> &ThirdPartyClaim {
        &self.claim
    }

    pub fn comparison(&self) -> ClaimComparison {
        self.comparison
    }

    /// The reproduced statistic as measured: nanoseconds for a percentile, a fraction for
    /// a success rate.
    pub fn measured(&self) -> f64 {
        self.measured
    }

    pub fn reproduction(&self) -> Digest {
        self.reproduction
    }
}

/// Whether a record ran on the fake, time-controlled substrate (S12 G0).
fn on_fake_substrate(record: &RunRecord) -> bool {
    record.substrate == RunSubstrate::FakeTimeControlled
}

/// The digest of raw records under [`RAW_RECORDS_DIGEST_DOMAIN`]; the substrate of every
/// record is part of it.
fn raw_records_digest(records: &[RunRecord]) -> Result<Digest, ReportError> {
    serde_json::to_vec(records)
        .map(|bytes| {
            DigestBuilder::new(RAW_RECORDS_DIGEST_DOMAIN)
                .bytes(&bytes)
                .finish()
        })
        .map_err(|_| ReportError::Encoding)
}

/// The evidence of a Yougori measurement: the digest of raw records that all ran in an
/// authorized disposable environment, or of a BENCH-13 record built from them. Built only
/// by [`Provenance::of_records`] and [`Provenance::of_reproduction`]; it is never read
/// back, so no digest becomes a measurement by being written down.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct MeasuredEvidence {
    evidence: Digest,
}

impl MeasuredEvidence {
    pub fn evidence(&self) -> Digest {
        self.evidence
    }
}

/// The evidence of runs on the fake, time-controlled substrate (S12 G0: fakes prove the
/// contract, not the performance). It validates the schema and the comparison
/// discipline, and no release or performance claim accepts it. Built only by
/// [`Provenance::of_records`] and [`Provenance::of_reproduction`].
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct FakeSubstrateEvidence {
    evidence: Digest,
}

impl FakeSubstrateEvidence {
    pub fn evidence(&self) -> Digest {
        self.evidence
    }
}

/// Where a number comes from (BENCH-13). A simulated run keeps its own provenance, so it
/// is never mistaken for a measurement.
///
/// Read back, only the provenances that back no claim are accepted: a fake-substrate run
/// and an unreproduced third-party claim. A Yougori measurement or a reproduced claim is
/// refused when read and rebuilt from its records with [`Provenance::of_records`],
/// [`Provenance::of_reproduction`] or [`ThirdPartyClaim::reproduced_by`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", try_from = "ProvenanceWire")]
pub enum Provenance {
    /// Measured by Yougori in an authorized disposable environment; the evidence names
    /// the raw records or the BENCH-13 record.
    YougoriMeasured(MeasuredEvidence),
    /// Run on a fake, time-controlled runner: schema and comparison validation only.
    FakeSubstrate(FakeSubstrateEvidence),
    /// Published elsewhere and not reproduced: a historical lead only.
    ThirdPartyHistorical { claim: ThirdPartyClaim },
    /// Published elsewhere and independently reproduced.
    ThirdPartyReproduced(ReproducedClaim),
}

/// The serialized form of [`Provenance`], read before the refusal of claim-backing
/// variants.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[serde(remote = "Self")]
enum ProvenanceWire {
    /// Read in full only to be refused.
    #[allow(dead_code)]
    YougoriMeasured {
        evidence: Digest,
    },
    FakeSubstrate {
        evidence: Digest,
    },
    ThirdPartyHistorical {
        claim: ThirdPartyClaim,
    },
    /// Read in full only to be refused.
    #[allow(dead_code)]
    ThirdPartyReproduced {
        claim: ThirdPartyClaim,
        comparison: ClaimComparison,
        measured: f64,
        reproduction: Digest,
    },
}

crate::foundation::strict_serde::strict_tag!(ProvenanceWire, "kind", deserialize);

impl TryFrom<ProvenanceWire> for Provenance {
    type Error = ReportError;

    fn try_from(wire: ProvenanceWire) -> Result<Self, Self::Error> {
        match wire {
            ProvenanceWire::YougoriMeasured { .. }
            | ProvenanceWire::ThirdPartyReproduced { .. } => {
                Err(ReportError::ProvenanceNotReadable)
            }
            ProvenanceWire::FakeSubstrate { evidence } => {
                Ok(Self::FakeSubstrate(FakeSubstrateEvidence { evidence }))
            }
            ProvenanceWire::ThirdPartyHistorical { claim } => {
                claim.check()?;
                Ok(Self::ThirdPartyHistorical { claim })
            }
        }
    }
}

impl Provenance {
    /// The provenance of raw records: a Yougori measurement when every record ran in an
    /// authorized disposable environment, the fake substrate when any ran on a fake.
    /// Refuses no records.
    pub fn of_records(records: &[RunRecord]) -> Result<Self, ReportError> {
        if records.is_empty() {
            return Err(ReportError::NoAttempts);
        }
        let evidence = raw_records_digest(records)?;
        Ok(if records.iter().any(on_fake_substrate) {
            Self::FakeSubstrate(FakeSubstrateEvidence { evidence })
        } else {
            Self::YougoriMeasured(MeasuredEvidence { evidence })
        })
    }

    /// The provenance of a BENCH-13 record, by the rule of [`Self::of_records`] over its
    /// raw records, with the record's own digest as evidence.
    pub fn of_reproduction(record: &ReproducibilityRecord) -> Result<Self, ReportError> {
        let evidence = record.digest()?;
        Ok(if record.raw_records().iter().any(on_fake_substrate) {
            Self::FakeSubstrate(FakeSubstrateEvidence { evidence })
        } else {
            Self::YougoriMeasured(MeasuredEvidence { evidence })
        })
    }

    /// The evidence digest of a Yougori measurement or reproduction, which every release
    /// or performance claim requires; a fake-substrate run and an unreproduced
    /// third-party number are refused.
    pub fn yougori_evidence(&self) -> Result<Digest, ReportError> {
        match self {
            Self::YougoriMeasured(measured) => Ok(measured.evidence),
            Self::ThirdPartyReproduced(reproduced) => Ok(reproduced.reproduction),
            Self::FakeSubstrate(_) => Err(ReportError::FakeSubstrateIsNotEvidence),
            Self::ThirdPartyHistorical { .. } => Err(ReportError::ThirdPartyNotReproduced),
        }
    }

    /// The evidence digest a comparison may validate against: everything
    /// [`Self::yougori_evidence`] accepts, plus a fake-substrate run (FAST-01: "CPU
    /// fixtures validate schema and comparisons"). Such a comparison backs no claim.
    pub fn comparable_evidence(&self) -> Result<Digest, ReportError> {
        match self {
            Self::FakeSubstrate(fake) => Ok(fake.evidence),
            other => other.yougori_evidence(),
        }
    }

    pub fn is_fake_substrate(&self) -> bool {
        matches!(self, Self::FakeSubstrate(_))
    }

    /// The provenance label shown with a number (S7, BENCH-13).
    pub fn label(&self) -> String {
        match self {
            Self::YougoriMeasured(_) => "Yougori measurement".to_string(),
            Self::FakeSubstrate(_) => {
                "fake time-controlled run, not a Yougori measurement".to_string()
            }
            Self::ThirdPartyHistorical { claim } => claim.historical_label(),
            Self::ThirdPartyReproduced(reproduced) => format!(
                "third-party claim from {} independently reproduced by Yougori",
                reproduced.claim.source
            ),
        }
    }
}

/// A release threshold bound to its evidence. S11: "no unverified third-party score
/// becomes a release requirement"; a fake-substrate run is no release evidence either
/// (S12 G0). The threshold is never supplied beside its evidence: it is the statistic as
/// the evidence measured it.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ReleaseRequirement {
    statistic: RecordStatistic,
    /// In nanoseconds for a percentile, a fraction for a success rate.
    threshold: NonNegative,
    evidence: Digest,
}

impl ReleaseRequirement {
    /// The requirement that `statistic` meets the value `record` measured. Refuses a
    /// record with any fake-substrate run, a statistic the record does not report and a
    /// low-resolution percentile (S8, S11). A third-party number enters a requirement
    /// only as Yougori's own measurement in such a record.
    pub fn from_reproduction(
        record: &ReproducibilityRecord,
        statistic: RecordStatistic,
    ) -> Result<Self, ReportError> {
        let evidence = Provenance::of_reproduction(record)?.yougori_evidence()?;
        let threshold = NonNegative::new(record.statistic(statistic)?)?;
        Ok(Self {
            statistic,
            threshold,
            evidence,
        })
    }

    pub fn statistic(&self) -> RecordStatistic {
        self.statistic
    }

    /// In nanoseconds for a percentile, a fraction for a success rate.
    pub fn threshold(&self) -> NonNegative {
        self.threshold
    }

    /// The digest of the BENCH-13 record the threshold was measured in.
    pub fn evidence(&self) -> Digest {
        self.evidence
    }
}

/// A claimed percentile, always carried with the overall success rate and deadline
/// failures it is conditional on (S8). Low-resolution percentiles are refused (S8, S11).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct LatencyClaim {
    interval: IntervalKind,
    quantile: Quantile,
    method: PercentileMethod,
    value_nanos: f64,
    success_rate: SuccessRate,
    deadline_failures: u64,
    successful_samples: u64,
    bursts: u64,
}

impl LatencyClaim {
    /// Claims `quantile` of `summary`; refused when it is low resolution or no run
    /// succeeded.
    pub fn from_summary(summary: &LatencySummary, quantile: Quantile) -> Result<Self, ReportError> {
        let estimate = summary
            .percentile(quantile)
            .ok_or(ReportError::InvalidQuantile)?;
        let value_nanos = *estimate
            .value_nanos
            .value()
            .ok_or(ReportError::NoSuccessfulRuns)?;
        if let Resolution::LowResolution {
            tail_samples,
            bursts,
            ..
        } = estimate.resolution
        {
            return Err(ReportError::LowResolution {
                tail_samples,
                bursts,
            });
        }
        Ok(Self {
            interval: summary.interval(),
            quantile,
            method: summary.method(),
            value_nanos,
            success_rate: summary.success_rate(),
            deadline_failures: summary.deadline_failures(),
            successful_samples: summary.samples().len() as u64,
            bursts: summary.bursts(),
        })
    }

    pub fn value_nanos(&self) -> f64 {
        self.value_nanos
    }

    pub fn success_rate(&self) -> SuccessRate {
        self.success_rate
    }

    pub fn deadline_failures(&self) -> u64 {
        self.deadline_failures
    }
}

/// A score computed by an external method, such as ComputeSDK's, which trims
/// successful-run extremes. Kept beside the untrimmed summary with raw failures and never
/// used as release evidence (S8).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ExternalMethodScore {
    method: Label,
    source: PublicUrl,
    value: f64,
    untrimmed: LatencySummary,
}

impl ExternalMethodScore {
    /// Keeps an externally computed score beside the untrimmed summary it came from.
    pub fn new(
        method: Label,
        source: PublicUrl,
        value: f64,
        untrimmed: LatencySummary,
    ) -> Result<Self, ReportError> {
        if !value.is_finite() {
            return Err(ReportError::InvalidNumber);
        }
        Ok(Self {
            method,
            source,
            value,
            untrimmed,
        })
    }

    /// The untrimmed tails and raw failures shown with the external score.
    pub fn untrimmed(&self) -> &LatencySummary {
        &self.untrimmed
    }

    /// Always refused: "Its scoring rule trims successful-run extremes, which cannot
    /// replace Yougori's release evidence." Use [`Self::untrimmed`].
    pub fn as_release_evidence(&self) -> Result<&LatencySummary, ReportError> {
        Err(ReportError::TrimmedScoreNotReleaseEvidence)
    }
}

/// A claim about VM burst scale (S12: "A simple local model runner does not need a
/// 1,000-VM cloud stress result; a claim about burst scale does").
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct BurstScaleClaim {
    claimed_concurrent_creates: u64,
    largest_observed_burst: u64,
    independent_bursts: u64,
    success_rate: SuccessRate,
}

impl BurstScaleClaim {
    /// Needs real VM provisioning attempts (never a fake run, S12 G0) with at least
    /// `claimed` initial attempts in one burst.
    pub fn new(
        claimed_concurrent_creates: u64,
        ledger: &AttemptLedger,
    ) -> Result<Self, ReportError> {
        let vm_creates = ledger
            .records()
            .first()
            .is_some_and(|record| record.scenario == Scenario::VmProvisioning);
        if !vm_creates {
            return Err(ReportError::WrongScenarioForClaim);
        }
        if ledger.records().iter().any(on_fake_substrate) {
            return Err(ReportError::FakeSubstrateIsNotEvidence);
        }
        let bursts = ledger.bursts();
        let largest_observed_burst = bursts.values().copied().max().unwrap_or(0);
        if largest_observed_burst < claimed_concurrent_creates {
            return Err(ReportError::InsufficientBurstScale {
                claimed: claimed_concurrent_creates,
                observed: largest_observed_burst,
            });
        }
        Ok(Self {
            claimed_concurrent_creates,
            largest_observed_burst,
            independent_bursts: bursts.len() as u64,
            success_rate: ledger.success_rate()?,
        })
    }

    pub fn success_rate(&self) -> SuccessRate {
        self.success_rate
    }
}

/// The resources S10 tracks through switches.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrackedResource {
    ResidentVram,
    PinnedHostMemory,
    HostRss,
    FileDescriptors,
    GpuContexts,
    CudaGraphs,
    Communicators,
    PhysicalAllocationReferences,
}

impl TrackedResource {
    /// Every resource a no-leak claim must track (S10).
    pub const ALL: [Self; 8] = [
        Self::ResidentVram,
        Self::PinnedHostMemory,
        Self::HostRss,
        Self::FileDescriptors,
        Self::GpuContexts,
        Self::CudaGraphs,
        Self::Communicators,
        Self::PhysicalAllocationReferences,
    ];
}

/// One resource's level at the start and end of a soak, and the growth allowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceTrend {
    pub resource: TrackedResource,
    pub first: u64,
    pub last: u64,
    pub allowed_growth: u64,
}

/// A soak run (S7 long-run stability, BENCH-07).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoakEvidence {
    /// Where the soak ran; a fake run backs no no-leak claim, however long its
    /// simulated time (BENCH-07).
    pub substrate: RunSubstrate,
    pub duration_seconds: u64,
    pub switch_or_wake_cycles: u64,
    /// Process recycles during the soak, each a recorded recovery event (S10).
    pub recycles: u64,
    pub canary_failures: u64,
    pub trends: Vec<ResourceTrend>,
}

/// A no-leak claim for one process or snapshot mode.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct NoLeakClaim {
    mode: Label,
    evidence: SoakEvidence,
}

impl NoLeakClaim {
    /// Needs a real multi-day soak (never a fake run, S12 G0) with repeated switches or
    /// wakes, no recycle (S10: "A recycle is a visible recovery event with a latency and
    /// cost, not an unmeasured way to make a memory graph flat"), no canary failure, and
    /// every S10 resource tracked without growth beyond its allowance.
    pub fn new(mode: Label, evidence: SoakEvidence) -> Result<Self, ReportError> {
        if evidence.substrate == RunSubstrate::FakeTimeControlled {
            return Err(ReportError::FakeSubstrateIsNotEvidence);
        }
        if evidence.duration_seconds < MIN_SOAK_SECONDS {
            return Err(ReportError::SoakTooShort {
                seconds: evidence.duration_seconds,
                required: MIN_SOAK_SECONDS,
            });
        }
        if evidence.switch_or_wake_cycles == 0 {
            return Err(ReportError::NoRepeatedCycles);
        }
        if evidence.recycles > 0 {
            return Err(ReportError::RecycledDuringSoak {
                recycles: evidence.recycles,
            });
        }
        if evidence.canary_failures > 0 {
            return Err(ReportError::CanaryFailures {
                failures: evidence.canary_failures,
            });
        }
        let tracked: BTreeSet<TrackedResource> =
            evidence.trends.iter().map(|trend| trend.resource).collect();
        if let Some(resource) = TrackedResource::ALL
            .iter()
            .find(|resource| !tracked.contains(resource))
        {
            return Err(ReportError::MissingTrackedResource {
                resource: *resource,
            });
        }
        if let Some(trend) = evidence
            .trends
            .iter()
            .find(|trend| trend.last > trend.first.saturating_add(trend.allowed_growth))
        {
            return Err(ReportError::ResourceGrowth {
                resource: trend.resource,
            });
        }
        Ok(Self { mode, evidence })
    }

    pub fn mode(&self) -> &Label {
        &self.mode
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::report::bench::BenchId;
    use crate::foundation::report::fixtures::{
        label, real_serving_records, reproduction, serving_record, vm_record,
    };

    pub(crate) fn vendor_claim(configuration: ClaimConfiguration) -> ThirdPartyClaim {
        ThirdPartyClaim {
            source: PublicUrl::new("https://example.org/benchmarks/cold-start").unwrap(),
            published_on: NaiveDate::from_ymd_opt(2026, 3, 2).unwrap(),
            retrieved_on: NaiveDate::from_ymd_opt(2026, 10, 27).unwrap(),
            configuration,
            metric: label("sandbox-create-p50"),
            value: NonNegative::new(90.0).unwrap(),
            unit: label("ms"),
        }
    }

    /// The record as a real run in an authorized disposable environment.
    fn real(mut record: RunRecord) -> RunRecord {
        record.substrate = RunSubstrate::AuthorizedDisposable {
            authorization: label("disposable-test-host"),
        };
        record
    }

    /// First-token p50, the statistic the requirement tests bind to.
    const TTFT_P50: RecordStatistic = RecordStatistic::Percentile {
        interval: IntervalKind::TimeToFirstToken,
        quantile: Quantile::P50,
    };

    /// A Yougori BENCH-01 claim under test.
    fn yougori_claim() -> ClaimUnderTest {
        ClaimUnderTest::Yougori {
            bench: BenchId::Bench01,
            statement: label("ttft-at-load-8"),
        }
    }

    #[test]
    fn a_third_party_number_is_not_a_measurement_or_a_requirement() {
        let claim = vendor_claim(ClaimConfiguration::Unspecified);
        let provenance = Provenance::ThirdPartyHistorical {
            claim: claim.clone(),
        };
        assert_eq!(
            provenance.yougori_evidence(),
            Err(ReportError::ThirdPartyNotReproduced)
        );
        assert!(provenance.label().contains("not a Yougori measurement"));
        assert!(provenance.label().contains("2026-03-02"));
        // A requirement takes its threshold from a Yougori record, so the vendor's 90 ms
        // never becomes one: the threshold is what the record measured (a p50 of 95 ms).
        let record = reproduction(
            yougori_claim(),
            real_serving_records(30, |i| 93 + i as u64 % 5),
        )
        .unwrap();
        let requirement = ReleaseRequirement::from_reproduction(&record, TTFT_P50).unwrap();
        assert_eq!(requirement.threshold().get(), 95e6);
        assert_eq!(requirement.statistic(), TTFT_P50);
        assert_eq!(requirement.evidence(), record.digest().unwrap());
        let mut backdated = claim;
        backdated.retrieved_on = NaiveDate::from_ymd_opt(2026, 1, 1).unwrap();
        assert_eq!(backdated.check(), Err(ReportError::InvalidClaimDates));
    }

    #[test]
    fn a_requirement_threshold_is_bound_to_its_evidence() {
        // Review finding: a requirement's threshold was a number supplied beside a
        // provenance. It is now the statistic as the evidence measured it.
        let record = reproduction(
            yougori_claim(),
            real_serving_records(30, |i| 88 + i as u64 % 5),
        )
        .unwrap();
        let p50 = ReleaseRequirement::from_reproduction(&record, TTFT_P50).unwrap();
        assert_eq!(p50.threshold().get(), record.statistic(TTFT_P50).unwrap());
        assert_eq!(p50.threshold().get(), 90e6);
        let reliability =
            ReleaseRequirement::from_reproduction(&record, RecordStatistic::SuccessRate).unwrap();
        assert_eq!(reliability.threshold().get(), 1.0);
        // A statistic the record does not report, or reports at low resolution, binds
        // nothing (S8, S11).
        assert_eq!(
            ReleaseRequirement::from_reproduction(
                &record,
                RecordStatistic::Percentile {
                    interval: IntervalKind::QueueWait,
                    quantile: Quantile::P50,
                }
            ),
            Err(ReportError::StatisticNotInRecord)
        );
        assert!(matches!(
            ReleaseRequirement::from_reproduction(
                &record,
                RecordStatistic::Percentile {
                    interval: IntervalKind::TimeToFirstToken,
                    quantile: Quantile::P99,
                }
            ),
            Err(ReportError::LowResolution { .. })
        ));
        // Evidence from a fake run binds no requirement (S12 G0).
        let fake_records: Vec<RunRecord> = (0..30)
            .map(|index| serving_record(&format!("op-{index}"), 90))
            .collect();
        let fake = reproduction(yougori_claim(), fake_records).unwrap();
        assert_eq!(
            ReleaseRequirement::from_reproduction(&fake, TTFT_P50),
            Err(ReportError::FakeSubstrateIsNotEvidence)
        );
    }

    #[test]
    fn a_hand_written_provenance_backs_no_release_requirement() {
        // Review probe a_hand_written_provenance_backs_a_release_requirement: a measured
        // or reproduced provenance read from any JSON passed the release gate. Such a
        // provenance is now refused when read, and a requirement takes its evidence from
        // a record, never from a provenance supplied beside it.
        let zeros = "0".repeat(64);
        let error = serde_json::from_str::<Provenance>(&format!(
            r#"{{"kind":"yougori_measured","evidence":"{zeros}"}}"#
        ))
        .unwrap_err();
        assert!(
            error.to_string().contains("rebuilt from its records"),
            "{error}"
        );
        // A reproduced claim written by hand is refused too, here one whose configuration
        // is unspecified (which reproduced_by refuses), in its full form and in the
        // probe's shorter form.
        let claim = vendor_claim(ClaimConfiguration::Unspecified);
        let claim_json = serde_json::to_string(&claim).unwrap();
        let comparison = r#"{"statistic":{"kind":"percentile","interval":"time_to_first_token","quantile":5000},"unit":"milliseconds","relative_tolerance":"0.1"}"#;
        for written in [
            format!(
                r#"{{"kind":"third_party_reproduced","claim":{claim_json},"comparison":{comparison},"measured":90000000.0,"reproduction":"{zeros}"}}"#
            ),
            format!(
                r#"{{"kind":"third_party_reproduced","claim":{claim_json},"reproduction":"{zeros}"}}"#
            ),
        ] {
            assert!(
                serde_json::from_str::<Provenance>(&written).is_err(),
                "{written}"
            );
        }
        // A real measurement is written for reports but is not read back as one.
        let measured = Provenance::of_records(&real_serving_records(1, |_| 100)).unwrap();
        assert!(measured.yougori_evidence().is_ok());
        let written = serde_json::to_string(&measured).unwrap();
        assert!(written.contains("\"kind\":\"yougori_measured\""));
        assert!(serde_json::from_str::<Provenance>(&written).is_err());
        // Provenances that back no claim still read back: a historical claim, which stays
        // refused as evidence.
        let historical = Provenance::ThirdPartyHistorical { claim };
        let read: Provenance =
            serde_json::from_str(&serde_json::to_string(&historical).unwrap()).unwrap();
        assert_eq!(read, historical);
        assert_eq!(
            read.yougori_evidence(),
            Err(ReportError::ThirdPartyNotReproduced)
        );
    }

    #[test]
    fn a_fake_substrate_run_is_never_release_or_performance_evidence() {
        // Simulated runs keep their own provenance, which every release or performance
        // claim refuses; schema and comparison validation still accept it (S12 G0).
        let fake_records = vec![serving_record("op-1", 100), serving_record("op-2", 120)];
        let fake = Provenance::of_records(&fake_records).unwrap();
        assert!(fake.is_fake_substrate());
        assert_eq!(
            fake.yougori_evidence(),
            Err(ReportError::FakeSubstrateIsNotEvidence)
        );
        let fake_record = reproduction(yougori_claim(), fake_records.clone()).unwrap();
        assert_eq!(
            ReleaseRequirement::from_reproduction(&fake_record, RecordStatistic::SuccessRate),
            Err(ReportError::FakeSubstrateIsNotEvidence)
        );
        assert!(fake.label().contains("not a Yougori measurement"));
        // The same attempts in an authorized disposable environment are a measurement,
        // and the substrate is part of the evidence digest.
        let real_records: Vec<RunRecord> = fake_records.iter().cloned().map(real).collect();
        let measured = Provenance::of_records(&real_records).unwrap();
        assert!(!measured.is_fake_substrate());
        assert_eq!(
            measured.yougori_evidence().unwrap(),
            measured.comparable_evidence().unwrap()
        );
        assert_ne!(
            measured.yougori_evidence().unwrap(),
            fake.comparable_evidence().unwrap()
        );
        let real_record = reproduction(yougori_claim(), real_records.clone()).unwrap();
        assert!(
            ReleaseRequirement::from_reproduction(&real_record, RecordStatistic::SuccessRate)
                .is_ok()
        );
        // One fake record makes the whole set fake, and no records are no evidence.
        let mut mixed = real_records.clone();
        mixed.push(serving_record("op-3", 100));
        assert!(Provenance::of_records(&mixed).unwrap().is_fake_substrate());
        assert_eq!(Provenance::of_records(&[]), Err(ReportError::NoAttempts));
        // The provenance survives a round trip and stays refused.
        let json = serde_json::to_string(&fake).unwrap();
        assert!(json.contains("\"kind\":\"fake_substrate\""));
        let read: Provenance = serde_json::from_str(&json).unwrap();
        assert_eq!(read, fake);
        assert_eq!(
            read.yougori_evidence(),
            Err(ReportError::FakeSubstrateIsNotEvidence)
        );
    }

    fn summary_with(samples: usize, bursts: u32) -> LatencySummary {
        let records = (0..samples).map(|index| {
            let mut record = serving_record(&format!("op-{index}"), 100 + index as u64 % 7);
            record.attempt.burst = index as u32 % bursts;
            record
        });
        let ledger = AttemptLedger::from_records(records).unwrap();
        LatencySummary::from_ledger(
            &ledger,
            IntervalKind::TimeToFirstToken,
            PercentileMethod::NearestRank,
        )
        .unwrap()
    }

    #[test]
    fn a_low_resolution_p99_is_not_claimed() {
        let one_burst = summary_with(100, 1);
        assert_eq!(
            LatencyClaim::from_summary(&one_burst, Quantile::P99),
            Err(ReportError::LowResolution {
                tail_samples: 1,
                bursts: 1
            })
        );
        let resolved = summary_with(1_000, 4);
        let claim = LatencyClaim::from_summary(&resolved, Quantile::P99).unwrap();
        assert_eq!(claim.success_rate().attempts(), 1_000);
        assert_eq!(claim.deadline_failures(), 0);
        let p50 = LatencyClaim::from_summary(&one_burst, Quantile::P50);
        assert!(matches!(
            p50,
            Err(ReportError::LowResolution { bursts: 1, .. })
        ));
    }

    #[test]
    fn a_trimmed_external_score_is_not_release_evidence() {
        let untrimmed = summary_with(20, 2);
        let score = ExternalMethodScore::new(
            label("computesdk-trimmed-score"),
            PublicUrl::new(
                "https://github.com/runloopai/computesdk-benchmarks/blob/master/METHODOLOGY.md",
            )
            .unwrap(),
            87.5,
            untrimmed.clone(),
        )
        .unwrap();
        assert_eq!(
            score.as_release_evidence(),
            Err(ReportError::TrimmedScoreNotReleaseEvidence)
        );
        assert_eq!(score.untrimmed(), &untrimmed);
    }

    #[test]
    fn a_burst_scale_claim_needs_a_real_burst_of_that_scale() {
        let fake = AttemptLedger::from_records(
            (0..100).map(|index| vm_record(&format!("op-{index}"), 800)),
        )
        .unwrap();
        assert_eq!(
            BurstScaleClaim::new(100, &fake),
            Err(ReportError::FakeSubstrateIsNotEvidence)
        );
        let records = (0..100).map(|index| real(vm_record(&format!("op-{index}"), 800)));
        let ledger = AttemptLedger::from_records(records).unwrap();
        let claim = BurstScaleClaim::new(100, &ledger).unwrap();
        assert_eq!(claim.success_rate().attempts(), 100);
        assert_eq!(
            BurstScaleClaim::new(1_000, &ledger),
            Err(ReportError::InsufficientBurstScale {
                claimed: 1_000,
                observed: 100
            })
        );
        let serving = AttemptLedger::from_records(vec![serving_record("op-1", 100)]).unwrap();
        assert_eq!(
            BurstScaleClaim::new(1, &serving),
            Err(ReportError::WrongScenarioForClaim)
        );
    }

    fn soak(duration_seconds: u64) -> SoakEvidence {
        SoakEvidence {
            substrate: RunSubstrate::AuthorizedDisposable {
                authorization: label("disposable-soak-host"),
            },
            duration_seconds,
            switch_or_wake_cycles: 5_000,
            recycles: 0,
            canary_failures: 0,
            trends: TrackedResource::ALL
                .iter()
                .map(|resource| ResourceTrend {
                    resource: *resource,
                    first: 100,
                    last: 100,
                    allowed_growth: 0,
                })
                .collect(),
        }
    }

    #[test]
    fn no_leak_claims_need_a_multi_day_soak() {
        assert_eq!(
            NoLeakClaim::new(label("retained-process"), soak(6 * 3600)),
            Err(ReportError::SoakTooShort {
                seconds: 6 * 3600,
                required: MIN_SOAK_SECONDS
            })
        );
        NoLeakClaim::new(label("retained-process"), soak(MIN_SOAK_SECONDS)).unwrap();
        let mut leaking = soak(MIN_SOAK_SECONDS);
        leaking.trends[2].last = 101;
        assert_eq!(
            NoLeakClaim::new(label("snapshot-restore"), leaking),
            Err(ReportError::ResourceGrowth {
                resource: TrackedResource::HostRss
            })
        );
        let mut untracked = soak(MIN_SOAK_SECONDS);
        untracked
            .trends
            .retain(|trend| trend.resource != TrackedResource::CudaGraphs);
        assert_eq!(
            NoLeakClaim::new(label("sleep-mode"), untracked),
            Err(ReportError::MissingTrackedResource {
                resource: TrackedResource::CudaGraphs
            })
        );
        let mut canary = soak(MIN_SOAK_SECONDS);
        canary.canary_failures = 1;
        assert_eq!(
            NoLeakClaim::new(label("sleep-mode"), canary),
            Err(ReportError::CanaryFailures { failures: 1 })
        );
        let mut idle = soak(MIN_SOAK_SECONDS);
        idle.switch_or_wake_cycles = 0;
        assert_eq!(
            NoLeakClaim::new(label("sleep-mode"), idle),
            Err(ReportError::NoRepeatedCycles)
        );
        // A recycle flattens the memory graph; it is not evidence of no leak.
        let mut recycled = soak(MIN_SOAK_SECONDS);
        recycled.recycles = 3;
        assert_eq!(
            NoLeakClaim::new(label("retained-process"), recycled),
            Err(ReportError::RecycledDuringSoak { recycles: 3 })
        );
        // A fake run backs no no-leak claim, however long its simulated time (BENCH-07).
        let mut fake = soak(10 * MIN_SOAK_SECONDS);
        fake.substrate = RunSubstrate::FakeTimeControlled;
        assert_eq!(
            NoLeakClaim::new(label("retained-process"), fake),
            Err(ReportError::FakeSubstrateIsNotEvidence)
        );
    }
}
