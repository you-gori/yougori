//! Engines, the default-engine roster and GGUF conversion (GPU part §3.8, SGLang and
//! llama.cpp/GGUF rows). A second default engine and a GGUF conversion both need an
//! attributable benefit: a CORE-08 improvement claim from a measured comparison against
//! what runs today, under matched configurations and with no disclosed regression. A fake
//! bench run backs none, and resemblance to another backend is never one.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::foundation::evidence::Backend;
use crate::foundation::ids::Digest;
use crate::foundation::report::{
    BaselineOutcome, BaselineRole, ComparisonReport, ConfigurationField, ImprovementClaim,
    Objective, ReportError,
};

/// An inference engine: one of evidence's backends, or SGLang, which the plan names as an
/// optional later backend and evidence does not include yet (GPU part §3.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Engine {
    /// vLLM, llama.cpp or Transformers.
    Backend(Backend),
    /// SGLang.
    Sglang,
}

impl fmt::Display for Engine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Backend(backend) => write!(f, "{backend}"),
            Self::Sglang => f.write_str("SGLang"),
        }
    }
}

/// The `FORMAT` values model_server.py chooses an engine by (Appendix A.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServingFormat {
    /// `safetensors`, served by Transformers today.
    Safetensors,
    /// `gguf`, served by llama.cpp today.
    Gguf,
    /// `vllm`, served by vLLM today.
    Vllm,
}

impl ServingFormat {
    /// Every format, in order.
    pub const ALL: [Self; 3] = [Self::Safetensors, Self::Gguf, Self::Vllm];
}

impl fmt::Display for ServingFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Safetensors => "safetensors",
            Self::Gguf => "gguf",
            Self::Vllm => "vllm",
        })
    }
}

/// How an artifact's weights are stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactFormat {
    /// A GGUF file, prequantized and memory-mapped by llama.cpp.
    Gguf,
    /// Safetensors files.
    Safetensors,
}

impl fmt::Display for ArtifactFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Gguf => "GGUF",
            Self::Safetensors => "safetensors",
        })
    }
}

/// What a benefit compares; each kind fixes its baseline.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Comparison {
    /// `candidate` as a default engine for `format`, against the `incumbent` default.
    DefaultEngine {
        format: ServingFormat,
        incumbent: Engine,
        candidate: Engine,
    },
    /// The GGUF `artifact` converted to `target` and served by `engine`, against the same
    /// GGUF on the existing llama.cpp mmap/prequantized path.
    GgufConversion {
        artifact: Digest,
        target: ArtifactFormat,
        engine: Engine,
    },
}

impl Comparison {
    /// Whether the compared choice itself changes `field` of the matched configuration
    /// (S7: matched model bytes, precision, prompt, output length, hardware and client).
    /// An engine changes none of them; a conversion changes the model bytes and may
    /// change their precision.
    pub fn changes(&self, field: ConfigurationField) -> bool {
        match self {
            Self::DefaultEngine { .. } => false,
            Self::GgufConversion { .. } => matches!(
                field,
                ConfigurationField::ModelBytes | ConfigurationField::Precision
            ),
        }
    }
}

impl fmt::Display for Comparison {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DefaultEngine {
                format,
                incumbent,
                candidate,
            } => write!(
                f,
                "{candidate} against {incumbent} as the default engine for {format}"
            ),
            Self::GgufConversion {
                artifact,
                target,
                engine,
            } => write!(
                f,
                "GGUF {artifact} converted to {target} for {engine}, against the existing \
                 llama.cpp path"
            ),
        }
    }
}

/// An attributable benefit (GPU part §3.8, SGLang and llama.cpp/GGUF rows; §1.1:
/// matched baselines; §1.3: improve a declared objective without silently violating
/// others; GPU-W01 acceptance: "attributable improvements in at least one real
/// workload").
///
/// Built only from a CORE-08 [`ComparisonReport`], through its [`ImprovementClaim`]
/// against the ordinary-workflow baseline: for both comparisons that is what runs today,
/// the incumbent default engine or the GGUF on its existing llama.cpp path. The claim
/// needs Yougori evidence on both sides, so a fake bench run, an unreproduced number or
/// no measurement at all backs none, and the improvement, regressions, configurations and
/// evidence digests are the report's, never the caller's.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct AttributableBenefit {
    comparison: Comparison,
    claim: ImprovementClaim,
    record: Digest,
    baseline_record: Digest,
    workload: Digest,
    differences: Vec<ConfigurationField>,
}

impl AttributableBenefit {
    /// The benefit `report` measured for `comparison`. Refuses what
    /// [`ImprovementClaim::from_report`] refuses against the ordinary-workflow baseline: a
    /// side without Yougori evidence, a missing baseline and a declared objective that did
    /// not improve.
    pub fn from_report(
        comparison: Comparison,
        report: &ComparisonReport,
    ) -> Result<Self, ReportError> {
        let claim = ImprovementClaim::from_report(report, BaselineRole::OrdinaryWorkflow)?;
        let BaselineOutcome::Compared { baseline, .. } = report.ordinary_workflow() else {
            return Err(ReportError::MissingBaseline {
                which: BaselineRole::OrdinaryWorkflow,
            });
        };
        let candidate = report.candidate();
        Ok(Self {
            comparison,
            record: candidate.provenance.yougori_evidence()?,
            baseline_record: baseline.provenance.yougori_evidence()?,
            workload: candidate.configuration.fixture,
            differences: candidate.configuration.differences(&baseline.configuration),
            claim,
        })
    }

    /// What was compared.
    pub fn comparison(&self) -> &Comparison {
        &self.comparison
    }

    /// The claim, with the regressions and unmeasured objectives it discloses.
    pub fn claim(&self) -> &ImprovementClaim {
        &self.claim
    }

    /// The Yougori evidence of the candidate's measurement.
    pub fn record(&self) -> Digest {
        self.record
    }

    /// The Yougori evidence of the baseline's measurement.
    pub fn baseline_record(&self) -> Digest {
        self.baseline_record
    }

    /// The workload fixture both arms ran.
    pub fn workload(&self) -> Digest {
        self.workload
    }

    /// Checks that the benefit supports `needed`: it measured exactly that comparison,
    /// against a baseline that differs only in what the comparison itself changes, and
    /// disclosed no regression.
    pub fn supports(&self, needed: &Comparison) -> Result<(), BenefitRefusal> {
        if self.comparison != *needed {
            return Err(BenefitRefusal::OtherComparison {
                recorded: self.comparison.clone(),
                needed: needed.clone(),
            });
        }
        let fields: Vec<ConfigurationField> = self
            .differences
            .iter()
            .copied()
            .filter(|field| !needed.changes(*field))
            .collect();
        if !fields.is_empty() {
            return Err(BenefitRefusal::UnmatchedBaseline { fields });
        }
        let objectives: BTreeSet<Objective> = self
            .claim
            .regressions()
            .iter()
            .map(|change| change.objective)
            .collect();
        if !objectives.is_empty() {
            return Err(BenefitRefusal::Regression { objectives });
        }
        Ok(())
    }
}

/// Why a benefit does not support a change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum BenefitRefusal {
    /// The benefit was measured for another comparison.
    OtherComparison {
        recorded: Comparison,
        needed: Comparison,
    },
    /// The arms differ in more than the compared choice, so the difference is not
    /// attributable to it.
    UnmatchedBaseline { fields: Vec<ConfigurationField> },
    /// The claim discloses regressions beyond tolerance on these objectives.
    Regression { objectives: BTreeSet<Objective> },
}

impl fmt::Display for BenefitRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OtherComparison { recorded, needed } => write!(
                f,
                "the benefit was measured for {recorded}, not for {needed}"
            ),
            Self::UnmatchedBaseline { fields } => write!(
                f,
                "the baseline and candidate also differ in {fields:?}, so the difference is \
                 not attributable to what was compared"
            ),
            Self::Regression { objectives } => {
                write!(
                    f,
                    "the candidate made these objectives worse: {objectives:?}"
                )
            }
        }
    }
}

impl std::error::Error for BenefitRefusal {}

/// Which engines run by default for each `FORMAT`, and which run only when chosen (GPU
/// part §3.8, SGLang row: "Do not add a second default engine without an attributable
/// benefit").
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EngineRoster {
    defaults: BTreeMap<ServingFormat, BTreeSet<Engine>>,
    optional: BTreeMap<ServingFormat, BTreeSet<Engine>>,
}

impl EngineRoster {
    /// Today's roster (Appendix A.1): `safetensors` runs Transformers, `gguf` runs
    /// llama.cpp and `vllm` runs vLLM; nothing is optional.
    pub fn current() -> Self {
        let default = |backend| BTreeSet::from([Engine::Backend(backend)]);
        Self {
            defaults: BTreeMap::from([
                (ServingFormat::Safetensors, default(Backend::Transformers)),
                (ServingFormat::Gguf, default(Backend::LlamaCpp)),
                (ServingFormat::Vllm, default(Backend::Vllm)),
            ]),
            optional: BTreeMap::new(),
        }
    }

    /// The engines that run `format` by default.
    pub fn defaults(&self, format: ServingFormat) -> impl Iterator<Item = Engine> + '_ {
        self.defaults.get(&format).into_iter().flatten().copied()
    }

    /// The engines that run `format` only when chosen.
    pub fn optional(&self, format: ServingFormat) -> impl Iterator<Item = Engine> + '_ {
        self.optional.get(&format).into_iter().flatten().copied()
    }

    /// Whether `engine` runs `format` by default.
    pub fn is_default(&self, format: ServingFormat, engine: Engine) -> bool {
        self.defaults
            .get(&format)
            .is_some_and(|engines| engines.contains(&engine))
    }

    /// Lists `engine` for `format` as an engine that runs only when chosen, such as SGLang
    /// as an "optional later backend using upstream facilities". It needs no benefit and
    /// never becomes a default this way.
    pub fn add_optional(
        &mut self,
        format: ServingFormat,
        engine: Engine,
    ) -> Result<(), RosterRefusal> {
        if self.is_default(format, engine) {
            return Err(RosterRefusal::AlreadyDefault { format, engine });
        }
        if !self.optional.entry(format).or_default().insert(engine) {
            return Err(RosterRefusal::AlreadyOptional { format, engine });
        }
        Ok(())
    }

    /// Makes `engine` another default for `format`, beside the current one, given an
    /// attributable benefit of `engine` over a current default of `format`, measured and
    /// claimed through CORE-08.
    pub fn add_default(
        &mut self,
        format: ServingFormat,
        engine: Engine,
        benefit: Option<&AttributableBenefit>,
    ) -> Result<(), RosterRefusal> {
        if self.is_default(format, engine) {
            return Err(RosterRefusal::AlreadyDefault { format, engine });
        }
        let Some(benefit) = benefit else {
            return Err(RosterRefusal::NoAttributableBenefit { format, engine });
        };
        let mut refusal = None;
        let supported = self.defaults(format).any(|incumbent| {
            let needed = Comparison::DefaultEngine {
                format,
                incumbent,
                candidate: engine,
            };
            match benefit.supports(&needed) {
                Ok(()) => true,
                Err(cause) => {
                    refusal.get_or_insert(cause);
                    false
                }
            }
        });
        if !supported {
            return Err(match refusal {
                Some(cause) => RosterRefusal::Benefit { cause },
                None => RosterRefusal::NoAttributableBenefit { format, engine },
            });
        }
        self.defaults.entry(format).or_default().insert(engine);
        if let Some(optional) = self.optional.get_mut(&format) {
            optional.remove(&engine);
        }
        Ok(())
    }
}

/// Why the roster refused a change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum RosterRefusal {
    /// The engine already runs the format by default.
    AlreadyDefault {
        format: ServingFormat,
        engine: Engine,
    },
    /// The engine is already listed as optional for the format.
    AlreadyOptional {
        format: ServingFormat,
        engine: Engine,
    },
    /// No attributable benefit was given.
    NoAttributableBenefit {
        format: ServingFormat,
        engine: Engine,
    },
    /// The given benefit does not support the change.
    Benefit { cause: BenefitRefusal },
}

impl fmt::Display for RosterRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyDefault { format, engine } => {
                write!(f, "{engine} already runs {format} by default")
            }
            Self::AlreadyOptional { format, engine } => {
                write!(f, "{engine} is already an optional engine for {format}")
            }
            Self::NoAttributableBenefit { format, engine } => write!(
                f,
                "{engine} cannot become another default engine for {format} without a \
                 recorded attributable benefit"
            ),
            Self::Benefit { cause } => write!(f, "the benefit does not support this: {cause}"),
        }
    }
}

impl std::error::Error for RosterRefusal {}

/// A proposed conversion of a GGUF artifact for another engine (GPU part §3.8,
/// llama.cpp/GGUF row: "Do not convert GGUF solely to make it resemble another
/// backend").
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GgufConversion {
    /// The GGUF artifact.
    pub artifact: Digest,
    /// What it would become.
    pub target: ArtifactFormat,
    /// The engine that would serve the result.
    pub engine: Engine,
}

/// Why a GGUF conversion is proposed.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversionReason {
    /// Only to make the artifact resemble what another backend loads.
    ResembleAnotherBackend,
    /// An attributable benefit of the converted path over the existing GGUF path.
    AttributableBenefit(Box<AttributableBenefit>),
}

/// Why a GGUF conversion was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum ConversionRefusal {
    /// The target is GGUF again, so this is not a conversion to another representation.
    NotAConversion,
    /// Resembling another backend is never a reason on its own.
    OnlyToResembleAnotherBackend,
    /// The given benefit does not support this conversion.
    Benefit { cause: BenefitRefusal },
}

impl fmt::Display for ConversionRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAConversion => f.write_str("the target is GGUF again"),
            Self::OnlyToResembleAnotherBackend => f.write_str(
                "GGUF is not converted solely to make it resemble another backend; it stays \
                 on its existing mmap/prequantized path unless an attributable benefit \
                 supports the conversion",
            ),
            Self::Benefit { cause } => {
                write!(f, "the benefit does not support this conversion: {cause}")
            }
        }
    }
}

impl std::error::Error for ConversionRefusal {}

/// An approved GGUF conversion. Only [`GgufConversion::approve`] makes one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ApprovedConversion {
    conversion: GgufConversion,
    record: Digest,
}

impl ApprovedConversion {
    /// The approved conversion.
    pub fn conversion(&self) -> &GgufConversion {
        &self.conversion
    }

    /// The Yougori evidence of the measurement that approved it.
    pub fn record(&self) -> Digest {
        self.record
    }
}

impl GgufConversion {
    /// The comparison a benefit for this conversion must have measured.
    pub fn comparison(&self) -> Comparison {
        Comparison::GgufConversion {
            artifact: self.artifact,
            target: self.target,
            engine: self.engine,
        }
    }

    /// Approves the conversion for `reason`: never to resemble another backend, only on an
    /// attributable benefit of exactly this conversion.
    pub fn approve(
        &self,
        reason: &ConversionReason,
    ) -> Result<ApprovedConversion, ConversionRefusal> {
        if self.target == ArtifactFormat::Gguf {
            return Err(ConversionRefusal::NotAConversion);
        }
        match reason {
            ConversionReason::ResembleAnotherBackend => {
                Err(ConversionRefusal::OnlyToResembleAnotherBackend)
            }
            ConversionReason::AttributableBenefit(benefit) => {
                benefit
                    .supports(&self.comparison())
                    .map_err(|cause| ConversionRefusal::Benefit { cause })?;
                Ok(ApprovedConversion {
                    conversion: self.clone(),
                    record: benefit.record(),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::digest;
    use crate::foundation::report::{
        Baseline, BaselineUnavailable, ComparisonSide, EffectClass, ExperimentDesign, Label,
        LatencyObjective, MatchedConfiguration, Measured, ModeFidelity, NonNegative,
        NotMeasuredReason, ObjectivePlan, ObjectiveVector, Provenance, Quantile, RunRecord,
        RunSubstrate, StartTemperature, StateComparison, TracePattern, RUN_RECORD_SAMPLE_JSON,
    };

    const SGLANG: Engine = Engine::Sglang;
    const VLLM: Engine = Engine::Backend(Backend::Vllm);
    const GIB: f64 = 1_073_741_824.0;

    fn id(text: &str) -> Digest {
        digest("yougori/test/backends/v1", &[text.as_bytes()])
    }

    fn label(text: &str) -> Label {
        Label::new(text).unwrap()
    }

    /// CORE-08's golden run record, run on `substrate`.
    fn record(substrate: RunSubstrate) -> RunRecord {
        let mut record: RunRecord = serde_json::from_str(RUN_RECORD_SAMPLE_JSON).unwrap();
        record.substrate = substrate;
        record
    }

    /// A Yougori measurement in an authorized disposable environment.
    fn measured() -> Provenance {
        Provenance::of_records(&[record(RunSubstrate::AuthorizedDisposable {
            authorization: label("disposable-test-host"),
        })])
        .unwrap()
    }

    /// A fake, time-controlled bench run.
    fn simulated() -> Provenance {
        Provenance::of_records(&[record(RunSubstrate::FakeTimeControlled)]).unwrap()
    }

    /// Every §1.3 objective measured; first-token latency and peak GPU memory vary.
    fn objectives(ttft_millis: f64, peak_gpu_gib: f64) -> ObjectiveVector {
        let value = |number: f64| Measured::measured(NonNegative::new(number).unwrap());
        ObjectiveVector {
            time_to_first_token_quantile: Quantile::P95,
            latency_objective: LatencyObjective {
                quantile: Quantile::P95,
                max_time_to_first_token_nanos: 500_000_000,
            },
            time_to_first_token_nanos: value(ttft_millis * 1e6),
            throughput_under_latency_objective_tokens_per_second: value(400.0),
            peak_gpu_memory_bytes: value(peak_gpu_gib * GIB),
            retained_gpu_memory_bytes: value(8.0 * GIB),
            peak_host_memory_bytes: value(16.0 * GIB),
            retained_host_memory_bytes: value(4.0 * GIB),
            transferred_bytes: value(0.0),
            storage_read_bytes: value(15.0 * GIB),
            preparation_cost_usd: value(0.0),
            cost_per_completed_request_usd: value(0.002),
            energy_per_completed_request_joules: value(30.0),
            reliability_success_rate: value(0.99),
        }
    }

    fn side(name: &str, provenance: Provenance, ttft_millis: f64) -> ComparisonSide {
        ComparisonSide {
            name: label(name),
            provenance,
            configuration: MatchedConfiguration::from_record(&record(
                RunSubstrate::FakeTimeControlled,
            ))
            .unwrap(),
            temperature: StartTemperature::Warm,
            fidelity: ModeFidelity::BitIdentical,
            accuracy_evaluation: Measured::not_measured(NotMeasuredReason::NotApplicable),
            objectives: objectives(ttft_millis, 20.0),
        }
    }

    /// A warm comparison of `candidate` against the ordinary workflow, declaring `varied`;
    /// no upstream release is compatible.
    fn report(
        candidate: ComparisonSide,
        ordinary: ComparisonSide,
        varied: Vec<ConfigurationField>,
    ) -> ComparisonReport {
        ComparisonReport::new(
            ObjectivePlan::new(Objective::TimeToFirstToken, 0.05).unwrap(),
            StateComparison::WarmLoad,
            ExperimentDesign {
                effect: EffectClass::Other,
                independent_trials: 8,
                trace: TracePattern::Mixed { seed: 3 },
                components: vec![label("candidate-path")],
                ablated_components: Vec::new(),
            },
            varied,
            candidate,
            Baseline::Measured {
                sides: vec![ordinary],
            },
            Baseline::Unavailable {
                reason: BaselineUnavailable::NoCompatibleUpstreamRelease,
                detail: label("none"),
            },
        )
        .unwrap()
    }

    /// A measured benefit for `comparison`: 200 ms against 300 ms to the first token,
    /// every other objective unchanged.
    fn benefit(comparison: Comparison) -> AttributableBenefit {
        let measured_report = report(
            side("candidate", measured(), 200.0),
            side("ordinary", measured(), 300.0),
            Vec::new(),
        );
        AttributableBenefit::from_report(comparison, &measured_report).unwrap()
    }

    /// A converted candidate: other model bytes and quantization, lossy, with an accuracy
    /// evaluation (§1.3).
    fn converted(ttft_millis: f64) -> ComparisonSide {
        let mut candidate = side("converted", measured(), ttft_millis);
        candidate.configuration.model_bytes = id("model.safetensors");
        candidate.configuration.precision.quantization = label("q8-0");
        candidate.fidelity = ModeFidelity::Lossy;
        candidate.accuracy_evaluation = Measured::measured(id("accuracy-evaluation"));
        candidate
    }

    fn sglang_over_vllm() -> Comparison {
        Comparison::DefaultEngine {
            format: ServingFormat::Vllm,
            incumbent: VLLM,
            candidate: SGLANG,
        }
    }

    fn conversion() -> GgufConversion {
        GgufConversion {
            artifact: id("model.gguf"),
            target: ArtifactFormat::Safetensors,
            engine: VLLM,
        }
    }

    #[test]
    fn the_current_roster_has_one_default_per_format() {
        let roster = EngineRoster::current();
        let expected = [
            (ServingFormat::Safetensors, Backend::Transformers),
            (ServingFormat::Gguf, Backend::LlamaCpp),
            (ServingFormat::Vllm, Backend::Vllm),
        ];
        for (format, backend) in expected {
            assert_eq!(
                roster.defaults(format).collect::<Vec<_>>(),
                [Engine::Backend(backend)]
            );
            assert_eq!(roster.optional(format).count(), 0);
        }
        assert_eq!(ServingFormat::ALL.len(), expected.len());
        assert_eq!(ServingFormat::Safetensors.to_string(), "safetensors");
    }

    #[test]
    fn a_second_default_engine_needs_an_attributable_benefit() {
        let mut roster = EngineRoster::current();
        let refusal = roster
            .add_default(ServingFormat::Vllm, SGLANG, None)
            .unwrap_err();
        assert_eq!(
            refusal,
            RosterRefusal::NoAttributableBenefit {
                format: ServingFormat::Vllm,
                engine: SGLANG
            }
        );
        assert!(refusal.to_string().contains("attributable benefit"));

        let refused = |benefit: &AttributableBenefit| {
            let mut roster = EngineRoster::current();
            let refusal = roster
                .add_default(ServingFormat::Vllm, SGLANG, Some(benefit))
                .unwrap_err();
            assert!(!roster.is_default(ServingFormat::Vllm, SGLANG));
            match refusal {
                RosterRefusal::Benefit { cause } => cause,
                other => panic!("expected a benefit refusal, got {other:?}"),
            }
        };

        // Judged per model format: a benefit for another format supports nothing here.
        let other_format = benefit(Comparison::DefaultEngine {
            format: ServingFormat::Safetensors,
            incumbent: Engine::Backend(Backend::Transformers),
            candidate: SGLANG,
        });
        assert!(matches!(
            refused(&other_format),
            BenefitRefusal::OtherComparison { .. }
        ));

        // The arms ran on other hardware: the difference is not the engine's.
        let mut elsewhere = side("ordinary", measured(), 300.0);
        elsewhere.configuration.hardware = id("other-host");
        let unmatched = AttributableBenefit::from_report(
            sglang_over_vllm(),
            &report(
                side("candidate", measured(), 200.0),
                elsewhere,
                vec![ConfigurationField::Hardware],
            ),
        )
        .unwrap();
        assert_eq!(
            refused(&unmatched),
            BenefitRefusal::UnmatchedBaseline {
                fields: vec![ConfigurationField::Hardware]
            }
        );
        // Other model bytes are another comparison for an engine, not a benefit of it.
        let rebuilt = AttributableBenefit::from_report(
            sglang_over_vllm(),
            &report(
                converted(200.0),
                side("ordinary", measured(), 300.0),
                vec![
                    ConfigurationField::ModelBytes,
                    ConfigurationField::Precision,
                ],
            ),
        )
        .unwrap();
        assert_eq!(
            refused(&rebuilt),
            BenefitRefusal::UnmatchedBaseline {
                fields: vec![
                    ConfigurationField::ModelBytes,
                    ConfigurationField::Precision
                ]
            }
        );

        // Faster to the first token, but a quarter more GPU memory: the claim discloses
        // the regression, and a disclosed regression refuses the engine.
        let mut costly = side("candidate", measured(), 200.0);
        costly.objectives = objectives(200.0, 25.0);
        let regressed = AttributableBenefit::from_report(
            sglang_over_vllm(),
            &report(costly, side("ordinary", measured(), 300.0), Vec::new()),
        )
        .unwrap();
        assert_eq!(
            refused(&regressed),
            BenefitRefusal::Regression {
                objectives: BTreeSet::from([Objective::PeakGpuMemory])
            }
        );

        roster.add_optional(ServingFormat::Vllm, SGLANG).unwrap();
        let measured_benefit = benefit(sglang_over_vllm());
        assert!(measured_benefit.claim().regressions().is_empty());
        assert_eq!(
            measured_benefit.claim().components(),
            [label("candidate-path")]
        );
        roster
            .add_default(ServingFormat::Vllm, SGLANG, Some(&measured_benefit))
            .unwrap();
        assert_eq!(
            roster.defaults(ServingFormat::Vllm).collect::<Vec<_>>(),
            [VLLM, SGLANG]
        );
        assert_eq!(roster.optional(ServingFormat::Vllm).count(), 0);
        assert_eq!(
            roster.add_default(ServingFormat::Vllm, SGLANG, Some(&measured_benefit)),
            Err(RosterRefusal::AlreadyDefault {
                format: ServingFormat::Vllm,
                engine: SGLANG
            })
        );
    }

    #[test]
    fn a_fake_bench_run_or_no_measurement_backs_no_benefit() {
        // Review finding: a default engine or a GGUF conversion was approved from a
        // caller-written record digest, "real workload" flag and improved and regressed
        // lists, which a fake bench run, or nothing at all, could back. A benefit now
        // comes only from a CORE-08 improvement claim.
        let from = |candidate: Provenance, ordinary: Provenance| {
            AttributableBenefit::from_report(
                sglang_over_vllm(),
                &report(
                    side("candidate", candidate, 200.0),
                    side("ordinary", ordinary, 300.0),
                    Vec::new(),
                ),
            )
        };
        assert_eq!(
            from(simulated(), simulated()),
            Err(ReportError::FakeSubstrateIsNotEvidence)
        );
        assert_eq!(
            from(measured(), simulated()),
            Err(ReportError::FakeSubstrateIsNotEvidence)
        );
        assert_eq!(
            from(simulated(), measured()),
            Err(ReportError::FakeSubstrateIsNotEvidence)
        );
        // Measured, but no faster: no improvement is claimed.
        assert_eq!(
            AttributableBenefit::from_report(
                sglang_over_vllm(),
                &report(
                    side("candidate", measured(), 320.0),
                    side("ordinary", measured(), 300.0),
                    Vec::new(),
                ),
            ),
            Err(ReportError::NotImproved)
        );
        // Without an ordinary-workflow measurement there is nothing to attribute to.
        let no_ordinary = ComparisonReport::new(
            ObjectivePlan::new(Objective::TimeToFirstToken, 0.05).unwrap(),
            StateComparison::WarmLoad,
            ExperimentDesign {
                effect: EffectClass::Other,
                independent_trials: 8,
                trace: TracePattern::Mixed { seed: 3 },
                components: vec![label("candidate-path")],
                ablated_components: Vec::new(),
            },
            Vec::new(),
            side("candidate", measured(), 200.0),
            Baseline::Unavailable {
                reason: BaselineUnavailable::NoOrdinaryWorkflowForThisPath,
                detail: label("none"),
            },
            Baseline::Measured {
                sides: vec![side("upstream", measured(), 300.0)],
            },
        )
        .unwrap();
        assert_eq!(
            AttributableBenefit::from_report(sglang_over_vllm(), &no_ordinary),
            Err(ReportError::MissingBaseline {
                which: BaselineRole::OrdinaryWorkflow
            })
        );

        // The digests a benefit names are the measurement's own evidence.
        let measured_benefit = benefit(sglang_over_vllm());
        assert_eq!(
            measured_benefit.record(),
            measured().yougori_evidence().unwrap()
        );
        assert_eq!(
            measured_benefit.baseline_record(),
            measured().yougori_evidence().unwrap()
        );
        assert_eq!(
            measured_benefit.workload(),
            side("candidate", measured(), 200.0).configuration.fixture
        );
        assert_eq!(measured_benefit.comparison(), &sglang_over_vllm());
    }

    #[test]
    fn optional_engines_need_no_benefit_and_never_run_by_default() {
        let mut roster = EngineRoster::current();
        roster.add_optional(ServingFormat::Vllm, SGLANG).unwrap();
        assert_eq!(
            roster.optional(ServingFormat::Vllm).collect::<Vec<_>>(),
            [SGLANG]
        );
        assert!(!roster.is_default(ServingFormat::Vllm, SGLANG));
        assert_eq!(
            roster.add_optional(ServingFormat::Vllm, SGLANG),
            Err(RosterRefusal::AlreadyOptional {
                format: ServingFormat::Vllm,
                engine: SGLANG
            })
        );
        assert_eq!(
            roster.add_optional(ServingFormat::Vllm, VLLM),
            Err(RosterRefusal::AlreadyDefault {
                format: ServingFormat::Vllm,
                engine: VLLM
            })
        );
    }

    #[test]
    fn gguf_is_never_converted_only_to_resemble_another_backend() {
        let refusal = conversion()
            .approve(&ConversionReason::ResembleAnotherBackend)
            .unwrap_err();
        assert_eq!(refusal, ConversionRefusal::OnlyToResembleAnotherBackend);
        assert!(refusal
            .to_string()
            .contains("existing mmap/prequantized path"));

        let reason =
            |comparison| ConversionReason::AttributableBenefit(Box::new(benefit(comparison)));
        let mut same = conversion();
        same.target = ArtifactFormat::Gguf;
        assert_eq!(
            same.approve(&reason(same.comparison())),
            Err(ConversionRefusal::NotAConversion)
        );

        let mut other_artifact = conversion();
        other_artifact.artifact = id("other.gguf");
        assert!(matches!(
            conversion().approve(&reason(other_artifact.comparison())),
            Err(ConversionRefusal::Benefit {
                cause: BenefitRefusal::OtherComparison { .. }
            })
        ));
        assert!(matches!(
            conversion().approve(&reason(sglang_over_vllm())),
            Err(ConversionRefusal::Benefit { .. })
        ));

        // The conversion changes the bytes and their precision, and nothing else may
        // differ from the GGUF on its existing llama.cpp path.
        let converted_benefit = |ordinary: ComparisonSide, varied| {
            AttributableBenefit::from_report(
                conversion().comparison(),
                &report(converted(200.0), ordinary, varied),
            )
            .unwrap()
        };
        let lossy = vec![
            ConfigurationField::ModelBytes,
            ConfigurationField::Precision,
        ];
        let approved = conversion()
            .approve(&ConversionReason::AttributableBenefit(Box::new(
                converted_benefit(side("llama-cpp-gguf", measured(), 300.0), lossy.clone()),
            )))
            .unwrap();
        assert_eq!(approved.conversion(), &conversion());
        assert_eq!(approved.record(), measured().yougori_evidence().unwrap());
        let mut other_client = side("llama-cpp-gguf", measured(), 300.0);
        other_client.configuration.client = id("other-client");
        let mut varied = lossy;
        varied.push(ConfigurationField::Client);
        assert_eq!(
            conversion().approve(&ConversionReason::AttributableBenefit(Box::new(
                converted_benefit(other_client, varied)
            ))),
            Err(ConversionRefusal::Benefit {
                cause: BenefitRefusal::UnmatchedBaseline {
                    fields: vec![ConfigurationField::Client]
                }
            })
        );
        assert!(conversion()
            .approve(&reason(conversion().comparison()))
            .is_ok());
    }

    #[test]
    fn inputs_refuse_unknown_fields() {
        let json = serde_json::to_value(conversion()).unwrap();
        assert_eq!(
            serde_json::from_value::<GgufConversion>(json.clone()).unwrap(),
            conversion()
        );
        let mut extra = json;
        extra["benefit"] = true.into();
        assert!(serde_json::from_value::<GgufConversion>(extra).is_err());

        let json = serde_json::to_value(sglang_over_vllm()).unwrap();
        assert_eq!(
            json["default_engine"]["candidate"],
            serde_json::json!("sglang")
        );
        assert_eq!(
            json["default_engine"]["incumbent"],
            serde_json::json!({"backend": "vllm"})
        );
        assert_eq!(
            serde_json::from_value::<Comparison>(json.clone()).unwrap(),
            sglang_over_vllm()
        );
        let mut extra = json.clone();
        extra["default_engine"]["trials"] = 3.into();
        assert!(serde_json::from_value::<Comparison>(extra).is_err());
        let mut second_key = json;
        second_key["gguf_conversion"] = serde_json::json!({});
        assert!(serde_json::from_value::<Comparison>(second_key).is_err());

        // A benefit is written out with its comparison and claim; it has no reader, so
        // none is ever written by hand.
        let written = serde_json::to_value(benefit(sglang_over_vllm())).unwrap();
        assert_eq!(
            written["comparison"]["default_engine"]["candidate"],
            serde_json::json!("sglang")
        );
        assert!(written["claim"].is_object());
    }
}
