//! Tool and answer fidelity (S7 "Tool and answer fidelity", S9, S12 BENCH-04, S13 quality
//! evidence): trigger precision, recall and F1 with their denominators, schema accuracy
//! over triggered calls, task success over original attempts, and token or logprob
//! agreement only when tokenizer and configuration alignment is declared.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::error::ReportError;
use super::measured::{Measured, NotMeasuredReason};
use super::stats::{McNemarResult, Quotient, Ratio, SuccessRate, UndefinedReason};
use super::text::Label;
use crate::foundation::ids::Digest;

/// How one paired-corpus item went: how many tool calls the reference made, and the
/// candidate's calls and how many of them passed schema validation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolCallObservation {
    pub item: Label,
    pub reference_calls: u32,
    pub candidate_calls: u32,
    pub candidate_schema_valid_calls: u32,
}

/// S9: "Report trigger precision, recall and F1 on the paired corpus, schema accuracy
/// with its triggered-call denominator, and task success with the original attempts
/// denominator"; S7 adds parallel-tool success.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ToolFidelity {
    pub items: u64,
    pub true_positives: u64,
    pub false_positives: u64,
    pub false_negatives: u64,
    pub true_negatives: u64,
    /// TP / (TP + FP): over items where the candidate called a tool.
    pub precision: Ratio,
    /// TP / (TP + FN): over items where the reference called a tool.
    pub recall: Ratio,
    /// 2TP / (2TP + FP + FN).
    pub f1: Ratio,
    /// Schema-valid calls over every call the candidate triggered.
    pub schema_accuracy: Ratio,
    /// Over items where the reference made parallel calls (two or more): the candidate
    /// made the same number of calls and every one was schema-valid.
    pub parallel_tool_success: Ratio,
    /// Over every original attempt (S9, BENCH-04).
    pub task_success: SuccessRate,
}

impl ToolFidelity {
    /// Tallies the paired corpus. Each item appears once, and valid calls never exceed
    /// calls.
    pub fn from_observations(
        observations: &[ToolCallObservation],
        task_success: SuccessRate,
    ) -> Result<Self, ReportError> {
        let mut seen = BTreeSet::new();
        let (mut tp, mut fp, mut false_negatives, mut tn) = (0u64, 0u64, 0u64, 0u64);
        let (mut calls, mut valid_calls) = (0u64, 0u64);
        let (mut parallel_items, mut parallel_successes) = (0u64, 0u64);
        for observation in observations {
            if !seen.insert(&observation.item) {
                return Err(ReportError::DuplicatePairedItem);
            }
            if observation.candidate_schema_valid_calls > observation.candidate_calls {
                return Err(ReportError::InvalidRatio);
            }
            let triggered = observation.candidate_calls > 0;
            match (observation.reference_calls > 0, triggered) {
                (true, true) => tp += 1,
                (false, true) => fp += 1,
                (true, false) => false_negatives += 1,
                (false, false) => tn += 1,
            }
            if observation.reference_calls >= 2 {
                parallel_items += 1;
                if observation.candidate_calls == observation.reference_calls
                    && observation.candidate_schema_valid_calls == observation.candidate_calls
                {
                    parallel_successes += 1;
                }
            }
            calls += u64::from(observation.candidate_calls);
            valid_calls += u64::from(observation.candidate_schema_valid_calls);
        }
        Ok(Self {
            items: observations.len() as u64,
            true_positives: tp,
            false_positives: fp,
            false_negatives,
            true_negatives: tn,
            precision: Ratio::new(tp, tp + fp)?,
            recall: Ratio::new(tp, tp + false_negatives)?,
            f1: Ratio::new(2 * tp, 2 * tp + fp + false_negatives)?,
            schema_accuracy: Ratio::new(valid_calls, calls)?,
            parallel_tool_success: Ratio::new(parallel_successes, parallel_items)?,
            task_success,
        })
    }
}

/// BENCH-04 tool evidence: measured against a reference, or a recorded missing reference,
/// which is never a pass (S12).
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ToolFidelityEvidence {
    Measured { metrics: ToolFidelity },
    ReferenceUnavailable { reference: Label },
}

impl ToolFidelityEvidence {
    /// The metrics, or a refusal when no reference was available.
    pub fn metrics(&self) -> Result<&ToolFidelity, ReportError> {
        match self {
            Self::Measured { metrics } => Ok(metrics),
            Self::ReferenceUnavailable { .. } => Err(ReportError::ReferenceUnavailable),
        }
    }
}

/// What must match before token outputs or distributions can be compared (S9: "matched
/// tokenizer/template/weight/quantization/kernel settings"). The kernel configuration
/// digest covers kernels, batching and sampling settings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlignmentKey {
    pub tokenizer: Digest,
    pub chat_template: Digest,
    pub weights: Digest,
    pub quantization: Label,
    pub kernel_configuration: Digest,
}

strict_tagged_enum! {
/// Whether a side declares the configuration its tokens were produced under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AlignmentDeclaration (tag = "kind", wire = AlignmentDeclarationWire, wire_name = "AlignmentDeclarationWire") {
    Declared { key: AlignmentKey },
    NotDeclared,
}
}

/// A field of [`AlignmentKey`] that differs between two sides.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlignmentField {
    Tokenizer,
    ChatTemplate,
    Weights,
    Quantization,
    KernelConfiguration,
}

impl AlignmentKey {
    /// The fields in which two keys differ.
    pub fn differences(&self, other: &Self) -> Vec<AlignmentField> {
        [
            (AlignmentField::Tokenizer, self.tokenizer == other.tokenizer),
            (
                AlignmentField::ChatTemplate,
                self.chat_template == other.chat_template,
            ),
            (AlignmentField::Weights, self.weights == other.weights),
            (
                AlignmentField::Quantization,
                self.quantization == other.quantization,
            ),
            (
                AlignmentField::KernelConfiguration,
                self.kernel_configuration == other.kernel_configuration,
            ),
        ]
        .into_iter()
        .filter_map(|(field, same)| (!same).then_some(field))
        .collect()
    }
}

/// One side's generated tokens and, when available, its per-position probability
/// distributions over the shared vocabulary.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenTrace {
    pub alignment: AlignmentDeclaration,
    /// Deterministic (greedy) decoding. Necessary for a parity claim but never enough:
    /// temperature zero does not establish token identity (S9, S13 FAST-01).
    pub temperature_zero: bool,
    pub top1_token_ids: Vec<u32>,
    pub distributions: Measured<Vec<Vec<f64>>>,
}

/// Comparable evidence, or the reason it is not comparable.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Comparability<T> {
    Comparable { result: T },
    NotComparable { reason: NotComparableReason },
}

/// Why token evidence is not comparable (S9, S13).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NotComparableReason {
    AlignmentNotDeclared,
    ConfigurationMismatch { fields: Vec<AlignmentField> },
}

/// Top-1 agreement and, where both sides have distributions, mean KL divergence.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct TokenAgreement {
    pub top1_agreement: Ratio,
    pub identical_sequences: bool,
    /// Both sides decoded deterministically; with random sampling no parity is claimed.
    pub deterministic_sampling: bool,
    /// Mean KL(reference ‖ candidate) per position, in nats.
    pub mean_kl_divergence_nats: Measured<Quotient>,
}

const DISTRIBUTION_SUM_TOLERANCE: f64 = 1e-6;

fn check_distribution(distribution: &[f64]) -> Result<(), ReportError> {
    let valid = !distribution.is_empty()
        && distribution
            .iter()
            .all(|probability| probability.is_finite() && *probability >= 0.0)
        && (distribution.iter().sum::<f64>() - 1.0).abs() <= DISTRIBUTION_SUM_TOLERANCE;
    if valid {
        Ok(())
    } else {
        Err(ReportError::InvalidDistribution)
    }
}

/// KL(p ‖ q) in nats over one aligned vocabulary; undefined (unbounded) when q is zero
/// where p is not.
pub fn kl_divergence_nats(p: &[f64], q: &[f64]) -> Result<Quotient, ReportError> {
    check_distribution(p)?;
    check_distribution(q)?;
    if p.len() != q.len() {
        return Err(ReportError::InvalidDistribution);
    }
    let mut total = 0.0;
    for (p, q) in p.iter().zip(q) {
        if *p == 0.0 {
            continue;
        }
        if *q == 0.0 {
            return Ok(Quotient::Undefined {
                reason: UndefinedReason::UnboundedDivergence,
            });
        }
        total += p * (p / q).ln();
    }
    Ok(Quotient::Defined {
        value: total.max(0.0),
    })
}

/// Compares token outputs only when both sides declare the same alignment key; otherwise
/// the result is "not comparable", whatever the temperature (S9, S13).
pub fn token_agreement(
    candidate: &TokenTrace,
    reference: &TokenTrace,
) -> Result<Comparability<TokenAgreement>, ReportError> {
    let (candidate_key, reference_key) = match (&candidate.alignment, &reference.alignment) {
        (
            AlignmentDeclaration::Declared { key: candidate_key },
            AlignmentDeclaration::Declared { key: reference_key },
        ) => (candidate_key, reference_key),
        _ => {
            return Ok(Comparability::NotComparable {
                reason: NotComparableReason::AlignmentNotDeclared,
            })
        }
    };
    let fields = candidate_key.differences(reference_key);
    if !fields.is_empty() {
        return Ok(Comparability::NotComparable {
            reason: NotComparableReason::ConfigurationMismatch { fields },
        });
    }
    let matches = candidate
        .top1_token_ids
        .iter()
        .zip(&reference.top1_token_ids)
        .filter(|(left, right)| left == right)
        .count();
    // Unequal lengths count the extra positions as disagreements.
    let compared = candidate
        .top1_token_ids
        .len()
        .max(reference.top1_token_ids.len());
    let identical_sequences = candidate.top1_token_ids == reference.top1_token_ids;
    let mean_kl_divergence_nats = match (
        candidate.distributions.value(),
        reference.distributions.value(),
    ) {
        (Some(candidate_rows), Some(reference_rows)) => {
            if candidate_rows.len() != reference_rows.len() || candidate_rows.is_empty() {
                return Err(ReportError::InvalidDistribution);
            }
            let mut total = 0.0;
            let mut unbounded = false;
            for (reference_row, candidate_row) in reference_rows.iter().zip(candidate_rows) {
                match kl_divergence_nats(reference_row, candidate_row)? {
                    Quotient::Defined { value } => total += value,
                    Quotient::Undefined { .. } => unbounded = true,
                }
            }
            Measured::measured(if unbounded {
                Quotient::Undefined {
                    reason: UndefinedReason::UnboundedDivergence,
                }
            } else {
                Quotient::Defined {
                    value: total / reference_rows.len() as f64,
                }
            })
        }
        _ => Measured::not_measured(NotMeasuredReason::UnsupportedByBackend),
    };
    Ok(Comparability::Comparable {
        result: TokenAgreement {
            top1_agreement: Ratio::new(matches as u64, compared as u64)?,
            identical_sequences,
            deterministic_sampling: candidate.temperature_zero && reference.temperature_zero,
            mean_kl_divergence_nats,
        },
    })
}

/// A claim of identical output between two configurations (S9: "Do not claim 100%
/// answer parity across different kernels, batching, quantization or random sampling").
/// Only comparable, deterministic, identical token sequences with at least one compared
/// token and full top-1 agreement support it: never temperature zero alone, never across
/// a configuration mismatch, never on zero tokens, and never with a missing reference
/// (S12).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ParityClaim {
    agreement: TokenAgreement,
}

impl ParityClaim {
    /// Refuses evidence that is not comparable, not deterministic, compares no tokens or
    /// does not agree at every compared position.
    pub fn from_agreement(evidence: &Comparability<TokenAgreement>) -> Result<Self, ReportError> {
        let result = match evidence {
            Comparability::NotComparable { .. } => return Err(ReportError::NotComparableEvidence),
            Comparability::Comparable { result } => result,
        };
        if !result.deterministic_sampling {
            return Err(ReportError::RandomSampling);
        }
        let agreement = result.top1_agreement;
        if agreement.denominator() == 0 {
            return Err(ReportError::NoTokensCompared);
        }
        if agreement.numerator() != agreement.denominator() || !result.identical_sequences {
            return Err(ReportError::NotIdentical);
        }
        Ok(Self {
            agreement: result.clone(),
        })
    }

    pub fn agreement(&self) -> &TokenAgreement {
        &self.agreement
    }
}

/// S13 line 250: bit-identical modes and lossy capacity modes are distinguished in the
/// user-facing capability record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModeFidelity {
    BitIdentical,
    Lossy,
}

/// The change a quality certification is for (S13 FAST-03/04/06).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityChange {
    Quantization,
    LongContextMode,
    ToolChoice,
}

/// Layer 1: exact protocol and tool-schema conformance under S9.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolConformance {
    pub fixtures: u64,
    pub failures: u64,
}

/// Layer 2: model behaviour against a comparable reference.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ModelBehavior {
    pub token_agreement: Comparability<TokenAgreement>,
    pub paired_tasks: Measured<McNemarResult>,
    /// The fixture families used, such as a GSM8K-style set or needle retrieval.
    pub fixture_families: Vec<Label>,
}

/// The three layers of S13 quality evidence. No single fixture set certifies a new
/// quantization, long-context mode or tool choice: every layer must be present.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct QualityEvidence {
    pub change: CapabilityChange,
    pub fidelity: ModeFidelity,
    pub protocol_conformance: Measured<ProtocolConformance>,
    pub model_behavior: Measured<ModelBehavior>,
    /// Layer 3: completed agent tasks over every original attempt (BENCH-04).
    pub agent_tasks: Measured<SuccessRate>,
}

/// Which quality layer is missing or failing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QualityLayer {
    ProtocolConformance,
    ModelBehavior,
    AgentTasks,
}

impl QualityEvidence {
    /// Refuses certification unless protocol conformance has fixtures and no failures,
    /// model behaviour has comparable token evidence or a paired-task test, and agent
    /// tasks were measured.
    pub fn check_complete(&self) -> Result<(), ReportError> {
        let protocol = self
            .protocol_conformance
            .value()
            .is_some_and(|layer| layer.fixtures > 0 && layer.failures == 0);
        if !protocol {
            return Err(ReportError::IncompleteQualityEvidence {
                layer: QualityLayer::ProtocolConformance,
            });
        }
        let behavior = self.model_behavior.value().is_some_and(|layer| {
            matches!(layer.token_agreement, Comparability::Comparable { .. })
                || layer.paired_tasks.is_measured()
        });
        if !behavior {
            return Err(ReportError::IncompleteQualityEvidence {
                layer: QualityLayer::ModelBehavior,
            });
        }
        if !self.agent_tasks.is_measured() {
            return Err(ReportError::IncompleteQualityEvidence {
                layer: QualityLayer::AgentTasks,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::digest;
    use crate::foundation::report::fixtures::label;
    use crate::foundation::report::stats::PairedTable;

    fn observation(item: &str, reference: u32, calls: u32, valid: u32) -> ToolCallObservation {
        ToolCallObservation {
            item: label(item),
            reference_calls: reference,
            candidate_calls: calls,
            candidate_schema_valid_calls: valid,
        }
    }

    #[test]
    fn precision_recall_f1_and_schema_accuracy_keep_their_denominators() {
        // TP: a, b, c (calls 1, 2, 1; valid 1, 1, 1); FP: d (calls 1, valid 0);
        // FN: e, f; TN: g. The reference made parallel calls on b and e.
        let observations = vec![
            observation("a", 1, 1, 1),
            observation("b", 2, 2, 1),
            observation("c", 1, 1, 1),
            observation("d", 0, 1, 0),
            observation("e", 2, 0, 0),
            observation("f", 1, 0, 0),
            observation("g", 0, 0, 0),
        ];
        let tasks = SuccessRate::new(5, 8).unwrap();
        let fidelity = ToolFidelity::from_observations(&observations, tasks).unwrap();
        assert_eq!(fidelity.precision, Ratio::new(3, 4).unwrap());
        assert_eq!(fidelity.recall, Ratio::new(3, 5).unwrap());
        assert_eq!(fidelity.f1, Ratio::new(6, 9).unwrap());
        // F1 equals 2PR / (P + R).
        let (p, r) = (0.75, 0.6);
        let f1 = fidelity.f1.value().value().unwrap();
        assert!((f1 - 2.0 * p * r / (p + r)).abs() < 1e-12);
        // Schema accuracy counts triggered calls only: 3 valid of 5 calls, not of 7 items.
        assert_eq!(fidelity.schema_accuracy, Ratio::new(3, 5).unwrap());
        // Parallel-tool success: b made both calls but one was invalid, e made none.
        assert_eq!(fidelity.parallel_tool_success, Ratio::new(0, 2).unwrap());
        assert_eq!(fidelity.task_success.attempts(), 8);
        assert_eq!(fidelity.true_negatives, 1);
        let parallel =
            ToolFidelity::from_observations(&[observation("p", 3, 3, 3)], tasks).unwrap();
        assert_eq!(parallel.parallel_tool_success, Ratio::new(1, 1).unwrap());

        // No triggered calls: precision and schema accuracy are undefined, not zero.
        let silent = ToolFidelity::from_observations(&[observation("a", 1, 0, 0)], tasks).unwrap();
        assert_eq!(
            silent.precision.value(),
            Quotient::Undefined {
                reason: UndefinedReason::ZeroDenominator
            }
        );
        assert_eq!(silent.schema_accuracy.denominator(), 0);
        assert_eq!(silent.f1, Ratio::new(0, 1).unwrap());

        assert_eq!(
            ToolFidelity::from_observations(&[observation("a", 1, 1, 2)], tasks),
            Err(ReportError::InvalidRatio)
        );
        assert_eq!(
            ToolFidelity::from_observations(
                &[observation("a", 1, 1, 1), observation("a", 0, 0, 0)],
                tasks
            ),
            Err(ReportError::DuplicatePairedItem)
        );
    }

    #[test]
    fn a_missing_reference_is_recorded_and_never_a_pass() {
        let evidence = ToolFidelityEvidence::ReferenceUnavailable {
            reference: label("vendor-api-unavailable"),
        };
        assert_eq!(evidence.metrics(), Err(ReportError::ReferenceUnavailable));
    }

    fn key(quantization: &str) -> AlignmentKey {
        AlignmentKey {
            tokenizer: digest("yougori/test/v1", &[b"tokenizer"]),
            chat_template: digest("yougori/test/v1", &[b"template"]),
            weights: digest("yougori/test/v1", &[b"weights"]),
            quantization: label(quantization),
            kernel_configuration: digest("yougori/test/v1", &[b"kernels"]),
        }
    }

    fn trace(alignment: AlignmentDeclaration, tokens: Vec<u32>) -> TokenTrace {
        TokenTrace {
            alignment,
            temperature_zero: true,
            top1_token_ids: tokens,
            distributions: Measured::not_measured(NotMeasuredReason::UnsupportedByBackend),
        }
    }

    #[test]
    fn token_agreement_needs_declared_alignment() {
        // Temperature zero on both sides proves nothing without alignment.
        let undeclared = token_agreement(
            &trace(AlignmentDeclaration::NotDeclared, vec![1, 2, 3]),
            &trace(AlignmentDeclaration::NotDeclared, vec![1, 2, 3]),
        )
        .unwrap();
        assert_eq!(
            undeclared,
            Comparability::NotComparable {
                reason: NotComparableReason::AlignmentNotDeclared
            }
        );
        assert_eq!(
            ParityClaim::from_agreement(&undeclared),
            Err(ReportError::NotComparableEvidence)
        );

        // Different quantization is not comparable either.
        let mismatched = token_agreement(
            &trace(
                AlignmentDeclaration::Declared { key: key("fp8") },
                vec![1, 2, 3],
            ),
            &trace(
                AlignmentDeclaration::Declared { key: key("bf16") },
                vec![1, 2, 3],
            ),
        )
        .unwrap();
        assert_eq!(
            mismatched,
            Comparability::NotComparable {
                reason: NotComparableReason::ConfigurationMismatch {
                    fields: vec![AlignmentField::Quantization]
                }
            }
        );

        let aligned = token_agreement(
            &trace(
                AlignmentDeclaration::Declared { key: key("bf16") },
                vec![1, 2, 3, 4],
            ),
            &trace(
                AlignmentDeclaration::Declared { key: key("bf16") },
                vec![1, 2, 9],
            ),
        )
        .unwrap();
        match &aligned {
            Comparability::Comparable { result } => {
                assert_eq!(result.top1_agreement, Ratio::new(2, 4).unwrap());
                assert!(!result.identical_sequences);
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(
            ParityClaim::from_agreement(&aligned),
            Err(ReportError::NotIdentical)
        );
        let identical = token_agreement(
            &trace(
                AlignmentDeclaration::Declared { key: key("bf16") },
                vec![5, 6],
            ),
            &trace(
                AlignmentDeclaration::Declared { key: key("bf16") },
                vec![5, 6],
            ),
        )
        .unwrap();
        assert!(ParityClaim::from_agreement(&identical).is_ok());

        // Identical text under random sampling is not parity.
        let mut sampled = trace(
            AlignmentDeclaration::Declared { key: key("bf16") },
            vec![5, 6],
        );
        sampled.temperature_zero = false;
        let sampled = token_agreement(
            &sampled,
            &trace(
                AlignmentDeclaration::Declared { key: key("bf16") },
                vec![5, 6],
            ),
        )
        .unwrap();
        assert_eq!(
            ParityClaim::from_agreement(&sampled),
            Err(ReportError::RandomSampling)
        );
    }

    #[test]
    fn a_parity_claim_needs_compared_tokens_and_full_agreement() {
        // Review probe a_parity_claim_from_zero_tokens: two empty traces counted as
        // identical, so parity rested on zero tokens (top-1 agreement 0/0). Refused now.
        let empty = trace(AlignmentDeclaration::Declared { key: key("bf16") }, vec![]);
        let agreement = token_agreement(&empty, &empty.clone()).unwrap();
        match &agreement {
            Comparability::Comparable { result } => {
                assert_eq!(result.top1_agreement.denominator(), 0);
                assert!(result.identical_sequences);
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(
            ParityClaim::from_agreement(&agreement),
            Err(ReportError::NoTokensCompared)
        );
        // Partial agreement is no parity either: 2 of 3 positions agree.
        let partial = token_agreement(
            &trace(
                AlignmentDeclaration::Declared { key: key("bf16") },
                vec![1, 2, 3],
            ),
            &trace(
                AlignmentDeclaration::Declared { key: key("bf16") },
                vec![1, 2, 4],
            ),
        )
        .unwrap();
        assert_eq!(
            ParityClaim::from_agreement(&partial),
            Err(ReportError::NotIdentical)
        );
        // Full agreement over at least one token is parity.
        let full = token_agreement(
            &trace(AlignmentDeclaration::Declared { key: key("bf16") }, vec![7]),
            &trace(AlignmentDeclaration::Declared { key: key("bf16") }, vec![7]),
        )
        .unwrap();
        let claim = ParityClaim::from_agreement(&full).unwrap();
        assert_eq!(claim.agreement().top1_agreement, Ratio::new(1, 1).unwrap());
    }

    #[test]
    fn kl_divergence_of_aligned_distributions() {
        let p = [0.5, 0.5];
        let q = [0.25, 0.75];
        let expected = 0.5 * (0.5f64 / 0.25).ln() + 0.5 * (0.5f64 / 0.75).ln();
        let value = kl_divergence_nats(&p, &q).unwrap().value().unwrap();
        assert!((value - expected).abs() < 1e-12);
        assert_eq!(
            kl_divergence_nats(&p, &p).unwrap(),
            Quotient::Defined { value: 0.0 }
        );
        assert_eq!(
            kl_divergence_nats(&p, &[1.0, 0.0]).unwrap(),
            Quotient::Undefined {
                reason: UndefinedReason::UnboundedDivergence
            }
        );
        assert_eq!(
            kl_divergence_nats(&p, &[0.5, 0.6]),
            Err(ReportError::InvalidDistribution)
        );
        assert_eq!(
            kl_divergence_nats(&p, &[0.2, 0.3, 0.5]),
            Err(ReportError::InvalidDistribution)
        );

        let mut candidate = trace(AlignmentDeclaration::Declared { key: key("bf16") }, vec![0]);
        candidate.distributions = Measured::measured(vec![q.to_vec()]);
        let mut reference = trace(AlignmentDeclaration::Declared { key: key("bf16") }, vec![0]);
        reference.distributions = Measured::measured(vec![p.to_vec()]);
        match token_agreement(&candidate, &reference).unwrap() {
            Comparability::Comparable { result } => {
                let mean = result
                    .mean_kl_divergence_nats
                    .value()
                    .and_then(Quotient::value)
                    .unwrap();
                assert!((mean - expected).abs() < 1e-12);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn one_fixture_set_alone_never_certifies() {
        let gsm8k_only = QualityEvidence {
            change: CapabilityChange::Quantization,
            fidelity: ModeFidelity::Lossy,
            protocol_conformance: Measured::not_measured(NotMeasuredReason::NotRecorded),
            model_behavior: Measured::measured(ModelBehavior {
                token_agreement: Comparability::NotComparable {
                    reason: NotComparableReason::AlignmentNotDeclared,
                },
                paired_tasks: Measured::measured(
                    PairedTable {
                        both_succeeded: 180,
                        only_baseline_succeeded: 6,
                        only_candidate_succeeded: 4,
                        both_failed: 10,
                    }
                    .mcnemar_exact()
                    .unwrap(),
                ),
                fixture_families: vec![label("gsm8k-style-200")],
            }),
            agent_tasks: Measured::not_measured(NotMeasuredReason::NotRecorded),
        };
        assert_eq!(
            gsm8k_only.check_complete(),
            Err(ReportError::IncompleteQualityEvidence {
                layer: QualityLayer::ProtocolConformance
            })
        );
        let mut layered = gsm8k_only.clone();
        layered.protocol_conformance = Measured::measured(ProtocolConformance {
            fixtures: 40,
            failures: 0,
        });
        assert_eq!(
            layered.check_complete(),
            Err(ReportError::IncompleteQualityEvidence {
                layer: QualityLayer::AgentTasks
            })
        );
        layered.agent_tasks = Measured::measured(SuccessRate::new(18, 20).unwrap());
        layered.check_complete().unwrap();
        let mut failing = layered.clone();
        failing.protocol_conformance = Measured::measured(ProtocolConformance {
            fixtures: 40,
            failures: 1,
        });
        assert!(failing.check_complete().is_err());
    }
}
