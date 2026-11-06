//! The VM-N3 experiment on fakes: seed known policy and lifecycle defects into the
//! models, then compare hand-written probes with generated mutations on detection, false
//! alarms, test cost and counterexample usefulness (VM §9.3, line 2377).
//!
//! - Hand-written probes are fixed scripts, one per VM-P scenario they mirror, run in the
//!   benign environment plus the injections the probe itself sets up.
//! - Generated mutations are the exhaustive check of the model under every injection of
//!   the threat model, which yields shortest counterexamples and missing assumptions.
//! - Ground truth is each defect's expected violation, written before either method ran;
//!   one defect is masked by another guard (an equivalent mutant), and every correct model
//!   is a control, so a report there is a false alarm.
//!
//! Results are recorded with `foundation::report` statistics under the fake-substrate
//! provenance, which backs no security claim, and the conclusion is at most
//! "inconclusive": the same author wrote the defects, probes and models.

use std::collections::BTreeSet;

use serde::Serialize;

use super::contract::{
    run_script, Defect, DefectClass, Injection, InvariantId, ModelConfig, ModelKind,
};
use super::explore::ScriptStep::{self, Attack, Setup};
use super::mutation::{counterexample, Checker};
use super::ModelError;
use crate::foundation::ids::{Digest, DigestBuilder};
use crate::foundation::report::{
    Label, McNemarResult, PairedOutcome, PairedTable, Provenance, Ratio, SuccessRate,
};

/// Domain of the experiment's evidence digest.
pub const EXPERIMENT_DOMAIN: &str = "yougori/sandbox/models/seeded-defects/v1";

/// A hand-written probe: a fixed script mirroring one VM-P scenario.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct HandProbe {
    pub name: &'static str,
    pub scenario: &'static str,
    pub model: ModelKind,
    pub injections: &'static [Injection],
    pub steps: &'static [ScriptStep],
}

/// The hand-written probe suite.
pub const HAND_PROBES: [HandProbe; 15] = [
    HandProbe {
        name: "exact payload after approval",
        scenario: "VM-P30",
        model: ModelKind::Effect,
        injections: &[Injection::ApprovalPayloadChanged],
        steps: &[
            Setup("authorize"),
            Setup("reserve"),
            Setup("change payload after approval"),
            Attack("dispatch"),
        ],
    },
    HandProbe {
        name: "cross-tenant ticket",
        scenario: "VM-P13",
        model: ModelKind::Effect,
        injections: &[Injection::RelayIdentitySpoofed],
        steps: &[
            Setup("authorize"),
            Setup("reserve"),
            Setup("spoof tenant identity"),
            Attack("dispatch"),
        ],
    },
    HandProbe {
        name: "retry after a lost response",
        scenario: "VM-P31",
        model: ModelKind::Effect,
        injections: &[Injection::ResponseLost],
        steps: &[
            Setup("authorize"),
            Setup("reserve"),
            Setup("dispatch"),
            Setup("response lost after provider committed"),
            Attack("retry"),
        ],
    },
    HandProbe {
        name: "authorization outage",
        scenario: "VM-P13",
        model: ModelKind::Effect,
        injections: &[Injection::AuthorizationUnavailable],
        steps: &[
            Setup("authorization service unavailable"),
            Attack("authorize"),
            Attack("reserve"),
            Attack("dispatch"),
        ],
    },
    HandProbe {
        name: "authorization after the revocation acknowledgment",
        scenario: "VM-P14",
        model: ModelKind::Lifecycle,
        injections: &[],
        steps: &[
            Setup("reserve resources"),
            Setup("ready perimeter"),
            Setup("create VM"),
            Setup("check boot evidence"),
            Setup("activate authority"),
            Setup("start workload"),
            Setup("revoke"),
            Setup("propagate revocation"),
            Setup("acknowledge revocation"),
            Attack("authorize new operation"),
        ],
    },
    HandProbe {
        name: "cleanup retry after revocation",
        scenario: "VM-P24",
        model: ModelKind::Lifecycle,
        injections: &[],
        steps: &[
            Setup("reserve resources"),
            Setup("ready perimeter"),
            Setup("create VM"),
            Setup("check boot evidence"),
            Setup("activate authority"),
            Setup("start workload"),
            Setup("revoke"),
            Setup("propagate revocation"),
            Setup("acknowledge revocation"),
            Setup("terminate VM"),
            Setup("finish termination"),
            Setup("cleanup fails"),
            Setup("retry cleanup"),
        ],
    },
    HandProbe {
        name: "authority before boot evidence",
        scenario: "VM-P01",
        model: ModelKind::Lifecycle,
        injections: &[],
        steps: &[
            Setup("reserve resources"),
            Setup("ready perimeter"),
            Setup("create VM"),
            Attack("activate authority"),
        ],
    },
    HandProbe {
        name: "engine crash during revocation",
        scenario: "VM-P19",
        model: ModelKind::Lifecycle,
        injections: &[Injection::EngineCrash],
        steps: &[
            Setup("reserve resources"),
            Setup("ready perimeter"),
            Setup("create VM"),
            Setup("check boot evidence"),
            Setup("activate authority"),
            Setup("start workload"),
            Setup("revoke"),
            Setup("engine crash and recovery"),
            Attack("check boot evidence"),
            Attack("activate authority"),
        ],
    },
    HandProbe {
        name: "competing reservations",
        scenario: "VM-P32",
        model: ModelKind::Budget,
        injections: &[Injection::ConcurrentRequests],
        steps: &[
            Setup("begin reservation for op 0"),
            Setup("begin reservation for op 1"),
            Setup("commit reservation for op 0"),
            Attack("commit reservation for op 1"),
        ],
    },
    HandProbe {
        name: "header bytes are counted",
        scenario: "VM-P33",
        model: ModelKind::Budget,
        injections: &[],
        steps: &[
            Setup("begin reservation for op 0"),
            Setup("commit reservation for op 0"),
            Setup("send header for op 0"),
            Setup("send payload for op 0"),
            Setup("send payload for op 0"),
            Setup("send payload for op 0"),
        ],
    },
    HandProbe {
        name: "restore after revocation",
        scenario: "VM-P21",
        model: ModelKind::Snapshot,
        injections: &[Injection::SnapshotEpochRestored],
        steps: &[
            Setup("attach tenant inputs"),
            Setup("approve action"),
            Setup("take snapshot"),
            Setup("revoke identity"),
            Attack("restore snapshot 0"),
            Attack("use approval on instance 1"),
        ],
    },
    HandProbe {
        name: "dirty snapshot into the pool",
        scenario: "VM-P43",
        model: ModelKind::Snapshot,
        injections: &[],
        steps: &[
            Setup("take snapshot"),
            Setup("promote snapshot 0 to pool"),
            Setup("attach tenant inputs"),
            Setup("take snapshot"),
            Attack("promote snapshot 1 to pool"),
        ],
    },
    HandProbe {
        name: "DNS rebinding",
        scenario: "VM-P07",
        model: ModelKind::Egress,
        injections: &[Injection::HostileGuest, Injection::StaleDnsAnswer],
        steps: &[Setup("send rebinding name via relay")],
    },
    HandProbe {
        name: "forged guest identity",
        scenario: "VM-P29",
        model: ModelKind::Egress,
        injections: &[Injection::HostileGuest, Injection::RelayIdentitySpoofed],
        steps: &[Setup("send other-tenant name via relay spoofing identity")],
    },
    HandProbe {
        name: "default egress denial",
        scenario: "VM-P06",
        model: ModelKind::Egress,
        injections: &[Injection::HostileGuest],
        steps: &[Setup("send forbidden address directly")],
    },
];

/// What one method reported for one model variant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MethodOutcome {
    /// Some invariant was reported violated.
    pub detected: bool,
    pub violations: Vec<InvariantId>,
    /// Probe steps executed, or states explored.
    pub cost: u64,
    /// Steps of the reported trace for the expected (else the first) violation.
    pub trace_steps: Option<usize>,
    /// The report names the missing enforcement assumption.
    pub names_missing_assumption: bool,
    /// Probes that could not run on this variant (a setup step was not offered).
    pub aborted_probes: usize,
}

/// One seeded defect, or a correct-model control (`defect: None`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DefectRow {
    pub defect: Option<Defect>,
    pub model: ModelKind,
    pub class: Option<DefectClass>,
    pub expected: Option<InvariantId>,
    pub probes: MethodOutcome,
    pub generated: MethodOutcome,
}

/// One method across the experiment.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct MethodSummary {
    /// Detected over the defects expected to break an invariant.
    pub detection: SuccessRate,
    /// Reports over the variants where nothing should break (controls, masked defects).
    pub false_alarms: Ratio,
    pub cost: u64,
    /// Detections whose report named the missing assumption.
    pub assumptions_named: Ratio,
    /// Total steps of the reported traces of detections, with their count.
    pub trace_steps: u64,
    pub traces: u64,
}

/// The conclusion the experiment may state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "conclusion", rename_all = "snake_case")]
pub enum Conclusion {
    Inconclusive { reasons: Vec<&'static str> },
}

/// The recorded experiment.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SeededDefectReport {
    pub rows: Vec<DefectRow>,
    pub probes: MethodSummary,
    pub generated: MethodSummary,
    /// Paired detection over the defects expected to break an invariant: probes are the
    /// baseline, generated mutations the candidate.
    pub paired: PairedTable,
    pub mcnemar: McNemarResult,
    pub provenance: Provenance,
    pub conclusion: Conclusion,
}

impl SeededDefectReport {
    /// The evidence a security claim would need: always refused, because the experiment
    /// ran on the fake substrate.
    pub fn security_claim(&self) -> Result<Digest, ModelError> {
        Ok(self.provenance.yougori_evidence()?)
    }
}

fn run_probes(kind: ModelKind, defect: Option<Defect>) -> Result<MethodOutcome, ModelError> {
    let mut outcome = MethodOutcome {
        detected: false,
        violations: Vec::new(),
        cost: 0,
        trace_steps: None,
        names_missing_assumption: false,
        aborted_probes: 0,
    };
    let expected = defect.and_then(Defect::expected_violation);
    let mut seen = BTreeSet::new();
    for probe in HAND_PROBES.iter().filter(|probe| probe.model == kind) {
        let config = ModelConfig::correct()
            .with_injections(probe.injections.iter().copied())
            .with_defects(defect);
        match run_script(kind, &config, probe.steps) {
            Ok(run) => {
                outcome.cost += run.executed as u64;
                for (invariant, step) in &run.violations {
                    if seen.insert(*invariant) {
                        outcome.violations.push(*invariant);
                    }
                    let better = outcome.trace_steps.is_none() || Some(*invariant) == expected;
                    if better {
                        outcome.trace_steps = Some(*step);
                    }
                }
            }
            Err(ModelError::ScriptAborted { step, .. }) => {
                outcome.aborted_probes += 1;
                outcome.cost += step.saturating_sub(1) as u64;
            }
            Err(error) => return Err(error),
        }
    }
    outcome.detected = !outcome.violations.is_empty();
    Ok(outcome)
}

fn run_generated(
    checker: &mut Checker,
    kind: ModelKind,
    defect: Option<Defect>,
) -> Result<MethodOutcome, ModelError> {
    let config = ModelConfig::threat_model().with_defects(defect);
    let result = checker.check(kind, &config)?;
    let violations: Vec<InvariantId> = result.violations.iter().map(|v| v.invariant).collect();
    let reported = defect
        .and_then(Defect::expected_violation)
        .filter(|expected| violations.contains(expected))
        .or_else(|| violations.first().copied());
    let (trace_steps, names_missing_assumption) = match reported {
        Some(invariant) => {
            let name = defect.map_or_else(|| "correct model".to_string(), |d| format!("{d:?}"));
            let found = counterexample(checker, kind, &config, invariant, &name)?;
            (
                found.as_ref().map(|c| c.trace.steps.len()),
                found.is_some_and(|c| c.missing.iter().flatten().any(|m| m.guard.is_some())),
            )
        }
        None => (None, false),
    };
    Ok(MethodOutcome {
        detected: !violations.is_empty(),
        violations,
        cost: result.states as u64,
        trace_steps,
        names_missing_assumption,
        aborted_probes: 0,
    })
}

fn summarize(
    rows: &[DefectRow],
    method: impl Fn(&DefectRow) -> &MethodOutcome,
) -> Result<MethodSummary, ModelError> {
    let breaking: Vec<&DefectRow> = rows.iter().filter(|row| row.expected.is_some()).collect();
    let quiet: Vec<&DefectRow> = rows.iter().filter(|row| row.expected.is_none()).collect();
    let detected: Vec<&MethodOutcome> = breaking
        .iter()
        .map(|row| method(row))
        .filter(|outcome| outcome.detected)
        .collect();
    Ok(MethodSummary {
        detection: SuccessRate::new(detected.len() as u64, breaking.len() as u64)?,
        false_alarms: Ratio::new(
            quiet.iter().filter(|row| method(row).detected).count() as u64,
            quiet.len() as u64,
        )?,
        cost: rows.iter().map(|row| method(row).cost).sum(),
        assumptions_named: Ratio::new(
            detected
                .iter()
                .filter(|o| o.names_missing_assumption)
                .count() as u64,
            detected.len() as u64,
        )?,
        trace_steps: detected
            .iter()
            .filter_map(|o| o.trace_steps)
            .map(|steps| steps as u64)
            .sum(),
        traces: detected.iter().filter(|o| o.trace_steps.is_some()).count() as u64,
    })
}

/// Runs the experiment: every seeded defect and every correct-model control, by both
/// methods.
pub fn run_seeded_defect_experiment(
    checker: &mut Checker,
) -> Result<SeededDefectReport, ModelError> {
    let kinds: BTreeSet<ModelKind> = Defect::ALL.iter().map(|defect| defect.model()).collect();
    let mut rows = Vec::new();
    for kind in &kinds {
        rows.push(DefectRow {
            defect: None,
            model: *kind,
            class: None,
            expected: None,
            probes: run_probes(*kind, None)?,
            generated: run_generated(checker, *kind, None)?,
        });
    }
    for defect in Defect::ALL {
        rows.push(DefectRow {
            defect: Some(defect),
            model: defect.model(),
            class: Some(defect.class()),
            expected: defect.expected_violation(),
            probes: run_probes(defect.model(), Some(defect))?,
            generated: run_generated(checker, defect.model(), Some(defect))?,
        });
    }
    let probes = summarize(&rows, |row| &row.probes)?;
    let generated = summarize(&rows, |row| &row.generated)?;
    let pairs: Vec<PairedOutcome> = rows
        .iter()
        .filter(|row| row.expected.is_some())
        .filter_map(|row| row.defect.map(|defect| (row, defect)))
        .map(|(row, defect)| {
            Ok(PairedOutcome {
                item: Label::new(format!("{defect:?}"))?,
                baseline_succeeded: row.probes.detected,
                candidate_succeeded: row.generated.detected,
            })
        })
        .collect::<Result<_, ModelError>>()?;
    let paired = PairedTable::from_pairs(&pairs)?;
    let mcnemar = paired.mcnemar_exact()?;
    let mut reasons = vec![
        "the experiment ran on fakes: the fake substrate backs no security claim",
        "the same author seeded the defects and wrote the probes and the models, so the \
         comparison is biased",
        "a model check covers only what the model includes, not the real enforcement boundary",
    ];
    if mcnemar.p_value_two_sided >= 0.05 {
        reasons.push("too few discordant defects for the paired test to separate the methods");
    }
    let rows_json = serde_json::to_vec(&rows).map_err(|_| ModelError::Encoding)?;
    let evidence = DigestBuilder::new(EXPERIMENT_DOMAIN)
        .bytes(&rows_json)
        .finish();
    // Report reads back only claim-free provenances; this one is labelled fake on purpose.
    let provenance: Provenance = serde_json::from_value(serde_json::json!({
        "kind": "fake_substrate",
        "evidence": evidence,
    }))
    .map_err(|_| ModelError::Encoding)?;
    Ok(SeededDefectReport {
        rows,
        probes,
        generated,
        paired,
        mcnemar,
        provenance,
        conclusion: Conclusion::Inconclusive { reasons },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::report::ReportError;
    use crate::sandbox_contract::models::explore::Bounds;

    #[test]
    fn every_probe_runs_on_the_correct_model_without_a_false_alarm() {
        for probe in HAND_PROBES {
            let config = ModelConfig::correct().with_injections(probe.injections.iter().copied());
            let run = run_script(probe.model, &config, probe.steps).unwrap();
            assert!(run.violations.is_empty(), "{}", probe.name);
            // Attack steps are either refused or harmless; setup steps all ran.
            let setups = probe
                .steps
                .iter()
                .filter(|step| matches!(step, Setup(_)))
                .count();
            assert!(run.executed >= setups, "{}", probe.name);
        }
    }

    #[test]
    fn the_seeded_defect_comparison_is_recorded_as_fake_and_inconclusive() {
        let mut checker = Checker::new(Bounds::DEFAULT);
        let report = run_seeded_defect_experiment(&mut checker).unwrap();
        assert_eq!(report.rows.len(), 5 + Defect::ALL.len());
        // Generated mutations find every defect that breaks an invariant, with no false
        // alarm on the controls or the masked defect.
        assert_eq!(report.generated.detection.successes(), 14);
        assert_eq!(report.generated.detection.attempts(), 14);
        assert_eq!(report.generated.false_alarms.numerator(), 0);
        assert_eq!(report.generated.false_alarms.denominator(), 6);
        assert_eq!(report.generated.assumptions_named.numerator(), 14);
        // The probes miss the two defects that need a combination they do not script.
        assert_eq!(report.probes.detection.successes(), 12);
        assert_eq!(report.probes.false_alarms.numerator(), 0);
        assert_eq!(report.probes.assumptions_named.numerator(), 0);
        let missed: Vec<Defect> = report
            .rows
            .iter()
            .filter(|row| row.expected.is_some() && !row.probes.detected)
            .filter_map(|row| row.defect)
            .collect();
        assert_eq!(
            missed,
            vec![Defect::HeaderNotCounted, Defect::CloneKeepsGeneration]
        );
        // Every generated detection reports the expected invariant.
        for row in report.rows.iter().filter(|row| row.expected.is_some()) {
            let expected = row.expected.unwrap();
            assert!(
                row.generated.violations.contains(&expected),
                "{:?}",
                row.defect
            );
        }
        // Probes are far cheaper; the paired test cannot separate the methods.
        assert!(report.probes.cost < report.generated.cost);
        assert_eq!(report.paired.only_candidate_succeeded, 2);
        assert_eq!(report.paired.only_baseline_succeeded, 0);
        assert!((report.mcnemar.p_value_two_sided - 0.5).abs() < 1e-12);
        // Fake-substrate provenance, no security claim, at most inconclusive.
        assert!(report.provenance.is_fake_substrate());
        assert_eq!(
            report.security_claim(),
            Err(ModelError::Report(ReportError::FakeSubstrateIsNotEvidence))
        );
        let Conclusion::Inconclusive { reasons } = &report.conclusion;
        assert!(reasons.len() >= 4);
        // The evidence digest is reproducible.
        let again = run_seeded_defect_experiment(&mut checker).unwrap();
        assert_eq!(again.provenance, report.provenance);
    }
}
