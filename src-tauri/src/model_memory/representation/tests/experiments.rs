//! The four experiments on fakes, each ending in comparison reports with fake-substrate
//! provenance and a claim record whose computed outcome the module docs state.

use std::collections::BTreeMap;

use super::super::claims::*;
use super::super::codec::{encode, DEFAULT_LEVEL};
use super::super::delta::{ColdRecoveryCost, DeltaDecision, DeltaLimits, DeltaStore, Parent};
use super::super::differential::{choose_loader, plan, IndexHashCost, LoaderChoice, RequiredSet};
use super::super::evidence::*;
use super::super::policy::{shadow_evaluate, HandCodedPolicy, OutcomeModel};
use super::super::selection::{
    select, strongest_uniform, CompressedForm, Conditions, CostModel, RangeCandidate,
};
use super::claims_tests::interference_not_measured;
use super::policy_tests::{batch_arms, config, input, table, TableModel, GIB};
use super::*;
use crate::foundation::ids::digest;
use crate::foundation::report::{
    BaselineRole, BaselineUnavailable, BenchId, ComparisonReport, EffectClass, ImprovementClaim,
    Label, Objective, Quantile, ReportError, StartTemperature, StateComparison,
};

const BURSTS: usize = 5;
const PER_BURST: usize = 6;
const PREFILL_SECONDS: f64 = 0.001;

fn label(text: &str) -> Label {
    Label::new(text).unwrap()
}

/// Common random numbers: trial `i` of every arm gets the same ±2% factor.
fn noise(seed: u64, index: usize) -> f64 {
    let mut rng = SeededRng::new(seed ^ (index as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
    1.0 + 0.02 * (rng.below(2001) as f64 / 1000.0 - 1.0)
}

fn arm(name: &str, seed: u64, weights_seconds: f64, extra_seconds: f64, bytes: u64) -> TrialArm {
    let bursts = (0..BURSTS)
        .map(|burst| {
            (0..PER_BURST)
                .map(|trial| {
                    let factor = noise(seed, burst * PER_BURST + trial);
                    let weights = weights_seconds * factor;
                    Trial {
                        weights_usable_seconds: weights,
                        first_token_seconds: weights + extra_seconds + PREFILL_SECONDS,
                        transferred_bytes: bytes,
                        storage_read_bytes: bytes,
                    }
                })
                .collect()
        })
        .collect();
    TrialArm {
        name: label(name),
        bursts,
    }
}

fn experiment(
    name: &str,
    temperature: StartTemperature,
    states: StateComparison,
    effect: EffectClass,
    component: &str,
) -> FakeExperiment {
    FakeExperiment {
        bench: BenchId::Bench02,
        name: label(name),
        temperature,
        states,
        effect,
        trace_seed: 42,
        model_bytes: digest("yougori/test/experiment/v1", &[name.as_bytes()]),
        fixture: digest("yougori/test/fixture/v1", &[name.as_bytes()]),
        quantile: Quantile::P50,
        max_time_to_first_token_nanos: 60_000_000_000,
        component: label(component),
        declared: Objective::TimeToFirstToken,
    }
}

fn upstream(detail: &str, reason: BaselineUnavailable) -> UnavailableUpstream {
    UnavailableUpstream {
        reason,
        detail: label(detail),
    }
}

/// The report backs schema and comparison validation only.
fn assert_fake_only(report: &ComparisonReport) {
    assert!(report.candidate().provenance.is_fake_substrate());
    assert_eq!(
        report.candidate().provenance.yougori_evidence(),
        Err(ReportError::FakeSubstrateIsNotEvidence)
    );
    assert!(report.candidate().provenance.comparable_evidence().is_ok());
    assert!(ImprovementClaim::from_report(report, BaselineRole::OrdinaryWorkflow).is_err());
    assert!(ImprovementClaim::from_report(report, BaselineRole::StrongestUpstream).is_err());
    assert!(report
        .candidate()
        .objectives
        .energy_per_completed_request_joules
        .reason()
        .is_some());
    assert!(report
        .candidate()
        .objectives
        .peak_gpu_memory_bytes
        .reason()
        .is_some());
}

#[test]
fn records_of_simulated_trials_are_valid_fake_substrate_records() {
    let setup = experiment(
        "evidence-check",
        StartTemperature::Cold,
        StateComparison::ColdLoad,
        EffectClass::Other,
        "check",
    );
    let records = fake_records(&setup, &arm("candidate", 1, 0.5, 0.0, 100)).unwrap();
    assert_eq!(records.len(), BURSTS * PER_BURST);
    for record in &records {
        record.validate().unwrap();
        assert_eq!(
            record.substrate,
            crate::foundation::report::RunSubstrate::FakeTimeControlled
        );
    }
    let invalid = TrialArm {
        name: label("bad"),
        bursts: vec![vec![Trial {
            weights_usable_seconds: 1.0,
            first_token_seconds: 0.5,
            transferred_bytes: 0,
            storage_read_bytes: 0,
        }]],
    };
    assert!(matches!(
        fake_records(&setup, &invalid),
        Err(EvidenceError::InvalidTrial { .. })
    ));
    assert!(matches!(
        fake_records(
            &setup,
            &TrialArm {
                name: label("empty"),
                bursts: Vec::new()
            }
        ),
        Err(EvidenceError::NoTrials { .. })
    ));
}

/// §4.2: the differential path against the full loader on four families.
#[test]
fn differential_materialization_claim_is_inconclusive() {
    let tensors = |seed: u64, count: usize| -> Vec<(&'static str, Vec<u8>)> {
        ["a", "b", "c", "d"][..count]
            .iter()
            .enumerate()
            .map(|(index, name)| (*name, bf16_weights(seed + index as u64, 512, 0.02)))
            .collect()
    };
    let base_tensors = tensors(100, 4);
    let base = build_model(&ModelSpec::single(base_tensors.clone()));
    let mut adapter_spec = ModelSpec::single(base_tensors.clone());
    adapter_spec.files.push(WeightFile::aligned(
        "adapter.safetensors",
        vec![("lora.a", bf16_weights(110, 256, 0.01))],
    ));
    adapter_spec.adapters = vec![digest("yougori/test/adapter/v1", &[b"lora"])];
    let mut checkpoint = base_tensors.clone();
    checkpoint[1].1 = fine_tune(&checkpoint[1].1, 120, 0.01);
    let dense: Vec<_> = base_tensors
        .iter()
        .enumerate()
        .map(|(index, (name, bytes))| (*name, fine_tune(bytes, 130 + index as u64, 0.002)))
        .collect();
    let mut shifted = ModelSpec::single(base_tensors.clone());
    shifted.files[0].header_length_bytes = ALIGNED_HEADER + 1;
    let workloads = [
        ("adapter-family", build_model(&adapter_spec)),
        (
            "checkpoint-family",
            build_model(&ModelSpec::single(checkpoint)),
        ),
        ("dense-fine-tune", build_model(&ModelSpec::single(dense))),
        ("shifted-layout", build_model(&shifted)),
    ];
    let (residents, _) = resident_model(&base);
    let link = 1.0e6;
    let mut comparisons = Vec::new();
    let mut provenance = None;
    for (workload, target) in &workloads {
        let required = RequiredSet::for_all_tensors(&target.manifest).unwrap();
        let switch = plan(&required, &residents, &consumer(), &clock());
        // The target's index is built at switch time: every source byte is hashed.
        let hashed_bytes: u64 = target.files.values().map(|bytes| bytes.len() as u64).sum();
        let decision = choose_loader(
            &switch,
            link,
            &IndexHashCost {
                index_seconds: 0.0,
                hashed_bytes,
                hash_bytes_per_second: 4.0e6,
            },
        )
        .unwrap();
        let (candidate_seconds, candidate_bytes) = match decision.choice {
            LoaderChoice::Differential => (
                decision.differential_seconds,
                switch.missing_stored_bytes().unwrap(),
            ),
            LoaderChoice::FullLoader => (
                decision.full_loader_seconds,
                switch.required_stored_bytes().unwrap(),
            ),
        };
        let full_bytes = switch.required_stored_bytes().unwrap();
        let expected = match *workload {
            "adapter-family" | "checkpoint-family" => LoaderChoice::Differential,
            _ => LoaderChoice::FullLoader,
        };
        assert_eq!(decision.choice, expected, "{workload}");
        let setup = experiment(
            &format!("gpu-4-2-{workload}"),
            StartTemperature::Warm,
            StateComparison::WarmLoad,
            EffectClass::CacheOrPredictor,
            "differential-materialization",
        );
        let report = fake_report(
            &setup,
            &arm("differential", 7, candidate_seconds, 0.0, candidate_bytes),
            &arm(
                "full-loader",
                7,
                decision.full_loader_seconds,
                0.0,
                full_bytes,
            ),
            &upstream(
                "deltazip-needs-a-cuda-gpu",
                BaselineUnavailable::NeedsUnauthorizedEnvironment,
            ),
        )
        .unwrap();
        assert_fake_only(&report);
        provenance = Some(report.candidate().provenance.clone());
        comparisons.push(WorkloadComparison::lower_is_better(
            *workload,
            "weight availability seconds",
            candidate_seconds,
            decision.full_loader_seconds,
            "full loader",
        ));
    }
    let record = ClaimRecord::decide(
        DIFFERENTIAL_CLAIM,
        comparisons,
        &provenance.unwrap(),
        interference_not_measured(),
    )
    .unwrap();
    let verdicts: Vec<Verdict> = record.comparisons.iter().map(|c| c.verdict).collect();
    assert_eq!(
        verdicts,
        vec![Verdict::Win, Verdict::Win, Verdict::Tie, Verdict::Tie]
    );
    assert_eq!(record.result, ClaimOutcome::Inconclusive);
}

/// §4.2 line 679: XOR deltas against independent compression.
#[test]
fn delta_chain_claim_is_rejected() {
    let base_bytes = bf16_weights(200, 65_536, 0.02);
    let tuned = fine_tune(&base_bytes, 201, 0.01);
    let unrelated = bf16_weights(202, 65_536, 0.02);
    let mut store = DeltaStore::new(DeltaLimits::new(2, DEFAULT_LEVEL).unwrap());
    let base = store.add_base(&base_bytes).unwrap();
    let tuned_key = store.add_version(Parent::Base(base), &tuned).unwrap();
    let unrelated_key = store.add_version(Parent::Base(base), &unrelated).unwrap();
    let local = ColdRecoveryCost {
        read_bytes_per_second: 3.0e9,
        decode_raw_bytes_per_second: 1.0e9,
        xor_bytes_per_second: 10.0e9,
    };
    let remote = ColdRecoveryCost {
        read_bytes_per_second: 50.0e6,
        ..local
    };
    let workloads = [
        ("fine-tune-local-nvme", tuned_key, local),
        ("fine-tune-remote-store", tuned_key, remote),
        ("unrelated-local-nvme", unrelated_key, local),
    ];
    let mut comparisons = Vec::new();
    let mut provenance = None;
    for (workload, version, cost) in workloads {
        let comparison = store.compare(&version, &cost).unwrap();
        let decision = store.decide(&version, &cost).unwrap();
        let verdict = match decision {
            DeltaDecision::Keep => Verdict::Win,
            DeltaDecision::Abandon(_) => Verdict::Loss,
        };
        let setup = experiment(
            &format!("gpu-4-2-delta-{workload}"),
            StartTemperature::Cold,
            StateComparison::ColdLoad,
            EffectClass::Other,
            "xor-delta-chain",
        );
        let report = fake_report(
            &setup,
            &arm(
                "delta-chain",
                9,
                comparison.delta_recovery_seconds,
                0.0,
                comparison.chain_read_bytes,
            ),
            &arm(
                "independent-zstd",
                9,
                comparison.independent_recovery_seconds,
                0.0,
                comparison.independent_stored_bytes,
            ),
            &upstream(
                "deltazip-needs-a-cuda-gpu",
                BaselineUnavailable::NeedsUnauthorizedEnvironment,
            ),
        )
        .unwrap();
        assert_fake_only(&report);
        provenance = Some(report.candidate().provenance.clone());
        comparisons.push(WorkloadComparison::decided(
            workload,
            "cold recovery seconds, with storage saving required",
            comparison.delta_recovery_seconds,
            comparison.independent_recovery_seconds,
            "independent zstd",
            verdict,
        ));
        if workload.starts_with("fine-tune") {
            assert!(comparison.delta_stored_bytes < comparison.independent_stored_bytes);
        }
    }
    let record = ClaimRecord::decide(
        DELTA_CLAIM,
        comparisons,
        &provenance.unwrap(),
        interference_not_measured(),
    )
    .unwrap();
    assert!(record
        .comparisons
        .iter()
        .all(|comparison| comparison.verdict == Verdict::Loss));
    assert_eq!(record.result, ClaimOutcome::Rejected);
}

fn selection_ranges() -> Vec<RangeCandidate> {
    const RANGE: usize = 64 * 1024;
    const METADATA: u64 = 112;
    let mut blocks: Vec<Vec<u8>> = (0..8)
        .map(|seed| bf16_weights(300 + seed, RANGE / 2, 0.02))
        .collect();
    blocks.extend((0..4).map(|seed| random_bytes(310 + seed, RANGE)));
    blocks.extend((0..2).map(|seed| {
        let mut sparse = vec![0u8; RANGE];
        for (index, byte) in random_bytes(320 + seed, RANGE / 64).into_iter().enumerate() {
            sparse[index * 64] = byte;
        }
        sparse
    }));
    blocks
        .iter()
        .map(|block| {
            let encoded = encode(block, DEFAULT_LEVEL, None).unwrap();
            let compressed =
                (encoded.len() as u64 + METADATA < block.len() as u64).then_some(CompressedForm {
                    stored_bytes: encoded.len() as u64,
                    metadata_bytes: METADATA,
                    scratch_bytes: encoded.len() as u64,
                });
            RangeCandidate {
                raw_bytes: block.len() as u64,
                raw_available: true,
                compressed,
            }
        })
        .collect()
}

/// §4.9: per-range selection against the better uniform choice.
#[test]
fn representation_selection_claim_is_inconclusive() {
    let ranges = selection_ranges();
    // Random blocks escape raw; weights and sparse blocks keep a compressed form.
    assert_eq!(
        ranges
            .iter()
            .filter(|range| range.compressed.is_none())
            .count(),
        4
    );
    let base = Conditions {
        link_bytes_per_second: 1.0e9,
        link_backlog_seconds: 0.0,
        decoder_raw_bytes_per_second: 1.0e9,
        decoder_backlog_seconds: 0.0,
        overhead_seconds_per_compressed_range: 2e-6,
        fill_drain_seconds: 40e-6,
        scratch_available_bytes: 1 << 20,
        interference_seconds_per_decoded_byte: 0.0,
        foreground_budget_seconds: 1.0,
        model: CostModel::Pipelined,
    };
    let workloads = [
        (
            "cold-remote",
            Conditions {
                link_bytes_per_second: 100.0e6,
                ..base
            },
        ),
        (
            "local-nvme-decoder-bound",
            Conditions {
                link_bytes_per_second: 1.0e9,
                decoder_raw_bytes_per_second: 0.5e9,
                ..base
            },
        ),
        (
            "gpu-peer",
            Conditions {
                link_bytes_per_second: 50.0e9,
                decoder_raw_bytes_per_second: 10.0e9,
                ..base
            },
        ),
        (
            "contended-link-with-interference",
            Conditions {
                link_bytes_per_second: 2.0e9,
                link_backlog_seconds: 0.002,
                decoder_raw_bytes_per_second: 2.0e9,
                interference_seconds_per_decoded_byte: 0.2e-9,
                foreground_budget_seconds: 0.0001,
                ..base
            },
        ),
    ];
    let mut comparisons = Vec::new();
    let mut provenance = None;
    for (workload, conditions) in workloads {
        let chosen = select(&ranges, &conditions).unwrap();
        let uniform = strongest_uniform(&ranges, &conditions).unwrap();
        assert!(chosen.objective_seconds <= uniform.objective_seconds);
        let bytes = |selection: &super::super::selection::Selection| -> u64 {
            ranges
                .iter()
                .zip(&selection.choices)
                .map(|(range, choice)| match (choice, range.compressed) {
                    (super::super::selection::Representation::Compressed, Some(form)) => {
                        form.stored_bytes + form.metadata_bytes
                    }
                    _ => range.raw_bytes,
                })
                .sum()
        };
        let setup = experiment(
            &format!("gpu-4-9-{workload}"),
            StartTemperature::Cold,
            StateComparison::ColdLoad,
            EffectClass::Other,
            "per-range-representation",
        );
        let report = fake_report(
            &setup,
            &arm(
                "per-range",
                11,
                chosen.completion_seconds,
                chosen.interference_seconds,
                bytes(&chosen),
            ),
            &arm(
                "best-uniform",
                11,
                uniform.completion_seconds,
                uniform.interference_seconds,
                bytes(&uniform),
            ),
            &upstream(
                "dfloat11-decoder-needs-a-cuda-gpu",
                BaselineUnavailable::NeedsUnauthorizedEnvironment,
            ),
        )
        .unwrap();
        assert_fake_only(&report);
        provenance = Some(report.candidate().provenance.clone());
        comparisons.push(WorkloadComparison::lower_is_better(
            workload,
            "completion plus interference seconds",
            chosen.objective_seconds,
            uniform.objective_seconds,
            "better uniform choice",
        ));
    }
    let record = ClaimRecord::decide(
        SELECTION_CLAIM,
        comparisons,
        &provenance.unwrap(),
        interference_not_measured(),
    )
    .unwrap();
    let verdicts: BTreeMap<&str, Verdict> = record
        .comparisons
        .iter()
        .map(|comparison| (comparison.workload.as_str(), comparison.verdict))
        .collect();
    assert_eq!(verdicts["gpu-peer"], Verdict::Tie);
    assert_eq!(verdicts["local-nvme-decoder-bound"], Verdict::Win);
    assert!(verdicts.values().all(|verdict| *verdict != Verdict::Loss));
    assert_eq!(record.result, ClaimOutcome::Inconclusive);
}

/// §4.12: the bandit against the strongest of the fixed and hand-coded policies.
#[test]
fn adaptive_policy_claim_is_narrowed() {
    const DECISIONS: usize = 200;
    let arms = batch_arms();
    let stationary = table(&[(0, [0.30, 0.20, 0.25])]);
    let mixed = table(&[(0, [0.30, 0.20, 0.10]), (1, [0.10, 0.20, 0.30])]);
    // A plausible hand-coded rule: batch 16 by default, batch 8 for context 1.
    let hand = [
        HandCodedPolicy::Fixed(0),
        HandCodedPolicy::ByContext {
            rule: BTreeMap::from([(1, 0)]),
            otherwise: 1,
        },
    ];
    let workloads = [
        ("stationary-one-context", stationary),
        ("mixed-contexts", mixed),
    ];
    let mut comparisons = Vec::new();
    let mut provenance = None;
    for (workload, outcomes) in workloads {
        let mut bandit_bursts = Vec::new();
        let mut baseline_bursts = Vec::new();
        let mut bandit_means = Vec::new();
        let mut baseline_means = Vec::new();
        for burst in 0..BURSTS as u64 {
            let mut rng = SeededRng::new(400 + burst);
            let contexts = if workload == "mixed-contexts" { 2 } else { 1 };
            let trace: Vec<_> = (0..DECISIONS)
                .map(|_| input(rng.below(contexts) as u32, 8 * GIB, true))
                .collect();
            let model = TableModel {
                table: outcomes.clone(),
                shift: None,
                seed: 500 + burst,
                spread: 0.02,
            };
            let report = shadow_evaluate(&arms, &hand, config(600 + burst), &trace, &mut || {
                Box::new(model.clone()) as Box<dyn OutcomeModel>
            })
            .unwrap();
            let strongest = report.strongest_baseline().unwrap();
            bandit_means.push(report.bandit().mean_seconds);
            baseline_means.push(strongest.mean_seconds);
            let to_trials = |realized: &[f64]| -> Vec<Trial> {
                realized
                    .iter()
                    .map(|seconds| Trial {
                        weights_usable_seconds: 0.0,
                        first_token_seconds: *seconds,
                        transferred_bytes: 0,
                        storage_read_bytes: 0,
                    })
                    .collect()
            };
            bandit_bursts.push(to_trials(&report.bandit().realized_seconds));
            baseline_bursts.push(to_trials(&strongest.realized_seconds));
        }
        let setup = FakeExperiment {
            bench: BenchId::Bench01,
            ..experiment(
                &format!("gpu-4-12-{workload}"),
                StartTemperature::Hot,
                StateComparison::HotDispatch,
                EffectClass::CacheOrPredictor,
                "constrained-contextual-bandit",
            )
        };
        let report = fake_report(
            &setup,
            &TrialArm {
                name: label("bandit"),
                bursts: bandit_bursts,
            },
            &TrialArm {
                name: label("strongest-fixed-or-hand-coded"),
                bursts: baseline_bursts,
            },
            &upstream(
                "no-upstream-adaptive-policy",
                BaselineUnavailable::UpstreamLacksRequiredCapability,
            ),
        )
        .unwrap();
        assert_fake_only(&report);
        provenance = Some(report.candidate().provenance.clone());
        let mean = |values: &[f64]| values.iter().sum::<f64>() / values.len() as f64;
        comparisons.push(WorkloadComparison::lower_is_better(
            workload,
            "mean seconds per request",
            mean(&bandit_means),
            mean(&baseline_means),
            "best fixed policy or hand-coded rule",
        ));
    }
    let record = ClaimRecord::decide(
        POLICY_CLAIM,
        comparisons,
        &provenance.unwrap(),
        interference_not_measured(),
    )
    .unwrap();
    let verdicts: Vec<Verdict> = record.comparisons.iter().map(|c| c.verdict).collect();
    assert_eq!(verdicts, vec![Verdict::Loss, Verdict::Win]);
    assert_eq!(record.kept_workloads(), vec!["mixed-contexts"]);
    assert_eq!(record.result, ClaimOutcome::Narrowed);
}
