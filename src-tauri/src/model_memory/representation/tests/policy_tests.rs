//! §4.12 adaptive policy: admitted arms, hard constraints, the guards, the decision log,
//! the shadow evaluator and the live gate.

use std::collections::{BTreeMap, BTreeSet};

use super::super::policy::*;
use crate::foundation::report::{
    Label, Provenance, ReportError, RunRecord, RunSubstrate, RUN_RECORD_SAMPLE_JSON,
};
use crate::model_memory::bench::rng::SeededRng;

pub(super) const GIB: u64 = 1 << 30;

pub(super) fn auth() -> AuthorizationName {
    AuthorizationName::new("large-batch").unwrap()
}

/// Batch size 8 (baseline, no extra memory), 16 (2 GiB) and 32 (4 GiB, needs a grant).
pub(super) fn batch_arms() -> ArmSet {
    let mut arms = ArmSet::new(Arm {
        value: KnobValue::BatchSize(8),
        memory_demand_bytes: 0,
        requires: None,
    });
    arms.admit(
        RequestedChange::SetKnob(KnobValue::BatchSize(16)),
        2 * GIB,
        None,
    )
    .unwrap();
    arms.admit(
        RequestedChange::SetKnob(KnobValue::BatchSize(32)),
        4 * GIB,
        Some(auth()),
    )
    .unwrap();
    arms
}

pub(super) fn config(seed: u64) -> BanditConfig {
    BanditConfig {
        exploration_probability: 0.1,
        min_samples: 5,
        p99_bound_seconds: 10.0,
        p99_window: 200,
        reserve_bound_bytes: 0,
        shift_window: 50,
        shift_relative_error: 0.5,
        seed,
    }
}

pub(super) fn input(context: u32, headroom: u64, granted: bool) -> DecisionInput {
    DecisionInput {
        context,
        granted_headroom_bytes: headroom,
        observed_reserve_bytes: 8 * GIB,
        authorizations: if granted {
            BTreeSet::from([auth()])
        } else {
            BTreeSet::new()
        },
    }
}

/// Seconds by context and arm.
pub(super) type OutcomeTable = BTreeMap<(u32, ArmIndex), f64>;

/// Outcomes from a table by context and arm, with seeded noise that depends only on the
/// step, so every policy sees the same noise for the same choice.
#[derive(Clone)]
pub(super) struct TableModel {
    pub table: OutcomeTable,
    /// From this step on, the second table applies.
    pub shift: Option<(u64, OutcomeTable)>,
    pub seed: u64,
    pub spread: f64,
}

impl OutcomeModel for TableModel {
    fn realize(&mut self, step: u64, context: u32, arm: ArmIndex) -> Result<f64, PolicyError> {
        let table = match &self.shift {
            Some((at, shifted)) if step >= *at => shifted,
            _ => &self.table,
        };
        let base = table
            .get(&(context, arm))
            .copied()
            .ok_or(PolicyError::UnknownArm { arm })?;
        let mut rng = SeededRng::new(self.seed ^ step.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let noise = 1.0 + self.spread * (rng.below(2001) as f64 / 1000.0 - 1.0);
        Ok(base * noise)
    }

    fn substrate(&self) -> RunSubstrate {
        RunSubstrate::FakeTimeControlled
    }
}

/// The table model replaying outcomes it declares to come from `substrate`.
struct Declared {
    inner: TableModel,
    substrate: RunSubstrate,
}

impl OutcomeModel for Declared {
    fn realize(&mut self, step: u64, context: u32, arm: ArmIndex) -> Result<f64, PolicyError> {
        self.inner.realize(step, context, arm)
    }

    fn substrate(&self) -> RunSubstrate {
        self.substrate.clone()
    }
}

pub(super) fn table(rows: &[(u32, [f64; 3])]) -> OutcomeTable {
    rows.iter()
        .flat_map(|(context, values)| {
            values
                .iter()
                .enumerate()
                .map(move |(arm, value)| ((*context, arm), *value))
        })
        .collect()
}

#[test]
fn only_values_of_the_tuned_knob_are_admitted() {
    let mut arms = batch_arms();
    for (change, expected) in [
        (
            RequestedChange::InstallKernel {
                kernel: "fused-decode-gemm".into(),
            },
            "install or invent a kernel",
        ),
        (
            RequestedChange::AlterModelSemantics {
                change: "quantize to int4".into(),
            },
            "alter model semantics",
        ),
        (
            RequestedChange::ChangeHostSecurity {
                setting: "disable seccomp".into(),
            },
            "change host security settings",
        ),
    ] {
        assert_eq!(
            arms.admit(change, 0, None),
            Err(PolicyError::ForbiddenChange { change: expected })
        );
    }
    assert_eq!(
        arms.admit(
            RequestedChange::SetKnob(KnobValue::PrefetchBudgetBytes(GIB)),
            0,
            None
        ),
        Err(PolicyError::KnobMismatch {
            expected: Knob::BatchSize,
            found: Knob::PrefetchBudget
        })
    );
    assert_eq!(
        arms.admit(RequestedChange::SetKnob(KnobValue::BatchSize(16)), 0, None),
        Err(PolicyError::DuplicateArm)
    );
    assert_eq!(arms.arms().len(), 3);
    // Retention-mode and prefetch-budget bandits are built the same way.
    let mut retention = ArmSet::new(Arm {
        value: KnobValue::Retention(RetentionMode::Lru),
        memory_demand_bytes: 0,
        requires: None,
    });
    assert!(retention
        .admit(
            RequestedChange::SetKnob(KnobValue::Retention(RetentionMode::GreedyDualSize)),
            0,
            None
        )
        .is_ok());
    assert_eq!(retention.knob(), Knob::RetentionMode);
    assert!(AuthorizationName::new("bad name").is_err());
}

#[test]
fn bandit_choices_never_leave_the_hard_constraints() {
    let arms = batch_arms();
    let mut bandit = ConstrainedBandit::new(
        arms.clone(),
        BanditConfig {
            exploration_probability: 0.5,
            ..config(3)
        },
    )
    .unwrap();
    let mut model = TableModel {
        table: table(&[(0, [0.3, 0.2, 0.1])]),
        shift: None,
        seed: 4,
        spread: 0.02,
    };
    let mut rng = SeededRng::new(5);
    let mut chosen = [0usize; 3];
    let mut trace = Vec::new();
    for step in 0..3000u64 {
        let headroom = [GIB, 3 * GIB, 8 * GIB][rng.below(3) as usize];
        let request = input(0, headroom, rng.below(2) == 0);
        let decision = bandit.choose(&request).unwrap();
        assert!(arms.feasible(decision.arm, &request), "step {step}");
        chosen[decision.arm] += 1;
        let outcome = model.realize(step, 0, decision.arm).unwrap();
        bandit.observe(decision.sequence, outcome).unwrap();
        trace.push(request);
    }
    for (decision, request) in bandit.log().iter().zip(&trace) {
        let arm = &arms.arms()[decision.arm];
        assert!(arm.memory_demand_bytes <= request.granted_headroom_bytes);
        if let Some(needed) = &arm.requires {
            assert!(request.authorizations.contains(needed));
        }
    }
    // The fastest arm is used when allowed, so the constraint is what limits it.
    assert!(chosen.iter().all(|count| *count > 0), "{chosen:?}");
}

#[test]
fn without_a_feasible_arm_nothing_acts() {
    let mut arms = ArmSet::new(Arm {
        value: KnobValue::PrefetchBudgetBytes(GIB),
        memory_demand_bytes: GIB,
        requires: None,
    });
    arms.admit(
        RequestedChange::SetKnob(KnobValue::PrefetchBudgetBytes(2 * GIB)),
        2 * GIB,
        None,
    )
    .unwrap();
    let mut bandit = ConstrainedBandit::new(arms.clone(), config(6)).unwrap();
    let starved = input(0, GIB / 2, false);
    assert_eq!(bandit.choose(&starved), Err(PolicyError::NoFeasibleArm));
    assert_eq!(
        HandCodedPolicy::Fixed(1).choose(&arms, &starved),
        Err(PolicyError::NoFeasibleArm)
    );
    assert_eq!(
        HandCodedPolicy::Fixed(7).choose(&arms, &starved),
        Err(PolicyError::UnknownArm { arm: 7 })
    );
}

#[test]
fn exploration_stops_when_the_p99_crosses_its_bound() {
    let mut bandit = ConstrainedBandit::new(
        batch_arms(),
        BanditConfig {
            exploration_probability: 0.3,
            p99_bound_seconds: 1.0,
            ..config(7)
        },
    )
    .unwrap();
    // Batch 32 is pathological: 5 s per request.
    let mut model = TableModel {
        table: table(&[(0, [0.1, 0.08, 5.0])]),
        shift: None,
        seed: 8,
        spread: 0.0,
    };
    let trace: Vec<DecisionInput> = (0..500).map(|_| input(0, 8 * GIB, true)).collect();
    run_bandit(&mut bandit, &trace, &mut model).unwrap();
    let BanditMode::ExplorationStopped(StopReason::P99AboveBound { p99_seconds }) = bandit.mode()
    else {
        panic!("exploration should have stopped: {:?}", bandit.mode());
    };
    assert!(p99_seconds > 1.0);
    let stopped_at = bandit
        .log()
        .iter()
        .position(|decision| decision.arm == 2)
        .unwrap();
    assert!(bandit.log()[stopped_at + 1..]
        .iter()
        .all(|decision| decision.kind != ChoiceKind::Explore));
    // The pathological arm is never chosen again.
    assert!(bandit.log()[stopped_at + 1..]
        .iter()
        .all(|decision| decision.arm != 2));
    bandit.reset();
    assert_eq!(bandit.mode(), BanditMode::Exploring);
}

#[test]
fn a_low_memory_reserve_stops_exploration_before_the_choice() {
    let mut bandit = ConstrainedBandit::new(
        batch_arms(),
        BanditConfig {
            exploration_probability: 1.0,
            reserve_bound_bytes: GIB,
            ..config(9)
        },
    )
    .unwrap();
    let low = DecisionInput {
        observed_reserve_bytes: GIB - 1,
        ..input(0, 8 * GIB, true)
    };
    let decision = bandit.choose(&low).unwrap();
    assert_eq!(
        bandit.mode(),
        BanditMode::ExplorationStopped(StopReason::ReserveBelowBound {
            reserve_bytes: GIB - 1
        })
    );
    assert_eq!(decision.kind, ChoiceKind::Baseline);
    assert_eq!(decision.arm, 0);
    // It stays stopped when the reserve recovers.
    let decision = bandit.choose(&input(0, 8 * GIB, true)).unwrap();
    assert_ne!(decision.kind, ChoiceKind::Explore);
}

#[test]
fn a_distribution_shift_reverts_to_the_baseline() {
    let mut bandit = ConstrainedBandit::new(batch_arms(), config(10)).unwrap();
    let before = table(&[(0, [0.3, 0.2, 0.1])]);
    let after = table(&[(0, [0.9, 0.6, 0.6])]);
    let mut model = TableModel {
        table: before,
        shift: Some((1000, after)),
        seed: 11,
        spread: 0.02,
    };
    let trace: Vec<DecisionInput> = (0..1500).map(|_| input(0, 8 * GIB, true)).collect();
    run_bandit(&mut bandit, &trace, &mut model).unwrap();
    let BanditMode::Reverted {
        mean_relative_error,
    } = bandit.mode()
    else {
        panic!("a shift should revert: {:?}", bandit.mode());
    };
    assert!(mean_relative_error > 0.5);
    let reverted_at = bandit
        .log()
        .iter()
        .position(|decision| matches!(decision.mode, BanditMode::Reverted { .. }))
        .unwrap();
    assert!(reverted_at > 1000);
    assert!(bandit.log()[reverted_at..]
        .iter()
        .all(|decision| decision.kind == ChoiceKind::Baseline && decision.arm == 0));
    // Before the shift the bandit had learned the fastest arm.
    assert!(bandit.log()[900..1000]
        .iter()
        .filter(|decision| decision.kind == ChoiceKind::Exploit)
        .all(|decision| decision.arm == 2));
}

#[test]
fn every_choice_is_logged_with_its_prediction_and_realized_outcome() {
    let mut bandit = ConstrainedBandit::new(batch_arms(), config(12)).unwrap();
    let mut model = TableModel {
        table: table(&[(0, [0.3, 0.2, 0.1]), (1, [0.1, 0.2, 0.3])]),
        shift: None,
        seed: 13,
        spread: 0.02,
    };
    let trace: Vec<DecisionInput> = (0..400)
        .map(|step| input(step % 2, 8 * GIB, true))
        .collect();
    run_bandit(&mut bandit, &trace, &mut model).unwrap();
    assert_eq!(bandit.log().len(), 400);
    assert!(bandit
        .log()
        .iter()
        .all(|decision| decision.realized_seconds.is_some()));
    let exploits: Vec<&Decision> = bandit
        .log()
        .iter()
        .filter(|decision| decision.kind == ChoiceKind::Exploit)
        .collect();
    assert!(!exploits.is_empty());
    assert!(exploits
        .iter()
        .all(|decision| decision.predicted_seconds.is_some()));
    // Per context: the fast arm differs, and the bandit learns both.
    let last_exploit = |context: u32| {
        exploits
            .iter()
            .rev()
            .find(|decision| decision.context == context)
            .map(|decision| decision.arm)
    };
    assert_eq!(last_exploit(0), Some(2));
    assert_eq!(last_exploit(1), Some(0));
    assert_eq!(
        bandit.observe(0, 0.1),
        Err(PolicyError::AlreadyObserved { sequence: 0 })
    );
    assert_eq!(
        bandit.observe(10_000, 0.1),
        Err(PolicyError::UnknownDecision { sequence: 10_000 })
    );
    assert!(bandit.observe(0, f64::NAN).is_err());
}

#[test]
fn the_shadow_evaluator_compares_with_the_best_fixed_policy_and_gates_live_use() {
    let arms = batch_arms();
    // The default (arm 0) is the worst; arm 1 is the best fixed policy.
    let model = TableModel {
        table: table(&[(0, [0.5, 0.2, 0.25])]),
        shift: None,
        seed: 14,
        spread: 0.02,
    };
    let trace: Vec<DecisionInput> = (0..2000).map(|_| input(0, 8 * GIB, true)).collect();
    let hand = [HandCodedPolicy::Fixed(0)];
    let report = shadow_evaluate(&arms, &hand, config(15), &trace, &mut || {
        Box::new(model.clone()) as Box<dyn OutcomeModel>
    })
    .unwrap();
    assert_eq!(report.fixed().len(), 3);
    assert_eq!(report.best_fixed().unwrap().policy, PolicyName::Fixed(1));
    let worst_default = &report.fixed()[0];
    // Beating the worst default is not the comparison; the best fixed policy is.
    assert!(report.bandit().mean_seconds < worst_default.mean_seconds);
    assert!(report.bandit().mean_seconds > report.best_fixed().unwrap().mean_seconds);
    // Live use needs measured evidence; a fake-substrate shadow run never qualifies.
    assert!(matches!(
        LiveApproval::from_shadow(&report),
        Err(PolicyError::Report(ReportError::FakeSubstrateIsNotEvidence))
    ));
    // A fixed arm that violates the constraints somewhere is not a compatible baseline.
    let constrained: Vec<DecisionInput> = (0..200)
        .map(|step| input(0, if step == 50 { GIB } else { 8 * GIB }, true))
        .collect();
    let report = shadow_evaluate(&arms, &hand, config(16), &constrained, &mut || {
        Box::new(model.clone()) as Box<dyn OutcomeModel>
    })
    .unwrap();
    assert_eq!(report.fixed().len(), 1);
    assert_eq!(
        shadow_evaluate(&arms, &[], config(16), &constrained, &mut || {
            Box::new(model.clone()) as Box<dyn OutcomeModel>
        }),
        Err(PolicyError::NoHandCodedPolicies)
    );
}

#[test]
fn invalid_bandit_configurations_are_refused() {
    for bad in [
        BanditConfig {
            exploration_probability: 1.5,
            ..config(1)
        },
        BanditConfig {
            p99_bound_seconds: 0.0,
            ..config(1)
        },
        BanditConfig {
            p99_window: 0,
            ..config(1)
        },
        BanditConfig {
            shift_window: 0,
            ..config(1)
        },
        BanditConfig {
            min_samples: 0,
            ..config(1)
        },
    ] {
        assert!(ConstrainedBandit::new(batch_arms(), bad).is_err());
    }
}

#[test]
fn live_approval_rests_only_on_the_shadow_reports_own_records() {
    let arms = batch_arms();
    let hand = [HandCodedPolicy::Fixed(0)];
    let mut rng = SeededRng::new(17);
    let trace: Vec<DecisionInput> = (0..400)
        .map(|_| input(rng.below(2) as u32, 8 * GIB, true))
        .collect();
    let model = TableModel {
        table: table(&[(0, [0.30, 0.20, 0.10]), (1, [0.10, 0.20, 0.30])]),
        shift: None,
        seed: 18,
        spread: 0.02,
    };
    // A fake shadow run in which the bandit wins: only its provenance blocks approval.
    let fake = shadow_evaluate(&arms, &hand, config(19), &trace, &mut || {
        Box::new(model.clone()) as Box<dyn OutcomeModel>
    })
    .unwrap();
    assert!(fake.provenance().is_fake_substrate());
    assert!(fake.bandit().mean_seconds < fake.strongest_baseline().unwrap().mean_seconds);
    assert_eq!(
        LiveApproval::from_shadow(&fake),
        Err(PolicyError::Report(ReportError::FakeSubstrateIsNotEvidence))
    );
    // Measured provenance from another run exists, but the approval takes no provenance
    // argument and the report's own cannot be replaced.
    let mut record: RunRecord = serde_json::from_str(RUN_RECORD_SAMPLE_JSON).unwrap();
    record.substrate = RunSubstrate::AuthorizedDisposable {
        authorization: Label::new("another-run").unwrap(),
    };
    let measured_elsewhere = Provenance::of_records(&[record]).unwrap();
    assert!(measured_elsewhere.yougori_evidence().is_ok());
    assert_ne!(fake.provenance(), &measured_elsewhere);
    // The same outcomes replayed from an authorized run: the report's records carry that
    // substrate, so its own provenance is measured and approval follows from it.
    let authorized = RunSubstrate::AuthorizedDisposable {
        authorization: Label::new("shadow-replay-1").unwrap(),
    };
    let replayed = shadow_evaluate(&arms, &hand, config(19), &trace, &mut || {
        Box::new(Declared {
            inner: model.clone(),
            substrate: authorized.clone(),
        }) as Box<dyn OutcomeModel>
    })
    .unwrap();
    let approval = LiveApproval::from_shadow(&replayed).unwrap();
    assert_eq!(
        Ok(approval.evidence()),
        replayed.provenance().yougori_evidence()
    );
    assert_ne!(
        Ok(approval.evidence()),
        measured_elsewhere.yougori_evidence()
    );
    // One fake outcome source among authorized ones makes the whole report fake.
    let mut calls = 0;
    let mixed_sources = shadow_evaluate(&arms, &hand, config(19), &trace, &mut || {
        calls += 1;
        if calls == 2 {
            Box::new(model.clone()) as Box<dyn OutcomeModel>
        } else {
            Box::new(Declared {
                inner: model.clone(),
                substrate: authorized.clone(),
            }) as Box<dyn OutcomeModel>
        }
    })
    .unwrap();
    assert!(mixed_sources.provenance().is_fake_substrate());
    assert!(LiveApproval::from_shadow(&mixed_sources).is_err());
}
