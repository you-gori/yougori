use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::foundation::evidence::{Backend, BackendModeRules, BackendRelease};
use crate::model_memory::backends::PinnedFeature;
use crate::model_memory::readiness::claim::{ClaimOutcome, EvidenceClass, InconclusiveReason};
use crate::model_memory::readiness::test_support::{
    factory, label, profile, runtime, verified, vllm_recorded, vllm_with_sleep, weights, GB, MILLIS,
};
use crate::model_memory::residency::eviction::CopyTier;

const MB: u64 = 1_000_000;

fn cost(gpu_bytes: u64, host_bytes: u64, recreate_seconds: f64) -> ComponentCost {
    ComponentCost {
        gpu_bytes,
        host_bytes,
        recreate_seconds,
        recreate_with_artifact_seconds: None,
        restore_from_host_seconds: None,
    }
}

/// Model-a's components, consistent with the fake profile: startup 2 s split into
/// tokenizer 0.1, process 0.4 and context 1.5; weights reload 0.4 s from the verified host
/// copy or restore in 0.35 s from pinned memory; graph capture 0.3 s, 0.1 s with a
/// compile artifact.
fn table() -> ComponentTable {
    ComponentTable::new(BTreeMap::from([
        (Component::TokenizerConfig, cost(0, 50 * MB, 0.1)),
        (Component::CpuProcess, cost(0, 2 * GB, 0.4)),
        (Component::GpuContext, cost(GB / 2, 0, 1.5)),
        (
            Component::ProcessedWeights,
            ComponentCost {
                restore_from_host_seconds: Some(0.35),
                ..cost(8 * GB, 0, 0.4)
            },
        ),
        (
            Component::Graphs,
            ComponentCost {
                recreate_with_artifact_seconds: Some(0.1),
                ..cost(200 * MB, 0, 0.3)
            },
        ),
        (Component::KvCache, cost(GB, 0, 0.01)),
        (Component::Communicators, cost(50 * MB, 0, 0.05)),
    ]))
    .unwrap()
}

fn supported() -> SupportedLevels {
    let vllm = vllm_with_sleep();
    SupportedLevels::from_runtime(
        &vllm.runtime,
        &[],
        &vllm.registry,
        weights("model-a"),
        Some(verified(CopyTier::LocalStorage, weights("model-a"))),
    )
}

fn governor() -> RetentionGovernor {
    RetentionGovernor::new(table(), supported(), BTreeSet::new()).unwrap()
}

fn close(left: f64, right: f64) -> bool {
    (left - right).abs() < 1e-9
}

fn point(level: &str, retained_bytes: u64, resume_seconds: f64) -> FrontierPoint {
    FrontierPoint {
        level: level.to_string(),
        retained_bytes,
        resume_seconds,
    }
}

#[test]
fn the_pareto_frontier_keeps_only_undominated_levels() {
    let points = vec![
        point("hot", 11_800, 0.0),
        point("restart", 0, 2.76),
        point("dominated", 10_900, 0.9),
        point("sleep-2", 2_550, 0.76),
        point("sleep-2-again", 2_550, 0.76),
        point("sleep-1", 10_550, 0.71),
        point("slower-and-bigger", 3_000, 2.0),
    ];
    let frontier = pareto_frontier(&points);
    assert_eq!(
        frontier
            .iter()
            .map(|point| point.level.as_str())
            .collect::<Vec<_>>(),
        vec!["restart", "sleep-2", "sleep-1", "hot"]
    );
    assert!(pareto_frontier(&[]).is_empty());
}

#[test]
fn levels_retain_and_resume_by_their_components() {
    let governor = governor();
    let names: Vec<&str> = governor
        .evaluations()
        .iter()
        .map(|evaluation| evaluation.level.name())
        .collect();
    assert_eq!(
        names,
        vec![
            "retained-process",
            "sleep-level-1",
            "sleep-level-2",
            "full-restart"
        ]
    );
    let find = |name: &str| {
        governor
            .evaluations()
            .iter()
            .find(|evaluation| evaluation.level.name() == name)
            .unwrap()
    };
    let hot = find("retained-process");
    assert_eq!(
        hot.retained,
        RetainedBytes {
            gpu_bytes: GB / 2 + 8 * GB + 200 * MB + GB + 50 * MB,
            pinned_host_bytes: 0,
            pageable_host_bytes: 2 * GB + 50 * MB,
        }
    );
    assert!(close(hot.resume_seconds, 0.0));
    // Level 1 offloads the weights to pinned memory and recreates graphs, KV and
    // communicators: 0.35 + 0.3 + 0.01 + 0.05.
    let sleep_1 = find("sleep-level-1");
    assert_eq!(sleep_1.retained.gpu_bytes, GB / 2);
    assert_eq!(sleep_1.retained.pinned_host_bytes, 8 * GB);
    assert!(close(sleep_1.resume_seconds, 0.71));
    // Level 2 drops the weights and reloads them: 0.4 + 0.3 + 0.01 + 0.05.
    let sleep_2 = find("sleep-level-2");
    assert_eq!(sleep_2.retained.pinned_host_bytes, 0);
    assert!(close(sleep_2.resume_seconds, 0.76));
    // Restart recreates everything: 0.1 + 0.4 + 1.5 + 0.4 + 0.3 + 0.01 + 0.05.
    let restart = find("full-restart");
    assert_eq!(restart.retained, RetainedBytes::default());
    assert!(close(restart.resume_seconds, 2.76));
    assert_eq!(
        governor
            .frontier()
            .iter()
            .map(|point| point.level.as_str())
            .collect::<Vec<_>>(),
        vec![
            "full-restart",
            "sleep-level-2",
            "sleep-level-1",
            "retained-process"
        ]
    );
    // A compile artifact under the exact ABI key shortens graph recreation by 0.2 s.
    let with_artifact =
        RetentionGovernor::new(table(), supported(), BTreeSet::from([Component::Graphs])).unwrap();
    assert!(close(with_artifact.evaluations()[1].resume_seconds, 0.51));
    assert_eq!(runner_mode(&hot.level), Some(RunnerMode::RetainedProcess));
    assert_eq!(
        runner_mode(&sleep_1.level),
        Some(RunnerMode::VersionSupportedSleep)
    );
    assert_eq!(
        runner_mode(&sleep_2.level),
        Some(RunnerMode::VerifiedReload)
    );
    assert_eq!(
        runner_mode(&restart.level),
        Some(RunnerMode::FullProcessRestart)
    );
}

#[test]
fn the_governor_chooses_the_fastest_supported_level_that_fits() {
    let governor = governor();
    let choose = |gpu_bytes, pinned_host_bytes| {
        governor
            .choose(&RetentionBudget {
                gpu_bytes,
                pinned_host_bytes,
            })
            .unwrap()
            .level
            .name()
            .to_string()
    };
    assert_eq!(choose(12 * GB, 32 * GB), "retained-process");
    assert_eq!(choose(2 * GB, 32 * GB), "sleep-level-1");
    assert_eq!(choose(2 * GB, GB), "sleep-level-2");
    assert_eq!(choose(0, 0), "full-restart");
}

#[test]
fn the_governor_never_uses_a_level_the_backend_did_not_supply() {
    let governor = governor();
    for level in governor.supported().levels() {
        assert_eq!(governor.check(level), Ok(()));
    }
    // A valid state no backend level provides: keep everything but the KV cache.
    let mut states: BTreeMap<Component, ComponentState> = Component::ALL
        .into_iter()
        .map(|component| (component, ComponentState::Kept))
        .collect();
    states.insert(Component::KvCache, ComponentState::Dropped);
    let proposed = RetentionLevel::proposed("all-but-kv", states.clone());
    assert_eq!(proposed.validate(), Ok(()));
    assert_eq!(
        governor.check(&proposed),
        Err(RetentionRefusal::NotBackendSupported {
            level: "all-but-kv".to_string()
        })
    );
    assert!(governor.resume_seconds(&proposed).is_err());
    // Artificial states are refused before anything else.
    states.insert(Component::ProcessedWeights, ComponentState::Dropped);
    assert_eq!(
        RetentionLevel::proposed("graphs-without-weights", states.clone()).validate(),
        Err(RetentionRefusal::ArtificialState {
            component: Component::Graphs,
            missing: Component::ProcessedWeights
        })
    );
    let kv_without_context = RetentionLevel::proposed(
        "kv-only",
        BTreeMap::from([(Component::KvCache, ComponentState::Kept)]),
    );
    assert_eq!(
        governor.check(&kv_without_context),
        Err(RetentionRefusal::ArtificialState {
            component: Component::KvCache,
            missing: Component::GpuContext
        })
    );
    let offloaded_graphs = RetentionLevel::proposed(
        "offloaded-graphs",
        BTreeMap::from([
            (Component::CpuProcess, ComponentState::Kept),
            (Component::Graphs, ComponentState::OffloadedToHost),
        ]),
    );
    assert_eq!(
        offloaded_graphs.validate(),
        Err(RetentionRefusal::CannotOffload {
            component: Component::Graphs
        })
    );
    let weights_without_process = RetentionLevel::proposed(
        "orphaned-host-copy",
        BTreeMap::from([(Component::ProcessedWeights, ComponentState::OffloadedToHost)]),
    );
    assert_eq!(
        weights_without_process.validate(),
        Err(RetentionRefusal::ArtificialState {
            component: Component::ProcessedWeights,
            missing: Component::CpuProcess
        })
    );
    // A level another runtime supplied is not this backend's.
    let no_sleep = runtime(
        BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
        BackendModeRules::recorded(),
        &[],
        BTreeMap::new(),
        &[],
    );
    let narrow = RetentionGovernor::new(
        table(),
        SupportedLevels::from_runtime(
            &no_sleep.runtime,
            &[],
            &no_sleep.registry,
            weights("model-a"),
            None,
        ),
        BTreeSet::new(),
    )
    .unwrap();
    let foreign = &governor.supported().levels()[1];
    assert_eq!(foreign.name(), "sleep-level-1");
    assert_eq!(
        narrow.check(foreign),
        Err(RetentionRefusal::NotBackendSupported {
            level: "sleep-level-1".to_string()
        })
    );
    assert_eq!(
        narrow
            .choose(&RetentionBudget {
                gpu_bytes: 2 * GB,
                pinned_host_bytes: 32 * GB
            })
            .unwrap()
            .level
            .name(),
        "full-restart"
    );
}

#[test]
fn supported_levels_come_from_backend_capabilities_only() {
    let vllm = vllm_with_sleep();
    // Without a reconstructible copy the weight-discarding level is refused.
    let no_copy =
        SupportedLevels::from_runtime(&vllm.runtime, &[], &vllm.registry, weights("model-a"), None);
    assert!(no_copy
        .levels()
        .iter()
        .all(|level| level.name() != "sleep-level-2"));
    assert!(no_copy
        .refused()
        .iter()
        .any(|(name, refusal)| name == "sleep-level-2"
            && matches!(
                refusal,
                LevelRefusal::Sleep {
                    refusal: SleepRefusal::NoReconstructibleCopy { .. }
                }
            )));
    // Without CORE-01 evidence for sleep weight discard, which no recorded release has,
    // the weight-discarding level is refused even with a reconstructible copy.
    let recorded = vllm_recorded();
    let gated = SupportedLevels::from_runtime(
        &recorded.runtime,
        &[],
        &recorded.registry,
        weights("model-a"),
        Some(verified(CopyTier::LocalStorage, weights("model-a"))),
    );
    assert!(gated
        .levels()
        .iter()
        .any(|level| level.name() == "sleep-level-1"));
    assert!(gated
        .refused()
        .iter()
        .any(|(name, refusal)| name == "sleep-level-2"
            && matches!(refusal, LevelRefusal::Evidence { .. })));
    // llama.cpp keeps a process only where the pinned build reports one.
    let release = BackendRelease::new(Backend::LlamaCpp, "b11425").unwrap();
    let without = runtime(
        release.clone(),
        BackendModeRules::recorded(),
        &[],
        BTreeMap::new(),
        &[],
    );
    let levels = SupportedLevels::from_runtime(
        &without.runtime,
        &[],
        &without.registry,
        weights("model-a"),
        None,
    );
    assert_eq!(
        levels
            .levels()
            .iter()
            .map(RetentionLevel::name)
            .collect::<Vec<_>>(),
        vec!["full-restart"]
    );
    assert_eq!(levels.refused().len(), 2);
    let with = runtime(
        release,
        BackendModeRules::recorded(),
        &[],
        BTreeMap::new(),
        &[PinnedFeature::PersistentProcess],
    );
    let levels =
        SupportedLevels::from_runtime(&with.runtime, &[], &with.registry, weights("model-a"), None);
    assert!(matches!(
        levels.levels()[0].origin(),
        LevelOrigin::RetainedProcess {
            technique: Technique::PersistentProcess
        }
    ));
    // An admitted technique that keeps no process is not a retained-process level.
    let sleep_wake = vllm
        .runtime
        .admit_with_evidence(Technique::VersionSupportedSleepWake, &[], &vllm.registry)
        .unwrap();
    assert_eq!(
        RetentionLevel::retained_process(&sleep_wake),
        Err(RetentionRefusal::NotARetainedProcess {
            technique: Technique::VersionSupportedSleepWake
        })
    );
    // Graphs and communicators, which the semantics do not state, are recreated.
    let supported = supported();
    let level_1 = &supported.levels()[1];
    assert_eq!(level_1.state(Component::CpuProcess), ComponentState::Kept);
    assert_eq!(level_1.state(Component::GpuContext), ComponentState::Kept);
    assert_eq!(
        level_1.state(Component::ProcessedWeights),
        ComponentState::OffloadedToHost
    );
    assert_eq!(level_1.state(Component::KvCache), ComponentState::Dropped);
    assert_eq!(level_1.state(Component::Graphs), ComponentState::Dropped);
    assert_eq!(
        level_1.state(Component::Communicators),
        ComponentState::Dropped
    );
}

#[test]
fn component_tables_are_complete_and_checked() {
    let mut costs = BTreeMap::new();
    assert_eq!(
        ComponentTable::new(costs.clone()),
        Err(RetentionRefusal::MissingComponent {
            component: Component::TokenizerConfig
        })
    );
    for component in Component::ALL {
        costs.insert(component, cost(0, 0, 0.1));
    }
    assert!(ComponentTable::new(costs.clone()).is_ok());
    costs.insert(Component::Graphs, cost(0, 0, -1.0));
    assert_eq!(
        ComponentTable::new(costs.clone()),
        Err(RetentionRefusal::InvalidCost {
            component: Component::Graphs,
            field: "recreate_seconds"
        })
    );
    costs.insert(
        Component::Graphs,
        ComponentCost {
            restore_from_host_seconds: Some(0.1),
            ..cost(0, 0, 0.1)
        },
    );
    assert_eq!(
        ComponentTable::new(costs.clone()),
        Err(RetentionRefusal::CannotOffload {
            component: Component::Graphs
        })
    );
    costs.insert(Component::Graphs, cost(0, 0, 0.1));
    // An offloaded component needs a restore cost.
    let table = ComponentTable::new(costs).unwrap();
    let level = RetentionLevel::proposed(
        "offloaded-weights",
        BTreeMap::from([
            (Component::CpuProcess, ComponentState::Kept),
            (Component::ProcessedWeights, ComponentState::OffloadedToHost),
        ]),
    );
    assert_eq!(
        level.resume_seconds(&table, &BTreeSet::new()),
        Err(RetentionRefusal::NoRestoreCost {
            component: Component::ProcessedWeights
        })
    );
}

fn retention_spec() -> RetentionSpec {
    let budget = |gpu_bytes, pinned_host_bytes| RetentionBudget {
        gpu_bytes,
        pinned_host_bytes,
    };
    RetentionSpec {
        models: [label("model-a"), label("model-b")],
        budgets: vec![
            ("large".to_string(), budget(12 * GB, 32 * GB)),
            ("medium".to_string(), budget(2 * GB, 32 * GB)),
            ("small".to_string(), budget(2 * GB, GB)),
        ],
        workloads: vec![
            (
                "burst".to_string(),
                Workload::Burst {
                    requests_per_model: 4,
                },
            ),
            (
                "gap".to_string(),
                Workload::Gap {
                    gap_nanos: 30_000 * MILLIS,
                },
            ),
        ],
        cycles: 2,
        trials: 5,
        ordinary_sleep: SleepLevel::new(1),
        active_headroom_bytes: GB,
        max_output_tokens: 8,
        tie_tolerance: 0.02,
        latency_objective: LatencyObjective {
            quantile: Quantile::P99,
            max_time_to_first_token_nanos: 10_000 * MILLIS,
        },
    }
}

#[test]
fn selective_retention_is_compared_over_three_budgets_and_two_workloads() {
    let base = factory(profile(RunnerMode::FullProcessRestart), 11);
    let experiment = run_retention(&base, &governor(), &retention_spec()).unwrap();
    assert_eq!(experiment.cells.len(), 3 * 2 * 4);
    let run =
        |budget, workload, strategy| &experiment.cell(budget, workload, strategy).unwrap().run;
    for workload in ["burst", "gap"] {
        // Large: always-hot fits, and selective retention chooses it.
        assert!(run("large", workload, Strategy::AlwaysHot).compatible());
        assert_eq!(
            experiment
                .cell("large", workload, Strategy::Selective)
                .unwrap()
                .level
                .as_deref(),
            Some("retained-process")
        );
        // Medium: two resident models exceed the GPU, so always-hot fails requests;
        // ordinary sleep fits, and selective retention chooses it.
        let hot = run("medium", workload, Strategy::AlwaysHot);
        assert!(matches!(hot, CellRun::Measured { measurement, .. }
            if measurement.success_rate() < 1.0));
        assert!(run("medium", workload, Strategy::OrdinarySleep).compatible());
        assert_eq!(
            experiment
                .cell("medium", workload, Strategy::Selective)
                .unwrap()
                .level
                .as_deref(),
            Some("sleep-level-1")
        );
        // Small: the pinned copy exceeds the host budget, so only restart and the
        // weight-discarding level remain; selective retention chooses the latter.
        assert!(matches!(
            run("small", workload, Strategy::OrdinarySleep),
            CellRun::Measured {
                over_budget: true,
                ..
            }
        ));
        assert!(run("small", workload, Strategy::FullRestart).compatible());
        let selective = experiment
            .cell("small", workload, Strategy::Selective)
            .unwrap();
        assert_eq!(selective.level.as_deref(), Some("sleep-level-2"));
        assert!(matches!(
            &selective.run,
            CellRun::Measured {
                mode: RunnerMode::VerifiedReload,
                ..
            }
        ));
    }
    for cell in &experiment.cells {
        if let CellRun::Measured { measurement, .. } = &cell.run {
            assert!(measurement.provenance.is_fake_substrate());
        }
    }
    assert_eq!(experiment.frontier.len(), 4);
    let claim = experiment.claim();
    assert_eq!(claim.evidence(), EvidenceClass::FakeSubstrate);
    assert_eq!(
        claim
            .cells()
            .iter()
            .map(|cell| (cell.label.as_str(), cell.verdict))
            .collect::<Vec<_>>(),
        vec![
            ("large/burst", CellVerdict::Tie),
            ("large/gap", CellVerdict::Tie),
            ("medium/burst", CellVerdict::Tie),
            ("medium/gap", CellVerdict::Tie),
            ("small/burst", CellVerdict::Better),
            ("small/gap", CellVerdict::Better),
        ]
    );
    assert_eq!(
        claim.outcome(),
        &ClaimOutcome::Inconclusive {
            reason: InconclusiveReason::FakeSubstrateOnly
        }
    );
}

#[test]
fn a_selective_choice_that_fails_its_cell_loses_it() {
    let failed = CellRun::NotRun {
        reason: "no mode".to_string(),
    };
    let restart = CellRun::NotRun {
        reason: "no mode".to_string(),
    };
    assert_eq!(verdict(&failed, &[&restart], 0.02), CellVerdict::Worse);
    let zero = RetentionSpec {
        trials: 0,
        ..retention_spec()
    };
    let base = factory(profile(RunnerMode::FullProcessRestart), 11);
    assert!(run_retention(&base, &governor(), &zero).is_err());
}
