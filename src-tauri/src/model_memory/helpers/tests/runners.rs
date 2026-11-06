//! G08 item 4: a running runner keeps the exact helper version it started with; an
//! upgrade or a rollback applies only to new runners.

use super::*;

fn instance(name: &str) -> RunnerInstance {
    RunnerInstance::new(name).unwrap()
}

/// Selects the gpu-optimizer for a new vLLM 0.29.0 runner and records its start.
fn start(rollouts: &HelperRollouts, pins: &mut RunnerPins, name: &str, opted_in: bool) {
    let selected = rollouts
        .select(&helper_id(), &vllm(), opted_in, &FakePins::default())
        .unwrap();
    pins.start(instance(name), vllm(), vec![selected]).unwrap();
}

fn serves(pins: &RunnerPins, name: &str) -> ServingHelper {
    pins.serving(&instance(name), &helper_id()).unwrap().clone()
}

fn bundle(pin: &HelperPin) -> ServingHelper {
    ServingHelper::Bundle { pin: pin.clone() }
}

#[test]
fn a_running_runner_keeps_the_versions_it_started_with() {
    let fakes = FakePins::default();
    let mut rollouts = HelperRollouts::new();
    let mut pins = RunnerPins::new();
    let v1 = fake_pin_at(1, 0, 0);
    let v2 = fake_pin_at(1, 1, 0);

    start(&rollouts, &mut pins, "env-legacy", false);
    make_default(&mut rollouts, &v1, &fakes);
    start(&rollouts, &mut pins, "env-a", false);
    assert_eq!(serves(&pins, "env-legacy"), ServingHelper::SourceInjection);
    assert_eq!(serves(&pins, "env-a"), bundle(&v1));

    // An upgrade reaches new runners only.
    make_default(&mut rollouts, &v2, &fakes);
    start(&rollouts, &mut pins, "env-b", false);
    assert_eq!(serves(&pins, "env-a"), bundle(&v1));
    assert_eq!(serves(&pins, "env-b"), bundle(&v2));
    assert_eq!(serves(&pins, "env-legacy"), ServingHelper::SourceInjection);

    // So does a rollback; the host learns which runners still run the failed version.
    rollouts
        .record(fail(&v2, RolloutStage::BackendDefault), &fakes)
        .unwrap();
    start(&rollouts, &mut pins, "env-c", false);
    assert_eq!(serves(&pins, "env-b"), bundle(&v2));
    assert_eq!(serves(&pins, "env-c"), bundle(&v1));
    assert_eq!(pins.running_on(v2.id()), vec![instance("env-b")]);
    assert_eq!(
        pins.running_on(v1.id()),
        vec![instance("env-a"), instance("env-c")]
    );
    assert_eq!(
        pins.running_on_object(v1.object),
        vec![instance("env-a"), instance("env-c")]
    );

    // A running runner cannot be given other versions; it stops and starts again.
    let selected = rollouts
        .select(&helper_id(), &vllm(), false, &fakes)
        .unwrap();
    assert_eq!(
        pins.start(instance("env-b"), vllm(), vec![selected.clone()]),
        Err(PinningRefusal::AlreadyRunning {
            runner: instance("env-b")
        })
    );
    assert_eq!(serves(&pins, "env-b"), bundle(&v2));
    let stopped = pins.stop(&instance("env-b")).unwrap();
    assert_eq!(stopped.release, vllm());
    assert!(pins.get(&instance("env-b")).is_none());
    pins.start(instance("env-b"), vllm(), vec![selected])
        .unwrap();
    assert_eq!(serves(&pins, "env-b"), bundle(&v1));
    assert!(pins.running_on(v2.id()).is_empty());
}

#[test]
fn shadow_versions_are_pinned_beside_what_serves() {
    let fakes = FakePins::default();
    let mut rollouts = HelperRollouts::new();
    let mut pins = RunnerPins::new();
    let v1 = fake_pin_at(1, 0, 0);
    let v2 = fake_pin_at(1, 1, 0);
    make_default(&mut rollouts, &v1, &fakes);
    rollouts.propose(v2.clone(), Backend::Vllm, &fakes).unwrap();
    start(&rollouts, &mut pins, "env-a", true);
    let started = pins.get(&instance("env-a")).unwrap();
    let helpers = &started.helpers[&helper_id()];
    assert_eq!(helpers.serve, bundle(&v1));
    assert_eq!(helpers.shadow, Some(v2.clone()));
    assert_eq!(pins.running_on(v2.id()), vec![instance("env-a")]);
    // The shadow version failing changes nothing a running runner serves.
    rollouts
        .record(fail(&v2, RolloutStage::Shadow), &fakes)
        .unwrap();
    assert_eq!(serves(&pins, "env-a"), bundle(&v1));
}

#[test]
fn a_start_records_one_selection_per_helper_for_its_own_runner() {
    let rollouts = HelperRollouts::new();
    let mut pins = RunnerPins::new();
    let for_vllm = rollouts
        .select(&helper_id(), &vllm(), false, &FakePins::default())
        .unwrap();
    let for_llama = rollouts
        .select(&helper_id(), &llama(), false, &FakePins::default())
        .unwrap();
    assert_eq!(
        pins.start(instance("env-a"), vllm(), vec![for_llama]),
        Err(PinningRefusal::WrongRunner {
            helper: helper_id(),
            expected: vllm(),
            found: llama()
        })
    );
    assert_eq!(
        pins.start(
            instance("env-a"),
            vllm(),
            vec![for_vllm.clone(), for_vllm.clone()]
        ),
        Err(PinningRefusal::DuplicateHelper {
            helper: helper_id()
        })
    );
    assert!(pins.get(&instance("env-a")).is_none());
    let publisher = HelperId::new("publisher-routes").unwrap();
    let other = rollouts
        .select(&publisher, &vllm(), false, &FakePins::default())
        .unwrap();
    let started = pins
        .start(instance("env-a"), vllm(), vec![for_vllm, other])
        .unwrap();
    assert_eq!(started.helpers.len(), 2);
    assert_eq!(
        pins.serving(&instance("env-a"), &publisher),
        Some(&ServingHelper::SourceInjection)
    );
    assert!(RunnerInstance::new("env a").is_err());
}
