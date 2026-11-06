//! G08 item 3: shadow, opt-in and backend-default stages per backend; promotion only on
//! recorded measured passes; automatic rollback to the last good pinned version on
//! failure evidence; source injection kept as the fallback until a recorded decision
//! removes it after its replacement passed.

use super::*;

const VLLM: Backend = Backend::Vllm;

fn select(rollouts: &HelperRollouts, runner: &BackendRelease, opted_in: bool) -> RunnerHelpers {
    rollouts
        .select(&helper_id(), runner, opted_in, &FakePins::default())
        .unwrap()
}

fn serving(rollouts: &HelperRollouts, runner: &BackendRelease, opted_in: bool) -> ServingHelper {
    select(rollouts, runner, opted_in).serve
}

fn bundle(pin: &HelperPin) -> ServingHelper {
    ServingHelper::Bundle { pin: pin.clone() }
}

fn track(rollouts: &HelperRollouts) -> TrackView {
    rollouts.track(&helper_id(), VLLM).unwrap()
}

fn removal() -> SourceInjectionRemoval {
    SourceInjectionRemoval {
        decided_by: label("release-owner"),
        reason: label("bundle-proven"),
    }
}

#[test]
fn without_a_rollout_every_runner_keeps_source_injection() {
    let rollouts = HelperRollouts::new();
    let selected = select(&rollouts, &vllm(), true);
    assert_eq!(selected.serve, ServingHelper::SourceInjection);
    assert_eq!(selected.shadow, None);
    assert_eq!(selected.fallback, None);
    assert_eq!(rollouts.track(&helper_id(), VLLM), None);
    assert!(rollouts.records().is_empty());
}

#[test]
fn a_proposed_version_runs_in_shadow_and_never_serves() {
    let fakes = FakePins::default();
    let mut rollouts = HelperRollouts::new();
    let v1 = fake_pin_at(1, 0, 0);
    rollouts.propose(v1.clone(), VLLM, &fakes).unwrap();
    assert_eq!(
        track(&rollouts).candidate,
        Some((v1.clone(), RolloutStage::Shadow))
    );
    for opted_in in [false, true] {
        let selected = select(&rollouts, &vllm(), opted_in);
        assert_eq!(selected.serve, ServingHelper::SourceInjection);
        assert_eq!(selected.shadow, Some(v1.clone()));
    }
    // Shadow is per backend and per exact runner version.
    assert_eq!(select(&rollouts, &llama(), true).shadow, None);
    assert_eq!(select(&rollouts, &vllm_next(), true).shadow, None);
    // Passing shadow evidence alone serves nothing either.
    rollouts
        .record(pass(&v1, RolloutStage::Shadow), &fakes)
        .unwrap();
    assert_eq!(
        serving(&rollouts, &vllm(), true),
        ServingHelper::SourceInjection
    );
    assert_eq!(
        rollouts.records()[0].event,
        RolloutEvent::Proposed {
            pin: v1.id(),
            version: version(1, 0, 0)
        }
    );
}

#[test]
fn promotion_needs_a_measured_pass_recorded_at_the_current_stage() {
    let fakes = FakePins::default();
    let mut rollouts = HelperRollouts::new();
    let v1 = fake_pin_at(1, 0, 0);
    let helper = helper_id();
    assert_eq!(
        rollouts.promote(&helper, VLLM, &fakes),
        Err(RolloutRefusal::UnknownTrack)
    );
    rollouts.propose(v1.clone(), VLLM, &fakes).unwrap();
    assert_eq!(
        rollouts.promote(&helper, VLLM, &fakes),
        Err(RolloutRefusal::NoPassingEvidence {
            stage: RolloutStage::Shadow
        })
    );
    // A fake-substrate pass is recorded and promotes nothing.
    let fake = trial(
        &v1,
        &vllm(),
        RolloutStage::Shadow,
        TrialVerdict::Passed,
        simulated(),
    );
    assert_eq!(rollouts.record(fake, &fakes), Ok(RecordOutcome::Recorded));
    assert_eq!(
        rollouts.promote(&helper, VLLM, &fakes),
        Err(RolloutRefusal::FakeSubstrateOnly {
            stage: RolloutStage::Shadow
        })
    );
    // Evidence from another stage or an unsupported runner is refused, not counted.
    assert_eq!(
        rollouts.record(pass(&v1, RolloutStage::OptIn), &fakes),
        Err(RolloutRefusal::StageMismatch {
            expected: RolloutStage::Shadow,
            found: RolloutStage::OptIn
        })
    );
    let unsupported = trial(
        &v1,
        &vllm_next(),
        RolloutStage::Shadow,
        TrialVerdict::Passed,
        measured(),
    );
    assert_eq!(
        rollouts.record(unsupported, &fakes),
        Err(RolloutRefusal::RunnerNotSupported {
            pin: v1.id(),
            runner: vllm_next()
        })
    );
    assert_eq!(
        rollouts.promote(&helper, VLLM, &fakes),
        Err(RolloutRefusal::FakeSubstrateOnly {
            stage: RolloutStage::Shadow
        })
    );

    // A measured shadow pass promotes to opt-in, and only to opt-in.
    rollouts
        .record(pass(&v1, RolloutStage::Shadow), &fakes)
        .unwrap();
    assert_eq!(
        rollouts.promote(&helper, VLLM, &fakes),
        Ok(Promotion {
            pin: v1.id(),
            from: RolloutStage::Shadow,
            to: RolloutStage::OptIn
        })
    );
    assert_eq!(
        rollouts.promote(&helper, VLLM, &fakes),
        Err(RolloutRefusal::NoPassingEvidence {
            stage: RolloutStage::OptIn
        })
    );
    // A late shadow result no longer applies.
    assert_eq!(
        rollouts.record(pass(&v1, RolloutStage::Shadow), &fakes),
        Err(RolloutRefusal::StageMismatch {
            expected: RolloutStage::OptIn,
            found: RolloutStage::Shadow
        })
    );
    rollouts
        .record(pass(&v1, RolloutStage::OptIn), &fakes)
        .unwrap();
    assert_eq!(
        rollouts.promote(&helper, VLLM, &fakes),
        Ok(Promotion {
            pin: v1.id(),
            from: RolloutStage::OptIn,
            to: RolloutStage::BackendDefault
        })
    );
    let view = track(&rollouts);
    assert_eq!(view.default, DefaultPath::Bundle { pin: v1.clone() });
    assert_eq!(view.candidate, None);
    assert_eq!(view.source_injection, SourceInjection::Retained);
    assert_eq!(
        rollouts.promote(&helper, VLLM, &fakes),
        Err(RolloutRefusal::NoCandidate)
    );
    let promotions = rollouts
        .records()
        .iter()
        .filter(|record| matches!(record.event, RolloutEvent::Promoted { .. }))
        .count();
    assert_eq!(promotions, 2);
}

#[test]
fn opt_in_serves_only_runners_that_opted_in() {
    let fakes = FakePins::default();
    let mut rollouts = HelperRollouts::new();
    let v1 = fake_pin_at(1, 0, 0);
    rollouts.propose(v1.clone(), VLLM, &fakes).unwrap();
    rollouts
        .record(pass(&v1, RolloutStage::Shadow), &fakes)
        .unwrap();
    rollouts.promote(&helper_id(), VLLM, &fakes).unwrap();
    assert_eq!(serving(&rollouts, &vllm(), true), bundle(&v1));
    let declined = select(&rollouts, &vllm(), false);
    assert_eq!(declined.serve, ServingHelper::SourceInjection);
    assert_eq!(declined.shadow, None);
    assert_eq!(
        serving(&rollouts, &vllm_next(), true),
        ServingHelper::SourceInjection
    );
}

#[test]
fn the_default_serves_new_runners_of_its_backend_only() {
    let fakes = FakePins::default();
    let mut rollouts = HelperRollouts::new();
    let v1 = fake_pin_at(1, 0, 0);
    make_default(&mut rollouts, &v1, &fakes);
    assert_eq!(serving(&rollouts, &vllm(), false), bundle(&v1));
    assert_eq!(serving(&rollouts, &vllm(), true), bundle(&v1));
    // Another backend's track is untouched.
    assert_eq!(rollouts.track(&helper_id(), Backend::LlamaCpp), None);
    assert_eq!(
        serving(&rollouts, &llama(), true),
        ServingHelper::SourceInjection
    );
    // A runner version the default does not support falls back, saying why.
    let other = select(&rollouts, &vllm_next(), false);
    assert_eq!(other.serve, ServingHelper::SourceInjection);
    assert_eq!(
        other.fallback,
        Some(FallbackReason::RunnerNotSupported { pin: v1.id() })
    );
    // So does a default that may not be loaded now.
    let mut quarantined = FakePins::default();
    let refusal = PinRefusal::NotPublished;
    quarantined.refuse(&v1, refusal.clone());
    let refused = rollouts
        .select(&helper_id(), &vllm(), false, &quarantined)
        .unwrap();
    assert_eq!(refused.serve, ServingHelper::SourceInjection);
    assert_eq!(
        refused.fallback,
        Some(FallbackReason::NotAdmissible {
            pin: v1.id(),
            refusal
        })
    );
}

#[test]
fn failure_evidence_rolls_back_to_the_last_good_version() {
    let fakes = FakePins::default();
    let mut rollouts = HelperRollouts::new();
    let v1 = fake_pin_at(1, 0, 0);
    let v2 = fake_pin_at(1, 1, 0);
    make_default(&mut rollouts, &v1, &fakes);
    make_default(&mut rollouts, &v2, &fakes);
    assert_eq!(serving(&rollouts, &vllm(), false), bundle(&v2));
    assert_eq!(track(&rollouts).previous, vec![v1.clone()]);

    assert_eq!(
        rollouts.record(fail(&v2, RolloutStage::BackendDefault), &fakes),
        Ok(RecordOutcome::RolledBack {
            failed: v2.id(),
            stage: RolloutStage::BackendDefault,
            to: RollbackTarget::Bundle { pin: v1.id() }
        })
    );
    assert_eq!(serving(&rollouts, &vllm(), false), bundle(&v1));
    let view = track(&rollouts);
    assert_eq!(view.previous, Vec::<HelperPin>::new());
    assert_eq!(view.failed, vec![v2.id()]);
    assert_eq!(view.source_injection, SourceInjection::Retained);
    match &rollouts.records().last().unwrap().event {
        RolloutEvent::RolledBack {
            failed, to, reason, ..
        } => {
            assert_eq!(*failed, v2.id());
            assert_eq!(*to, RollbackTarget::Bundle { pin: v1.id() });
            assert_eq!(*reason, label("shadow-mismatch"));
        }
        other => panic!("expected a rollback, got {other:?}"),
    }
    // The failed version never returns, and a rollout never goes backwards.
    assert_eq!(
        rollouts.propose(v2.clone(), VLLM, &fakes),
        Err(RolloutRefusal::PreviouslyFailed { pin: v2.id() })
    );
    assert_eq!(
        rollouts.propose(fake_pin_at(1, 0, 5), VLLM, &fakes),
        Err(RolloutRefusal::NotNewer {
            proposed: version(1, 0, 5),
            newest: version(1, 1, 0)
        })
    );
    rollouts
        .propose(fake_pin_at(1, 2, 0), VLLM, &fakes)
        .unwrap();
    // With no good version left, the track falls back to source injection.
    assert!(matches!(
        rollouts.record(fail(&v1, RolloutStage::BackendDefault), &fakes),
        Ok(RecordOutcome::RolledBack {
            to: RollbackTarget::SourceInjection,
            ..
        })
    ));
    assert_eq!(
        serving(&rollouts, &vllm(), false),
        ServingHelper::SourceInjection
    );
}

#[test]
fn a_rollback_passes_over_failed_and_inadmissible_versions() {
    let mut fakes = FakePins::default();
    let mut rollouts = HelperRollouts::new();
    let v1 = fake_pin_at(1, 0, 0);
    let v2 = fake_pin_at(1, 1, 0);
    let v3 = fake_pin_at(1, 2, 0);
    for pin in [&v1, &v2, &v3] {
        make_default(&mut rollouts, pin, &fakes);
    }
    assert_eq!(track(&rollouts).previous, vec![v1.clone(), v2.clone()]);
    let quarantined = PinRefusal::NotPublished;
    fakes.refuse(&v2, quarantined.clone());
    assert_eq!(
        rollouts.record(fail(&v3, RolloutStage::BackendDefault), &fakes),
        Ok(RecordOutcome::RolledBack {
            failed: v3.id(),
            stage: RolloutStage::BackendDefault,
            to: RollbackTarget::Bundle { pin: v1.id() }
        })
    );
    match &rollouts.records().last().unwrap().event {
        RolloutEvent::RolledBack { skipped, .. } => {
            assert_eq!(*skipped, vec![(v2.id(), quarantined)]);
        }
        other => panic!("expected a rollback, got {other:?}"),
    }
}

#[test]
fn a_failing_candidate_is_withdrawn_without_changing_what_serves() {
    let fakes = FakePins::default();
    let mut rollouts = HelperRollouts::new();
    let v1 = fake_pin_at(1, 0, 0);
    make_default(&mut rollouts, &v1, &fakes);

    let v2 = fake_pin_at(1, 1, 0);
    rollouts.propose(v2.clone(), VLLM, &fakes).unwrap();
    assert_eq!(
        rollouts.record(fail(&v2, RolloutStage::Shadow), &fakes),
        Ok(RecordOutcome::RolledBack {
            failed: v2.id(),
            stage: RolloutStage::Shadow,
            to: RollbackTarget::Bundle { pin: v1.id() }
        })
    );
    assert_eq!(track(&rollouts).candidate, None);
    assert_eq!(select(&rollouts, &vllm(), true).shadow, None);

    let v3 = fake_pin_at(1, 2, 0);
    rollouts.propose(v3.clone(), VLLM, &fakes).unwrap();
    rollouts
        .record(pass(&v3, RolloutStage::Shadow), &fakes)
        .unwrap();
    rollouts.promote(&helper_id(), VLLM, &fakes).unwrap();
    assert_eq!(serving(&rollouts, &vllm(), true), bundle(&v3));
    // A fake-substrate failure rolls back as well: failures are never ignored.
    let failure = trial(
        &v3,
        &vllm(),
        RolloutStage::OptIn,
        TrialVerdict::Failed {
            reason: label("crash"),
        },
        simulated(),
    );
    assert!(matches!(
        rollouts.record(failure, &fakes),
        Ok(RecordOutcome::RolledBack {
            stage: RolloutStage::OptIn,
            ..
        })
    ));
    assert_eq!(serving(&rollouts, &vllm(), true), bundle(&v1));
    assert_eq!(track(&rollouts).failed.len(), 2);
}

#[test]
fn a_rollout_moves_forward_one_admissible_candidate_at_a_time() {
    let mut fakes = FakePins::default();
    let mut rollouts = HelperRollouts::new();
    let v1 = fake_pin_at(1, 0, 0);
    let llama_only = fake_pin(version(1, 0, 0), &[llama()]);
    assert_eq!(
        rollouts.propose(llama_only.clone(), VLLM, &fakes),
        Err(RolloutRefusal::BackendNotSupported {
            pin: llama_only.id(),
            backend: VLLM
        })
    );
    fakes.refuse(&v1, PinRefusal::NotPublished);
    assert_eq!(
        rollouts.propose(v1.clone(), VLLM, &fakes),
        Err(RolloutRefusal::NotAdmissible {
            pin: v1.id(),
            refusal: PinRefusal::NotPublished
        })
    );
    let fakes = FakePins::default();
    rollouts.propose(v1.clone(), VLLM, &fakes).unwrap();
    assert_eq!(
        rollouts.propose(fake_pin_at(1, 1, 0), VLLM, &fakes),
        Err(RolloutRefusal::CandidateInFlight { candidate: v1.id() })
    );
    // The same version can roll out on another backend at the same time.
    rollouts
        .propose(v1.clone(), Backend::LlamaCpp, &fakes)
        .unwrap();
    assert_eq!(
        rollouts
            .track(&helper_id(), Backend::LlamaCpp)
            .unwrap()
            .candidate,
        Some((v1.clone(), RolloutStage::Shadow))
    );
    // Promotion checks admissibility again.
    rollouts
        .record(pass(&v1, RolloutStage::Shadow), &fakes)
        .unwrap();
    let mut withdrawn = FakePins::default();
    withdrawn.refuse(&v1, PinRefusal::NotPublished);
    assert_eq!(
        rollouts.promote(&helper_id(), VLLM, &withdrawn),
        Err(RolloutRefusal::NotAdmissible {
            pin: v1.id(),
            refusal: PinRefusal::NotPublished
        })
    );
    // An inadmissible shadow or opt-in candidate is not loaded.
    let selected = rollouts
        .select(&helper_id(), &vllm(), true, &withdrawn)
        .unwrap();
    assert_eq!(selected.shadow, None);
    // The default cannot be proposed again.
    rollouts.promote(&helper_id(), VLLM, &fakes).unwrap();
    rollouts
        .record(pass(&v1, RolloutStage::OptIn), &fakes)
        .unwrap();
    rollouts.promote(&helper_id(), VLLM, &fakes).unwrap();
    assert_eq!(
        rollouts.propose(v1.clone(), VLLM, &fakes),
        Err(RolloutRefusal::NotNewer {
            proposed: version(1, 0, 0),
            newest: version(1, 0, 0)
        })
    );
}

#[test]
fn evidence_must_name_a_rolling_out_or_default_version() {
    let fakes = FakePins::default();
    let mut rollouts = HelperRollouts::new();
    let v1 = fake_pin_at(1, 0, 0);
    let v2 = fake_pin_at(1, 1, 0);
    let stranger = fake_pin_at(7, 0, 0);
    assert_eq!(
        rollouts.record(pass(&stranger, RolloutStage::Shadow), &fakes),
        Err(RolloutRefusal::UnknownPin { pin: stranger.id() })
    );
    make_default(&mut rollouts, &v1, &fakes);
    make_default(&mut rollouts, &v2, &fakes);
    // An earlier default is a rollback target, not a version under trial.
    assert_eq!(
        rollouts.record(fail(&v1, RolloutStage::BackendDefault), &fakes),
        Err(RolloutRefusal::UnknownPin { pin: v1.id() })
    );
    // Evidence on another backend names that backend's track.
    let on_llama = trial(
        &v2,
        &llama(),
        RolloutStage::BackendDefault,
        TrialVerdict::Passed,
        measured(),
    );
    assert_eq!(
        rollouts.record(on_llama, &fakes),
        Err(RolloutRefusal::UnknownPin { pin: v2.id() })
    );
    assert_eq!(serving(&rollouts, &vllm(), false), bundle(&v2));
}

#[test]
fn source_injection_is_removed_only_by_a_recorded_decision_after_the_replacement_passed() {
    let fakes = FakePins::default();
    let mut rollouts = HelperRollouts::new();
    let helper = helper_id();
    assert_eq!(
        rollouts.remove_source_injection(&helper, VLLM, removal()),
        Err(RolloutRefusal::UnknownTrack)
    );
    let v1 = fake_pin_at(1, 0, 0);
    rollouts.propose(v1.clone(), VLLM, &fakes).unwrap();
    assert_eq!(
        rollouts.remove_source_injection(&helper, VLLM, removal()),
        Err(RolloutRefusal::ReplacementNotProven)
    );
    rollouts
        .record(pass(&v1, RolloutStage::Shadow), &fakes)
        .unwrap();
    rollouts.promote(&helper, VLLM, &fakes).unwrap();
    rollouts
        .record(pass(&v1, RolloutStage::OptIn), &fakes)
        .unwrap();
    rollouts.promote(&helper, VLLM, &fakes).unwrap();
    // Promoted, but not yet passed as the backend default; a fake pass does not count.
    assert_eq!(
        rollouts.remove_source_injection(&helper, VLLM, removal()),
        Err(RolloutRefusal::ReplacementNotProven)
    );
    let fake = trial(
        &v1,
        &vllm(),
        RolloutStage::BackendDefault,
        TrialVerdict::Passed,
        simulated(),
    );
    rollouts.record(fake, &fakes).unwrap();
    assert_eq!(
        rollouts.remove_source_injection(&helper, VLLM, removal()),
        Err(RolloutRefusal::ReplacementNotProven)
    );
    assert_eq!(track(&rollouts).source_injection, SourceInjection::Retained);

    rollouts
        .record(pass(&v1, RolloutStage::BackendDefault), &fakes)
        .unwrap();
    let evidence = measured().yougori_evidence().unwrap();
    assert!(rollouts.records().iter().any(|record| record.event
        == RolloutEvent::Proven {
            pin: v1.id(),
            evidence
        }));
    rollouts
        .remove_source_injection(&helper, VLLM, removal())
        .unwrap();
    assert_eq!(
        track(&rollouts).source_injection,
        SourceInjection::Removed {
            replacement: v1.id(),
            evidence,
            decided_by: label("release-owner"),
            reason: label("bundle-proven"),
        }
    );
    assert_eq!(
        rollouts.records().last().unwrap().event,
        RolloutEvent::SourceInjectionRemoved {
            replacement: v1.id(),
            evidence,
            decided_by: label("release-owner"),
            reason: label("bundle-proven"),
        }
    );
    assert_eq!(
        rollouts.remove_source_injection(&helper, VLLM, removal()),
        Err(RolloutRefusal::SourceInjectionAlreadyRemoved)
    );
    // The other backend keeps it.
    assert_eq!(
        serving(&rollouts, &llama(), false),
        ServingHelper::SourceInjection
    );

    // Without the fallback, a runner the default cannot serve is refused with why...
    assert_eq!(
        rollouts.select(&helper, &vllm_next(), false, &fakes),
        Err(SelectionRefusal::DefaultUnusable {
            reason: FallbackReason::RunnerNotSupported { pin: v1.id() }
        })
    );
    // ...and a failing default with no earlier good version leaves nothing to serve.
    assert_eq!(
        rollouts.record(fail(&v1, RolloutStage::BackendDefault), &fakes),
        Ok(RecordOutcome::RolledBack {
            failed: v1.id(),
            stage: RolloutStage::BackendDefault,
            to: RollbackTarget::Unavailable
        })
    );
    assert_eq!(
        rollouts.select(&helper, &vllm(), false, &fakes),
        Err(SelectionRefusal::Unavailable)
    );
    // A newer version can still be rolled out to recover.
    let v2 = fake_pin_at(1, 1, 0);
    make_default(&mut rollouts, &v2, &fakes);
    assert_eq!(serving(&rollouts, &vllm(), false), bundle(&v2));
}

#[test]
fn every_decision_is_recorded_in_order() {
    let fakes = FakePins::default();
    let mut rollouts = HelperRollouts::new();
    let v1 = fake_pin_at(1, 0, 0);
    make_default(&mut rollouts, &v1, &fakes);
    rollouts
        .record(fail(&v1, RolloutStage::BackendDefault), &fakes)
        .unwrap();
    let kinds: Vec<&str> = rollouts
        .records()
        .iter()
        .map(|record| match record.event {
            RolloutEvent::Proposed { .. } => "proposed",
            RolloutEvent::Evidence { .. } => "evidence",
            RolloutEvent::Promoted { .. } => "promoted",
            RolloutEvent::Proven { .. } => "proven",
            RolloutEvent::RolledBack { .. } => "rolled_back",
            RolloutEvent::SourceInjectionRemoved { .. } => "source_injection_removed",
        })
        .collect();
    assert_eq!(
        kinds,
        [
            "proposed",
            "evidence",
            "promoted",
            "evidence",
            "promoted",
            "evidence",
            "rolled_back"
        ]
    );
    for (index, record) in rollouts.records().iter().enumerate() {
        assert_eq!(record.sequence, u64::try_from(index).unwrap());
        assert_eq!(record.helper, helper_id());
        assert_eq!(record.backend, VLLM);
    }
    let written = serde_json::to_value(rollouts.records()).unwrap();
    assert_eq!(written[0]["event"]["event"], "proposed");
    assert_eq!(written[6]["event"]["to"]["path"], "source_injection");
    assert_eq!(written[1]["event"]["measured"], true);
}
