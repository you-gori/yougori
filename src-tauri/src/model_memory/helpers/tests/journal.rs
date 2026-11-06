//! G08 "persist rollout state" and "record rollout decisions with CORE-08 evidence": the
//! durable rollout journal across simulated restarts (the stream's owner released and
//! taken again, the state rebuilt), with retention, gaps and tampering (a rewritten
//! record, a deleted segment, a rollback attempt).

use std::fs;
use std::path::{Path, PathBuf};

use super::super::journal::{
    RecordedDefault, RecordedEvidence, RecordedOutcome, RecordedSourceInjection, RecordedTarget,
    RecordedTrack, RecordedVerdict, TrackPosition,
};
use super::*;
use crate::foundation::catalog::IntegrityFailure;
use crate::foundation::events::{
    DurableLog, DurableStreamId, EventSequence, GapReason, LogConfig, LogDamage, LogEntry,
    LogError, LogMarker, ProducerId, ReadItem, Takeover,
};
use crate::foundation::signing::SignedComponent;

const VLLM: Backend = Backend::Vllm;

fn stream() -> DurableStreamId {
    DurableStreamId::new("model-memory.helper-rollouts").unwrap()
}

fn owner() -> ProducerId {
    ProducerId::new("model-memory.rollouts").unwrap()
}

fn config(max_entries: u64, segment_entries: u64) -> LogConfig {
    LogConfig {
        max_entries,
        max_bytes: 1 << 22,
        segment_entries,
        segment_bytes: 1 << 18,
    }
}

/// One record per segment, so a test cuts records off by deleting files.
fn roomy() -> LogConfig {
    config(10_000, 1)
}

fn open_with(
    directory: &Path,
    config: LogConfig,
    admissible: &dyn PinAdmissibility,
    on_quarantine: OnQuarantine,
) -> Result<(RolloutJournal, ReplayReport), JournalError> {
    RolloutJournal::open(
        directory,
        stream(),
        owner(),
        config,
        admissible,
        on_quarantine,
    )
}

fn open(directory: &Path) -> (RolloutJournal, ReplayReport) {
    open_with(
        directory,
        roomy(),
        &FakePins::default(),
        OnQuarantine::Refuse,
    )
    .unwrap()
}

fn withdrawal() -> Withdrawal {
    Withdrawal {
        decided_by: label("release-owner"),
        reason: label("key-revoked"),
    }
}

/// A pin to a bundle that was never imported, published by helper key 1.
fn signed_pin(major: u32, minor: u32, patch: u32) -> HelperPin {
    HelperPin {
        publisher: publisher(1),
        ..fake_pin_at(major, minor, patch)
    }
}

/// Key 1's verified signature over `pin`'s bundle statement, checked in June 2026.
fn component(pin: &HelperPin) -> SignedComponent {
    let statement = pin_statement(pin);
    let signature = pair(1).sign(statement.as_bytes()).as_ref().to_vec();
    SignedComponent::check(
        &roots_from(root_keys()),
        HELPER_CLASS,
        &publisher(1),
        statement,
        &signature,
        at("2026-06-01T00:00:00Z"),
    )
}

/// A measured run on another authorized host: other run records than [`measured`].
fn measured_elsewhere() -> Provenance {
    Provenance::of_records(&[run_record(RunSubstrate::AuthorizedDisposable {
        authorization: label("other-test-host"),
    })])
    .unwrap()
}

/// The reference to [`measured`] with `pin`'s component, built again from the records.
fn reference(pin: &HelperPin) -> EvidenceReference {
    EvidenceReference::of(&measured(), component(pin)).unwrap()
}

fn record_pass(journal: &mut RolloutJournal, pin: &HelperPin, stage: RolloutStage) {
    journal
        .record(pass(pin, stage), component(pin), &FakePins::default())
        .unwrap();
}

fn promote(journal: &mut RolloutJournal, pin: &HelperPin) -> Promotion {
    journal
        .promote(&helper_id(), VLLM, &reference(pin), &FakePins::default())
        .unwrap()
}

/// Takes `pin` through shadow and opt-in to the vLLM default on measured passes.
fn make_default_in(journal: &mut RolloutJournal, pin: &HelperPin) {
    journal
        .propose(pin.clone(), VLLM, &FakePins::default())
        .unwrap();
    record_pass(journal, pin, RolloutStage::Shadow);
    promote(journal, pin);
    record_pass(journal, pin, RolloutStage::OptIn);
    promote(journal, pin);
}

fn instance(name: &str) -> RunnerInstance {
    RunnerInstance::new(name).unwrap()
}

/// Selects the gpu-optimizer for a new vLLM 0.29.0 runner and records its start.
fn start(journal: &mut RolloutJournal, name: &str, opted_in: bool) -> RunnerStart {
    let selected = journal
        .select(&helper_id(), &vllm(), opted_in, &FakePins::default())
        .unwrap();
    journal
        .start_runner(instance(name), vllm(), vec![selected])
        .unwrap()
}

fn v1() -> HelperPin {
    signed_pin(1, 0, 0)
}

fn v2() -> HelperPin {
    signed_pin(1, 1, 0)
}

/// Track records 1–9 at sequences 1–9, then the runners at 10 and 11: v1 is the vLLM
/// default with a measured pass as the default (records 1–6), v2 is the opt-in candidate
/// (records 7–9), `env-a` serves v1 and `env-b`, opted in, v2.
fn history(directory: &Path) {
    let (mut journal, _) = open(directory);
    make_default_in(&mut journal, &v1());
    record_pass(&mut journal, &v1(), RolloutStage::BackendDefault);
    journal.propose(v2(), VLLM, &FakePins::default()).unwrap();
    record_pass(&mut journal, &v2(), RolloutStage::Shadow);
    promote(&mut journal, &v2());
    start(&mut journal, "env-a", false);
    start(&mut journal, "env-b", true);
    assert_eq!(journal.log().last().map(EventSequence::get), Some(11));
    journal.close().unwrap();
}

/// What a restart must keep: the track, its floor and the named runners' pins.
type Snapshot = (
    Option<TrackView>,
    Option<HelperVersion>,
    Vec<Option<RunnerStart>>,
);

fn snapshot(journal: &RolloutJournal, runners: &[&str]) -> Snapshot {
    (
        journal.rollouts().track(&helper_id(), VLLM),
        journal.floor(&helper_id(), VLLM),
        runners
            .iter()
            .map(|name| journal.runners().get(&instance(name)).cloned())
            .collect(),
    )
}

fn segments(directory: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("segment-")
        })
        .collect();
    found.sort();
    found
}

/// Changes one character of the JSON of the only line in the segment at `path`.
fn rewrite(path: &Path) {
    let mut bytes = fs::read(path).unwrap();
    let at = bytes
        .windows(9)
        .position(|window| window == b"\"floor\":\"")
        .unwrap()
        + 9;
    bytes[at] = if bytes[at] == b'1' { b'2' } else { b'1' };
    fs::write(path, bytes).unwrap();
}

/// Every record of the stream, in order.
fn stored(log: &DurableLog<JournalRecord>) -> Vec<JournalRecord> {
    let batch = log.read(&log.start(), 10_000).unwrap();
    batch
        .items
        .into_iter()
        .filter_map(|item| match item {
            ReadItem::Entry {
                entry: LogEntry::Record(record),
                ..
            } => Some(record),
            _ => None,
        })
        .collect()
}

fn position(record: u64, floor: HelperVersion) -> TrackPosition {
    TrackPosition {
        helper: helper_id(),
        backend: VLLM,
        record,
        floor,
    }
}

fn recorded(pin: &HelperPin, provenance: &Provenance) -> RecordedEvidence {
    RecordedEvidence::from(&EvidenceReference::of(provenance, component(pin)).unwrap())
}

/// Builds [`history`] in a new directory, appends `forged` as a raw owner of the stream
/// would, opens the journal on it and returns the track it rebuilt.
fn forged(forged: Vec<JournalRecord>) -> Result<Option<TrackView>, JournalError> {
    let directory = tempfile::tempdir().unwrap();
    history(directory.path());
    let (mut raw, _) =
        DurableLog::<JournalRecord>::open(directory.path(), stream(), owner(), roomy()).unwrap();
    for record in forged {
        raw.append(record).unwrap();
    }
    raw.close().unwrap();
    let (journal, _) = open_with(
        directory.path(),
        roomy(),
        &FakePins::default(),
        OnQuarantine::Refuse,
    )?;
    let track = journal.rollouts().track(&helper_id(), VLLM);
    journal.close().unwrap();
    Ok(track)
}

fn replay_refusal(result: Result<Option<TrackView>, JournalError>) -> ReplayRefusal {
    match result {
        Err(JournalError::Replay(refusal)) => refusal,
        Err(other) => panic!("not a replay refusal: {other:?}"),
        Ok(_) => panic!("the replay accepted the stream"),
    }
}

#[test]
fn every_decision_and_running_runner_survives_a_restart() {
    let directory = tempfile::tempdir().unwrap();
    history(directory.path());
    let (mut journal, report) = open(directory.path());
    assert!(matches!(report.opened.takeover, Takeover::Released { .. }));
    assert_eq!(report.records, 11);
    assert!(report.gaps.is_empty() && report.fell_back.is_empty() && !report.restated);

    // A failure rolls the candidate back; runners start and stop; the owner removes
    // source injection on the default's measured pass as the default.
    assert_eq!(
        journal
            .record(
                fail(&v2(), RolloutStage::OptIn),
                component(&v2()),
                &FakePins::default()
            )
            .unwrap(),
        RecordOutcome::RolledBack {
            failed: v2().id(),
            stage: RolloutStage::OptIn,
            to: RollbackTarget::Bundle { pin: v1().id() },
        }
    );
    start(&mut journal, "env-c", true);
    assert_eq!(
        journal
            .stop_runner(&instance("env-a"))
            .unwrap()
            .unwrap()
            .runner,
        instance("env-a")
    );
    assert_eq!(journal.stop_runner(&instance("env-a")).unwrap(), None);
    journal
        .remove_source_injection(
            &helper_id(),
            VLLM,
            SourceInjectionRemoval {
                decided_by: label("release-owner"),
                reason: label("bundle-proven"),
            },
            &reference(&v1()),
        )
        .unwrap();
    let runners = ["env-a", "env-b", "env-c"];
    let before = snapshot(&journal, &runners);
    assert_eq!(before.1, Some(version(1, 1, 0)));
    assert_eq!(
        before.0.as_ref().unwrap().failed,
        vec![v2().id()],
        "the failed candidate is remembered"
    );
    journal.close().unwrap();

    // The owner released the stream; the next one rebuilds the same state.
    let (mut journal, report) = open(directory.path());
    assert!(matches!(report.opened.takeover, Takeover::Released { .. }));
    assert!(report.gaps.is_empty() && report.fell_back.is_empty());
    assert_eq!(snapshot(&journal, &runners), before);
    // env-b still runs the failed v2, exactly as it started; the host learns it.
    assert_eq!(
        journal.runners().serving(&instance("env-b"), &helper_id()),
        Some(&ServingHelper::Bundle { pin: v2() })
    );
    assert_eq!(
        journal.runners().running_on(v2().id()),
        vec![instance("env-b")]
    );
    // Decisions continue from the rebuilt state: the failed version is never proposed
    // again, and a newer one is.
    assert_eq!(
        journal.propose(v2(), VLLM, &FakePins::default()),
        Err(JournalError::Rollout(RolloutRefusal::PreviouslyFailed {
            pin: v2().id()
        }))
    );
    journal
        .propose(signed_pin(1, 2, 0), VLLM, &FakePins::default())
        .unwrap();
    assert_eq!(
        journal
            .select(&helper_id(), &vllm(), false, &FakePins::default())
            .unwrap()
            .serve,
        ServingHelper::Bundle { pin: v1() }
    );
    let after = snapshot(&journal, &runners);
    journal.close().unwrap();
    let (journal, _) = open(directory.path());
    assert_eq!(snapshot(&journal, &runners), after);
}

#[test]
fn one_owner_at_a_time() {
    let directory = tempfile::tempdir().unwrap();
    let (journal, report) = open(directory.path());
    assert!(report.opened.created);
    assert!(matches!(
        open_with(
            directory.path(),
            roomy(),
            &FakePins::default(),
            OnQuarantine::Refuse
        ),
        Err(JournalError::Log(LogError::Owner(_)))
    ));
    journal.close().unwrap();
    let (_journal, report) = open(directory.path());
    assert!(matches!(report.opened.takeover, Takeover::Released { .. }));
}

#[test]
fn a_runner_restarts_with_exactly_what_it_started_with() {
    let directory = tempfile::tempdir().unwrap();
    let (mut journal, _) = open(directory.path());
    make_default_in(&mut journal, &v1());
    journal.propose(v2(), VLLM, &FakePins::default()).unwrap();
    // The default may not be loaded on this host: the runner falls back with the reason,
    // and loads the shadow candidate beside.
    let mut pins = FakePins::default();
    pins.refuse(
        &v1(),
        PinRefusal::IncompatibleAbi {
            refusal: HelperAbiRefusal::MajorNotProvided {
                required: HelperAbi::new(1, 0),
                provided: vec![HelperAbi::new(2, 0)],
            },
        },
    );
    let selected = journal.select(&helper_id(), &vllm(), false, &pins).unwrap();
    assert!(selected.fallback.is_some() && selected.shadow == Some(v2()));
    let started = journal
        .start_runner(instance("env-a"), vllm(), vec![selected])
        .unwrap();
    journal.close().unwrap();
    let (journal, _) = open(directory.path());
    assert_eq!(journal.runners().get(&instance("env-a")), Some(&started));
}

#[test]
fn restatements_let_retention_drop_without_forgetting() {
    let directory = tempfile::tempdir().unwrap();
    let (mut journal, _) = open_with(
        directory.path(),
        config(30, 2),
        &FakePins::default(),
        OnQuarantine::Refuse,
    )
    .unwrap();
    make_default_in(&mut journal, &v1());
    journal.propose(v2(), VLLM, &FakePins::default()).unwrap();
    start(&mut journal, "env-kept", true);
    for round in 0..40 {
        let name = format!("env-{round}");
        start(&mut journal, &name, false);
        journal.stop_runner(&instance(&name)).unwrap();
    }
    assert!(journal.log().retention().dropped_entries > 0);
    assert!(stored(journal.log())
        .iter()
        .any(|record| matches!(record, JournalRecord::RestatementBegins { .. })));
    let before = snapshot(&journal, &["env-kept", "env-39"]);
    journal.close().unwrap();

    let (journal, report) = open_with(
        directory.path(),
        config(30, 2),
        &FakePins::default(),
        OnQuarantine::Refuse,
    )
    .unwrap();
    assert!(report.restatement.is_some());
    assert!(report.fell_back.is_empty() && !report.restated);
    assert_eq!(snapshot(&journal, &["env-kept", "env-39"]), before);
    assert_eq!(before.2[1], None);
}

#[test]
fn a_restatement_that_cannot_fit_is_refused_before_anything_is_written() {
    let directory = tempfile::tempdir().unwrap();
    // Half of six entries less a segment of four leaves one entry: room for one record,
    // never for a restatement.
    let (mut journal, _) = open_with(
        directory.path(),
        config(6, 4),
        &FakePins::default(),
        OnQuarantine::Refuse,
    )
    .unwrap();
    journal.propose(v1(), VLLM, &FakePins::default()).unwrap();
    let before = journal.rollouts().track(&helper_id(), VLLM);
    assert!(matches!(
        journal.record(
            pass(&v1(), RolloutStage::Shadow),
            component(&v1()),
            &FakePins::default()
        ),
        Err(JournalError::NoRoom {
            needed_entries: 3,
            budget_entries: 1,
            ..
        })
    ));
    assert_eq!(journal.log().last().map(EventSequence::get), Some(1));
    assert_eq!(journal.rollouts().track(&helper_id(), VLLM), before);
    journal.close().unwrap();
    assert_eq!(
        open_with(
            directory.path(),
            config(4, 4),
            &FakePins::default(),
            OnQuarantine::Refuse
        )
        .err(),
        Some(JournalError::BoundsTooSmall)
    );
}

#[test]
fn a_truncated_tail_makes_the_track_fall_back_never_forward() {
    let directory = tempfile::tempdir().unwrap();
    history(directory.path());
    // A deleted last segments: v2's shadow pass and promotion and both runner starts.
    for segment in segments(directory.path()).iter().skip(7) {
        fs::remove_file(segment).unwrap();
    }
    let (mut journal, report) = open(directory.path());
    assert_eq!(report.gaps.len(), 1);
    let (missing, reason) = report.gaps[0];
    assert_eq!((missing.first().get(), missing.last().get()), (8, 11));
    assert_eq!(reason, GapReason::Truncated);
    assert!(matches!(report.markers[0].1, LogMarker::Truncated { .. }));
    // The track kept the last good pinned version; the candidate whose fate the gap holds
    // was dropped, not failed, and its version stays below the floor.
    assert_eq!(
        report.fell_back,
        vec![FellBack {
            helper: helper_id(),
            backend: VLLM,
            dropped: Some(v2()),
            default: DefaultPath::Bundle { pin: v1() },
            floor: Some(version(1, 1, 0)),
        }]
    );
    assert!(report.restated);
    let track = journal.rollouts().track(&helper_id(), VLLM).unwrap();
    assert_eq!(track.candidate, None);
    assert!(track.failed.is_empty());
    assert_eq!(journal.runners().get(&instance("env-a")), None);
    assert_eq!(
        journal.propose(v2(), VLLM, &FakePins::default()),
        Err(JournalError::Rollout(RolloutRefusal::NotNewer {
            proposed: version(1, 1, 0),
            newest: version(1, 1, 0)
        }))
    );
    journal
        .propose(signed_pin(1, 2, 0), VLLM, &FakePins::default())
        .unwrap();
    let after = snapshot(&journal, &[]);
    journal.close().unwrap();
    // The open restated after the gap: the next replay starts after it.
    let (journal, report) = open(directory.path());
    assert!(report.fell_back.is_empty() && !report.restated);
    assert_eq!(snapshot(&journal, &[]), after);
}

#[test]
fn after_a_gap_only_records_that_move_a_track_back_apply() {
    let directory = tempfile::tempdir().unwrap();
    history(directory.path());
    for segment in segments(directory.path()).iter().skip(7) {
        fs::remove_file(segment).unwrap();
    }
    // The owner that wrote the lost records went on: the default failed (track record
    // 10), then it proposed v3 (record 11). This replay holds the track up to record 7.
    let (mut raw, _) =
        DurableLog::<JournalRecord>::open(directory.path(), stream(), owner(), roomy()).unwrap();
    raw.append(JournalRecord::Trial {
        track: position(10, version(1, 1, 0)),
        pin: v1().id(),
        runner: vllm(),
        stage: RolloutStage::BackendDefault,
        verdict: RecordedVerdict::Failed {
            reason: label("default-regressed"),
        },
        evidence: recorded(&v1(), &measured()),
        outcome: RecordedOutcome::RolledBack {
            to: RecordedTarget::SourceInjection {},
            skipped: Vec::new(),
        },
    })
    .unwrap();
    raw.append(JournalRecord::Proposed {
        track: position(11, version(1, 2, 0)),
        pin: signed_pin(1, 2, 0),
    })
    .unwrap();
    raw.close().unwrap();

    let (journal, report) = open(directory.path());
    assert_eq!(report.fell_back.len(), 1);
    // The failure moved the track back; the proposal after the gap did not move it on,
    // but raised the floor.
    let track = journal.rollouts().track(&helper_id(), VLLM).unwrap();
    assert_eq!(track.default, DefaultPath::SourceInjection);
    assert_eq!(track.candidate, None);
    assert_eq!(track.failed, vec![v1().id()]);
    assert_eq!(journal.floor(&helper_id(), VLLM), Some(version(1, 2, 0)));
    assert_eq!(
        journal
            .select(&helper_id(), &vllm(), true, &FakePins::default())
            .unwrap()
            .serve,
        ServingHelper::SourceInjection
    );
}

#[test]
fn a_retention_gap_after_the_last_restatement_falls_back_to_source_injection() {
    let directory = tempfile::tempdir().unwrap();
    history(directory.path());
    let (journal, _) = open(directory.path());
    let before = snapshot(&journal, &["env-a", "env-b"]);
    journal.close().unwrap();
    // Opened with lower bounds, retention drops records 1 and 2, which no restatement
    // holds: the track's records from 3 on cannot be replayed.
    let (journal, report) = open_with(
        directory.path(),
        config(9, 1),
        &FakePins::default(),
        OnQuarantine::Refuse,
    )
    .unwrap();
    assert_eq!(report.gaps[0].1, GapReason::Retention);
    assert_eq!(report.fell_back.len(), 1);
    let track = journal.rollouts().track(&helper_id(), VLLM).unwrap();
    assert_eq!(track.default, DefaultPath::SourceInjection);
    assert_eq!(track.candidate, None);
    assert_eq!(journal.floor(&helper_id(), VLLM), Some(version(1, 1, 0)));
    // The running runners keep exactly what they started with.
    assert_eq!(snapshot(&journal, &["env-a", "env-b"]).2, before.2);
}

#[test]
fn a_rewritten_record_is_detected() {
    // In the middle of the stream: the log refuses to open.
    let directory = tempfile::tempdir().unwrap();
    history(directory.path());
    rewrite(&segments(directory.path())[3]);
    assert!(matches!(
        open_with(
            directory.path(),
            roomy(),
            &FakePins::default(),
            OnQuarantine::Refuse
        ),
        Err(JournalError::Log(LogError::Damaged(LogDamage::Line { .. })))
    ));

    // At its end: a torn tail, kept aside and read as a gap; the track falls back.
    let directory = tempfile::tempdir().unwrap();
    history(directory.path());
    let (mut journal, _) = open(directory.path());
    journal
        .record(
            pass(&v2(), RolloutStage::OptIn),
            component(&v2()),
            &FakePins::default(),
        )
        .unwrap();
    journal.close().unwrap();
    rewrite(segments(directory.path()).last().unwrap());
    let (journal, report) = open(directory.path());
    assert!(report
        .markers
        .iter()
        .any(|(_, marker)| matches!(marker, LogMarker::TornTail { .. })));
    assert_eq!(report.gaps[0].1, GapReason::Truncated);
    assert_eq!(report.fell_back[0].dropped, Some(v2()));
    assert_eq!(
        journal
            .rollouts()
            .track(&helper_id(), VLLM)
            .unwrap()
            .default,
        DefaultPath::Bundle { pin: v1() }
    );
}

#[test]
fn a_deleted_segment_in_the_middle_refuses_the_stream() {
    let directory = tempfile::tempdir().unwrap();
    history(directory.path());
    fs::remove_file(&segments(directory.path())[4]).unwrap();
    assert!(matches!(
        open_with(
            directory.path(),
            roomy(),
            &FakePins::default(),
            OnQuarantine::Refuse
        ),
        Err(JournalError::Log(LogError::Damaged(_)))
    ));
}

#[test]
fn a_rollback_attempt_in_the_stream_is_refused() {
    let floor = version(1, 1, 0);
    // An old signed version offered again as an upgrade.
    let old = signed_pin(0, 9, 0);
    assert!(matches!(
        replay_refusal(forged(vec![JournalRecord::Proposed {
            track: position(10, old.version),
            pin: old.clone(),
        }])),
        ReplayRefusal::BelowFloor { proposed, floor: established, .. }
            if proposed == old.version && established == floor
    ));
    // A record lowering the floor.
    let failure =
        |record: u64, floor: HelperVersion, pin: &HelperPin, outcome| JournalRecord::Trial {
            track: position(record, floor),
            pin: pin.id(),
            runner: vllm(),
            stage: RolloutStage::BackendDefault,
            verdict: RecordedVerdict::Failed {
                reason: label("default-regressed"),
            },
            evidence: recorded(pin, &measured()),
            outcome,
        };
    let to_source = || RecordedOutcome::RolledBack {
        to: RecordedTarget::SourceInjection {},
        skipped: Vec::new(),
    };
    assert!(matches!(
        replay_refusal(forged(vec![failure(
            10,
            version(1, 0, 0),
            &v1(),
            to_source()
        )])),
        ReplayRefusal::FloorLowered { .. }
    ));
    // A rollback rewritten to land on an older version than the rule gives.
    assert!(matches!(
        replay_refusal(forged(vec![failure(
            10,
            floor,
            &v1(),
            RecordedOutcome::RolledBack {
                to: RecordedTarget::Bundle { pin: old.id() },
                skipped: Vec::new(),
            }
        )])),
        ReplayRefusal::Diverged { .. }
    ));
    // A promotion that rests on no recorded measured pass.
    assert!(matches!(
        replay_refusal(forged(vec![JournalRecord::Promoted {
            track: position(10, floor),
            pin: v2().id(),
            from: RolloutStage::OptIn,
            to: RolloutStage::BackendDefault,
            evidence: recorded(&v2(), &measured_elsewhere()),
        }])),
        ReplayRefusal::Diverged { .. }
    ));
    // A version the track never introduced.
    assert!(matches!(
        replay_refusal(forged(vec![failure(
            10,
            floor,
            &signed_pin(1, 0, 5),
            to_source()
        )])),
        ReplayRefusal::NotIntroduced { .. }
    ));
    // A record whose predecessors are gone without a gap.
    assert!(matches!(
        replay_refusal(forged(vec![failure(12, floor, &v1(), to_source())])),
        ReplayRefusal::Discontinuous {
            expected: 10,
            found: 12,
            ..
        }
    ));
    // A restatement that forgets the track, and one that lowers its floor.
    assert!(matches!(
        replay_refusal(forged(vec![JournalRecord::RestatementBegins {
            tracks: 0,
            runners: 0
        }])),
        ReplayRefusal::BadRecord { .. }
    ));
    let lowered = RecordedTrack {
        helper: helper_id(),
        backend: VLLM,
        records: 9,
        floor: version(1, 0, 0),
        default: RecordedDefault::SourceInjection {},
        previous: Vec::new(),
        candidate: None,
        failed: Vec::new(),
        proven: Vec::new(),
        source_injection: RecordedSourceInjection::Retained {},
    };
    assert!(matches!(
        replay_refusal(forged(vec![
            JournalRecord::RestatementBegins {
                tracks: 1,
                runners: 0
            },
            JournalRecord::RestatedTrack {
                part: 1,
                track: Box::new(lowered)
            },
        ])),
        ReplayRefusal::FloorLowered { .. }
    ));
    // The real failure, as recorded, replays.
    let track = forged(vec![failure(
        10,
        floor,
        &v1(),
        RecordedOutcome::RolledBack {
            to: RecordedTarget::SourceInjection {},
            skipped: Vec::new(),
        },
    )])
    .unwrap();
    assert_eq!(track.unwrap().default, DefaultPath::SourceInjection);
}

#[test]
fn unknown_and_quarantined_versions_in_force_refuse_the_replay() {
    let directory = tempfile::tempdir().unwrap();
    history(directory.path());
    let reopen = |pins: &FakePins, on_quarantine| {
        open_with(directory.path(), roomy(), pins, on_quarantine).map(|(journal, report)| {
            let track = journal.rollouts().track(&helper_id(), VLLM);
            let running = journal.runners().running_on(v2().id());
            journal.close().unwrap();
            (report, track, running)
        })
    };
    let mut unknown = FakePins::default();
    unknown.refuse(&v1(), PinRefusal::NotPublished);
    assert_eq!(
        reopen(&unknown, OnQuarantine::Refuse).err(),
        Some(JournalError::Replay(ReplayRefusal::UnknownHelper {
            pin: v1().id(),
            refusal: PinRefusal::NotPublished
        }))
    );
    let mut quarantined = FakePins::default();
    quarantined.refuse(
        &v2(),
        PinRefusal::Quarantined {
            reason: IntegrityFailure::MissingData,
        },
    );
    assert_eq!(
        reopen(&quarantined, OnQuarantine::Refuse).err(),
        Some(JournalError::Replay(ReplayRefusal::QuarantinedHelper {
            pin: v2().id(),
            reason: IntegrityFailure::MissingData
        }))
    );
    // The owner's decision: withdraw it. The candidate goes, the runner on it stays
    // listed for a restart, and the withdrawal is recorded.
    let (report, track, running) =
        reopen(&quarantined, OnQuarantine::Withdraw(withdrawal())).unwrap();
    assert_eq!(report.withdrawn, vec![v2().id()]);
    let track = track.unwrap();
    assert_eq!(track.candidate, None);
    assert_eq!(track.failed, vec![v2().id()]);
    assert_eq!(running, vec![instance("env-b")]);
    // From now on the stream itself says so.
    let (report, _, _) = reopen(&quarantined, OnQuarantine::Refuse).unwrap();
    assert!(report.withdrawn.is_empty());
}

#[test]
fn a_failed_version_quarantined_later_does_not_refuse_the_replay() {
    let directory = tempfile::tempdir().unwrap();
    history(directory.path());
    let (mut journal, _) = open(directory.path());
    journal
        .record(
            fail(&v2(), RolloutStage::OptIn),
            component(&v2()),
            &FakePins::default(),
        )
        .unwrap();
    journal.close().unwrap();
    // v2 is never offered again; env-b still runs it and stays listed for a restart.
    let mut quarantined = FakePins::default();
    quarantined.refuse(
        &v2(),
        PinRefusal::Quarantined {
            reason: IntegrityFailure::MissingData,
        },
    );
    let (journal, report) = open_with(
        directory.path(),
        roomy(),
        &quarantined,
        OnQuarantine::Refuse,
    )
    .unwrap();
    assert!(report.withdrawn.is_empty());
    assert_eq!(
        journal.runners().running_on(v2().id()),
        vec![instance("env-b")]
    );
}

#[test]
fn a_revoked_helper_key_fails_the_replay_closed_until_the_owner_withdraws() {
    let mut fixture = Fixture::new();
    let bytes = encoded(version(1, 0, 0), HelperAbi::new(1, 0));
    let pin = fixture.admit(&bytes, Some(1)).unwrap().pin;
    // The bundle's signed component, checked as the run's build records it, is the pin's.
    let signed = SignedComponent::check(
        &fixture.roots.current(),
        HELPER_CLASS,
        &publisher(1),
        bundle_statement(&publisher(1), &bytes),
        &signature(1, &bytes),
        at("2026-06-01T00:00:00Z"),
    );
    assert_eq!(check_component(&signed, &pin, true), Ok(()));
    let directory = tempfile::tempdir().unwrap();
    {
        let catalog = fixture.admission.admissibility(&fixture.catalog);
        let (mut journal, _) =
            open_with(directory.path(), roomy(), &catalog, OnQuarantine::Refuse).unwrap();
        journal.propose(pin.clone(), VLLM, &catalog).unwrap();
        journal
            .record(pass(&pin, RolloutStage::Shadow), signed.clone(), &catalog)
            .unwrap();
        journal.close().unwrap();
    }
    fixture.revoke_key_one();
    let catalog = fixture.admission.admissibility(&fixture.catalog);
    assert!(matches!(
        open_with(directory.path(), roomy(), &catalog, OnQuarantine::Refuse),
        Err(JournalError::Replay(ReplayRefusal::QuarantinedHelper { pin: refused, .. })) if refused == pin.id()
    ));
    let (journal, report) = open_with(
        directory.path(),
        roomy(),
        &catalog,
        OnQuarantine::Withdraw(withdrawal()),
    )
    .unwrap();
    assert_eq!(report.withdrawn, vec![pin.id()]);
    assert_eq!(
        journal
            .rollouts()
            .track(&helper_id(), VLLM)
            .unwrap()
            .candidate,
        None
    );
    journal.close().unwrap();
    assert!(open_with(directory.path(), roomy(), &catalog, OnQuarantine::Refuse).is_ok());
}

#[test]
fn trials_name_their_evidence_by_identity() {
    let directory = tempfile::tempdir().unwrap();
    let (mut journal, _) = open(directory.path());
    journal.propose(v1(), VLLM, &FakePins::default()).unwrap();
    // The component of another bundle is refused for any trial.
    assert!(matches!(
        journal.record(
            pass(&v1(), RolloutStage::Shadow),
            component(&v2()),
            &FakePins::default()
        ),
        Err(JournalError::Evidence(EvidenceRefusal::Bundle {
            mismatch: BundleMismatch::Statement { .. },
            ..
        }))
    ));
    // A signature no trust-root key vouches for backs no pass, but never holds a failure
    // up.
    let statement = pin_statement(&v1());
    let unverified = SignedComponent::check(
        &roots_from(root_keys()),
        HELPER_CLASS,
        &publisher(1),
        statement,
        &[0u8; 64],
        at("2026-06-01T00:00:00Z"),
    );
    assert!(matches!(
        journal.record(
            pass(&v1(), RolloutStage::Shadow),
            unverified.clone(),
            &FakePins::default()
        ),
        Err(JournalError::Evidence(EvidenceRefusal::Bundle {
            mismatch: BundleMismatch::NotVerified { .. },
            ..
        }))
    ));
    assert_eq!(journal.log().last().map(EventSequence::get), Some(1));
    record_pass(&mut journal, &v1(), RolloutStage::Shadow);
    // The record names the run records and the component, never a provenance.
    let records = stored(journal.log());
    let JournalRecord::Trial { evidence, .. } = records.last().unwrap() else {
        panic!("not a trial: {records:?}");
    };
    assert_eq!(
        evidence,
        &RecordedEvidence {
            records: measured().comparable_evidence().unwrap(),
            measured: true,
            component: component(&v1()),
        }
    );
    let text = serde_json::to_string(&records).unwrap();
    assert!(!text.contains("provenance") && !text.contains("yougori_measured"));
    journal
        .record(
            fail(&v1(), RolloutStage::Shadow),
            unverified,
            &FakePins::default(),
        )
        .unwrap();
    assert_eq!(
        journal.rollouts().track(&helper_id(), VLLM).unwrap().failed,
        vec![v1().id()]
    );
}

#[test]
fn a_promotion_needs_the_reference_to_its_recorded_measured_pass() {
    let directory = tempfile::tempdir().unwrap();
    let (mut journal, _) = open(directory.path());
    let helper = helper_id();
    journal.propose(v1(), VLLM, &FakePins::default()).unwrap();
    let refused = |journal: &mut RolloutJournal, reference: &EvidenceReference| {
        let last = journal.log().last();
        let refusal = journal
            .promote(&helper, VLLM, reference, &FakePins::default())
            .unwrap_err();
        assert_eq!(
            journal.log().last(),
            last,
            "a refused promotion writes nothing"
        );
        refusal
    };
    // Missing: nothing recorded yet.
    assert_eq!(
        refused(&mut journal, &reference(&v1())),
        JournalError::Evidence(EvidenceRefusal::Missing {
            pin: v1().id(),
            stage: RolloutStage::Shadow
        })
    );
    // A fake-substrate pass is recorded and still leaves the evidence missing.
    journal
        .record(
            trial(
                &v1(),
                &vllm(),
                RolloutStage::Shadow,
                TrialVerdict::Passed,
                simulated(),
            ),
            component(&v1()),
            &FakePins::default(),
        )
        .unwrap();
    assert!(matches!(
        refused(&mut journal, &reference(&v1())),
        JournalError::Evidence(EvidenceRefusal::Missing { .. })
    ));
    record_pass(&mut journal, &v1(), RolloutStage::Shadow);
    let fake = EvidenceReference::of(&simulated(), component(&v1())).unwrap();
    assert_eq!(
        refused(&mut journal, &fake),
        JournalError::Evidence(EvidenceRefusal::NotMeasured)
    );
    let elsewhere = EvidenceReference::of(&measured_elsewhere(), component(&v1())).unwrap();
    assert!(matches!(
        refused(&mut journal, &elsewhere),
        JournalError::Evidence(EvidenceRefusal::Mismatch { .. })
    ));
    // The right records with another version's bundle.
    let other_bundle = EvidenceReference::of(&measured(), component(&v2())).unwrap();
    assert!(matches!(
        refused(&mut journal, &other_bundle),
        JournalError::Evidence(EvidenceRefusal::Bundle { .. })
    ));
    journal.close().unwrap();

    // The pass survives a restart as an identity; the promotion takes the reference built
    // again from the same run records.
    let (mut journal, _) = open(directory.path());
    assert_eq!(
        promote(&mut journal, &v1()),
        Promotion {
            pin: v1().id(),
            from: RolloutStage::Shadow,
            to: RolloutStage::OptIn
        }
    );
    let records = stored(journal.log());
    assert!(matches!(
        records.last(),
        Some(JournalRecord::Promoted { evidence, .. }) if evidence.records == measured().comparable_evidence().unwrap()
    ));
}

#[test]
fn source_injection_goes_only_on_the_reference_to_the_defaults_proof() {
    let directory = tempfile::tempdir().unwrap();
    let (mut journal, _) = open(directory.path());
    make_default_in(&mut journal, &v1());
    let removal = || SourceInjectionRemoval {
        decided_by: label("release-owner"),
        reason: label("bundle-proven"),
    };
    assert_eq!(
        journal.remove_source_injection(&helper_id(), VLLM, removal(), &reference(&v1())),
        Err(JournalError::Evidence(EvidenceRefusal::Missing {
            pin: v1().id(),
            stage: RolloutStage::BackendDefault
        }))
    );
    record_pass(&mut journal, &v1(), RolloutStage::BackendDefault);
    let elsewhere = EvidenceReference::of(&measured_elsewhere(), component(&v1())).unwrap();
    assert!(matches!(
        journal.remove_source_injection(&helper_id(), VLLM, removal(), &elsewhere),
        Err(JournalError::Evidence(EvidenceRefusal::Mismatch { .. }))
    ));
    journal.close().unwrap();
    let (mut journal, _) = open(directory.path());
    journal
        .remove_source_injection(&helper_id(), VLLM, removal(), &reference(&v1()))
        .unwrap();
    journal.close().unwrap();
    let (journal, _) = open(directory.path());
    assert!(matches!(
        journal
            .rollouts()
            .track(&helper_id(), VLLM)
            .unwrap()
            .source_injection,
        SourceInjection::Removed { replacement, .. } if replacement == v1().id()
    ));
}

#[test]
fn records_are_read_strictly() {
    let record = JournalRecord::Trial {
        track: position(2, version(1, 0, 0)),
        pin: v1().id(),
        runner: vllm(),
        stage: RolloutStage::Shadow,
        verdict: RecordedVerdict::Passed {},
        evidence: recorded(&v1(), &measured()),
        outcome: RecordedOutcome::Recorded {},
    };
    let value = serde_json::to_value(&record).unwrap();
    assert_eq!(
        serde_json::from_value::<JournalRecord>(value.clone()).unwrap(),
        record
    );
    for path in [
        &["trial"][..],
        &["trial", "track"],
        &["trial", "verdict"],
        &["trial", "outcome"],
        &["trial", "evidence"],
    ] {
        let mut extra = value.clone();
        let mut at = &mut extra;
        for key in path {
            at = &mut at[*key];
        }
        at["provenance"] = serde_json::json!({ "kind": "yougori_measured" });
        assert!(
            serde_json::from_value::<JournalRecord>(extra).is_err(),
            "an unknown field under {path:?} was accepted"
        );
    }
}
