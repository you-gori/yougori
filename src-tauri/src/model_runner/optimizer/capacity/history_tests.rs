//! The host ledger's history export (S03, `crate::ledger_history`) on the engine's own
//! accounting: staged under the ledger lock, written to the journal with no ledger or
//! history lock held, nothing written without a configured directory.
use super::*;
use crate::foundation::events::LogConfig;
use crate::foundation::ledger::{HistoryEntry, HistoryItem, JournalRecord};
use crate::ledger_history::{
    respond, FlushOutcome, HistoryExporter, HistorySetting, HISTORY_DIR_SETTING, MAX_STAGED,
};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Instant;

const GIB: u64 = 1024 * 1024 * 1024;

fn bounds() -> LogConfig {
    LogConfig {
        max_entries: 1 << 16,
        max_bytes: 1 << 24,
        segment_entries: 1 << 12,
        segment_bytes: 1 << 20,
    }
}

fn journal_in(directory: &Path, bounds: LogConfig) -> Arc<HistoryExporter> {
    Arc::new(HistoryExporter::new(HistorySetting::Journal {
        directory: directory.to_path_buf(),
        bounds,
    }))
}

/// The engine's accounting from `test_accounting`, exporting through `export`.
fn accounting(export: &Arc<HistoryExporter>) -> (Snapshot, Accounting<SystemClock>) {
    let (sample, account) = test_accounting();
    (sample, account.exporting_to(Arc::clone(export)))
}

/// Admits a model `rounds` times; each admission after the first settles the previous
/// model's parent and child, which close.
fn admit(account: &mut Accounting<SystemClock>, sample: &Snapshot, rounds: usize) {
    for round in 0..rounds {
        let mut fresh = sample.clone();
        fresh.observed = Instant::now();
        account
            .settle_and_reserve(&fresh, &format!("model-{round}"), Some(GIB))
            .unwrap();
    }
}

/// The history's totals, locked in the order the adapter uses.
fn collected(account: &Accounting<SystemClock>) -> u64 {
    let _ledger = account.ledger.lock().unwrap();
    account.history.lock().unwrap().totals().collected
}

/// Another client of the shared ledger reserves and cancels `count` times.
fn other_client_closes(account: &Accounting<SystemClock>, sample: &Snapshot, count: usize) {
    let key = ResourceKey::vram(sample.device);
    let mut ledger = account.ledger.lock().unwrap();
    for _ in 0..count {
        let provenance = Provenance {
            requester: Requester::Transfer,
            execution: ExecutionId::generate(),
            operation: OperationId::generate(),
            tenant: account.tenant.clone(),
            purpose: CostPurpose::Transfer,
            retry_number: 0,
        };
        let Admission::Granted(other) = ledger
            .reserve(ReservationRequest::new(
                provenance,
                Priority::Foreground,
                Amounts::new().with(key, 256 * 1024 * 1024),
            ))
            .unwrap()
        else {
            panic!("the other client fits beside the model")
        };
        ledger.cancel(other).unwrap();
    }
}

/// The journal's entries as (owner incarnation, history sequence).
fn numbered(export: &HistoryExporter) -> Vec<(u64, u64)> {
    export
        .journal_records()
        .into_iter()
        .filter_map(|(owner, record)| match record {
            JournalRecord::Entry(entry) => Some((owner, entry.sequence)),
            JournalRecord::Missing { .. } => None,
        })
        .collect()
}

#[test]
fn without_a_directory_history_stays_in_the_window_and_nothing_is_written() {
    let (sample, mut account) = test_accounting();
    assert!(!account.export.is_configured());
    admit(&mut account, &sample, 3);
    let total = collected(&account);
    assert!(
        total >= 4,
        "two settled models close a parent and a child each"
    );
    assert_eq!(account.export.flush(), FlushOutcome::NotConfigured);
    assert!(account.export.journal_records().is_empty());
    assert_eq!(account.export.staged(), 0);
    {
        let _ledger = account.ledger.lock().unwrap();
        let history = account.history.lock().unwrap();
        assert_eq!(u64::try_from(history.pending_export()).unwrap(), total);
        assert_eq!(history.exported_through(), 0);
    }
    let status = respond(&account.export, None).unwrap();
    assert_eq!(status["state"], "not_configured");
    assert!(status["destination"]["remedy"]
        .as_str()
        .unwrap()
        .contains(HISTORY_DIR_SETTING));
    assert!(status["journal"].is_null());
    assert_eq!(status["window"]["pending_export"], total);
    assert_eq!(status["window"]["collections"], 3);
    assert_eq!(status["exports"]["flushes"], 0);
}

#[test]
fn configured_history_reaches_the_journal_once_across_a_restart() {
    let directory = tempfile::tempdir().unwrap();
    let place = directory.path().join("history");
    let export = journal_in(&place, bounds());
    let (sample, mut account) = accounting(&export);
    admit(&mut account, &sample, 3);
    let first_run = collected(&account);
    // Staged in memory under the ledger lock; nothing touches storage until the export.
    assert_eq!(u64::try_from(export.staged()).unwrap(), first_run);
    assert!(!place.exists());
    assert_eq!(
        export.flush(),
        FlushOutcome::Exported {
            entries: usize::try_from(first_run).unwrap()
        }
    );
    assert_eq!(export.flush(), FlushOutcome::Exported { entries: 0 });
    let status = respond(&export, None).unwrap();
    assert_eq!(status["state"], "configured");
    assert_eq!(status["journal"]["state"], "open");
    assert_eq!(status["journal"]["opened"]["takeover"], "fresh");
    assert_eq!(status["journal"]["through"], first_run);
    assert_eq!(status["journal"]["totals"]["appended"], first_run);
    assert_eq!(status["window"]["pending_export"], 0);
    assert_eq!(status["window"]["exported_through"], first_run);
    assert_eq!(status["window"]["totals"]["lost_unexported"], 0);
    assert_eq!(status["staged"]["entries"], 0);
    assert!(status["exports"]["last_failure"].is_null());
    let first = status["journal"]["incarnation"].as_u64().unwrap();
    // The engine stops: its accounting and export go, and the stream is released.
    drop(account);
    drop(export);

    // The next run numbers its history from 1 again, under the next owner incarnation.
    let export = journal_in(&place, bounds());
    let (sample, mut account) = accounting(&export);
    admit(&mut account, &sample, 2);
    export.flush();
    admit(&mut account, &sample, 2);
    export.flush();
    let second_run = collected(&account);
    let status = respond(&export, None).unwrap();
    assert_eq!(status["journal"]["opened"]["takeover"], "released");
    assert_eq!(status["journal"]["incarnation"], first + 1);
    let expected: Vec<(u64, u64)> = (1..=first_run)
        .map(|sequence| (first, sequence))
        .chain((1..=second_run).map(|sequence| (first + 1, sequence)))
        .collect();
    assert_eq!(numbered(&export), expected, "every entry once, in order");
    let records = export.journal_records();
    assert!(records
        .iter()
        .all(|(_, record)| matches!(record, JournalRecord::Entry(_))));
    let closed = records
        .iter()
        .filter(|(_, record)| {
            matches!(
                record,
                JournalRecord::Entry(HistoryEntry {
                    item: HistoryItem::Closed { .. },
                    ..
                })
            )
        })
        .count();
    // Five settled models, two in the first run and three in the next: a parent and a
    // child each.
    assert_eq!(closed, 10);
    assert_eq!(first_run + second_run, 10);
}

#[test]
fn a_failing_destination_is_reported_and_admission_continues() {
    let directory = tempfile::tempdir().unwrap();
    // A journal that cannot be opened: its directory would lie inside a file.
    let blocker = directory.path().join("blocker");
    std::fs::write(&blocker, b"not a directory").unwrap();
    let export = journal_in(&blocker.join("history"), bounds());
    let (sample, account) = accounting(&export);
    let host = Mutex::new(None);
    let mut first = Some(account);
    for round in 0..3 {
        let mut fresh = sample.clone();
        fresh.observed = Instant::now();
        // The engine's path: settle under the host lock, then export once it is released
        // (at once here, with no runtime).
        settle_on_host(
            &host,
            || first.take().unwrap(),
            |account| account.settle_and_reserve(&fresh, &format!("model-{round}"), Some(GIB)),
        )
        .unwrap();
    }
    {
        let host = host.lock().unwrap();
        let account = host.as_ref().unwrap();
        assert_eq!(
            account.ledger.lock().unwrap().open_reservations().count(),
            2
        );
        assert_eq!(u64::try_from(export.staged()).unwrap(), collected(account));
    }
    let status = respond(&export, None).unwrap();
    assert_eq!(status["journal"]["state"], "not_open");
    assert!(
        status["journal"]["next_attempt_in_seconds"]
            .as_u64()
            .unwrap()
            > 0
    );
    // The first export tried to open the journal; the next ones wait for the interval.
    assert_eq!(status["exports"]["failures"], 1);
    assert!(status["exports"]["last_failure"]["reason"]
        .as_str()
        .unwrap()
        .contains("could not be opened"));
    // The owner's export tries at once, and its failure is reported and counted too.
    let answer = respond(&export, Some("export")).unwrap();
    assert_eq!(answer["export"]["outcome"], "not_open");
    assert_eq!(answer["status"]["exports"]["failures"], 2);

    // A journal that opens but refuses every append: no entry fits its segments.
    let tiny = LogConfig {
        max_entries: 64,
        max_bytes: 64,
        segment_entries: 8,
        segment_bytes: 16,
    };
    let refusing = journal_in(&directory.path().join("tiny"), tiny);
    let (sample, mut account) = accounting(&refusing);
    admit(&mut account, &sample, 3);
    let waiting = refusing.staged();
    assert!(waiting >= 4);
    let FlushOutcome::Refused { entries, reason } = refusing.flush() else {
        panic!("the journal refuses the batch");
    };
    assert_eq!(entries, 0);
    assert!(reason.contains("a segment holds at most 16"), "{reason}");
    admit(&mut account, &sample, 1);
    assert_eq!(
        account.ledger.lock().unwrap().open_reservations().count(),
        2
    );
    assert!(
        refusing.staged() > waiting,
        "the entries wait for the next export"
    );
    // Staging is bounded: what does not fit stays in the window, which counts its losses.
    other_client_closes(&account, &sample, MAX_STAGED + 4);
    admit(&mut account, &sample, 1);
    assert!(refusing.staged() <= MAX_STAGED);
    let status = respond(&refusing, None).unwrap();
    assert_eq!(status["journal"]["state"], "open");
    assert!(
        status["journal"]["totals"]["refused_batches"]
            .as_u64()
            .unwrap()
            >= 1
    );
    assert_eq!(status["journal"]["through"], 0);
    assert!(status["staged"]["refused_batches"].as_u64().unwrap() >= 1);
    assert!(
        status["window"]["totals"]["lost_unexported"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(
        status["window"]["held"].as_u64().unwrap()
            <= u64::try_from(HistoryLimits::DEFAULT.max_entries()).unwrap()
    );
    assert!(status["exports"]["last_failure"]["reason"]
        .as_str()
        .unwrap()
        .contains("refused a batch"));
}

#[test]
fn admission_never_waits_for_the_journal_and_racing_exports_write_each_entry_once() {
    let directory = tempfile::tempdir().unwrap();
    let export = journal_in(directory.path(), bounds());
    let (sample, account) = accounting(&export);
    let account = Arc::new(Mutex::new(account));
    // An export holds the journal lock across its file I/O. Admission takes the ledger,
    // history and staging locks only, so it completes while the journal lock is held.
    let held = export.hold_journal();
    let (done, finished) = mpsc::channel();
    let worker = {
        let account = Arc::clone(&account);
        let sample = sample.clone();
        std::thread::spawn(move || {
            admit(&mut account.lock().unwrap(), &sample, 3);
            done.send(()).unwrap();
        })
    };
    finished
        .recv_timeout(Duration::from_secs(30))
        .expect("admission waited for the journal lock");
    worker.join().unwrap();
    assert!(export.staged() > 0);
    drop(held);

    // Exports race admissions: every entry reaches the journal once, in order.
    let stop = Arc::new(AtomicBool::new(false));
    let exporter = {
        let export = Arc::clone(&export);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                export.flush();
                std::thread::yield_now();
            }
        })
    };
    for _ in 0..10 {
        admit(&mut account.lock().unwrap(), &sample, 2);
    }
    stop.store(true, Ordering::SeqCst);
    exporter.join().unwrap();
    export.flush();
    let total = collected(&account.lock().unwrap());
    let sequences: Vec<u64> = numbered(&export)
        .into_iter()
        .map(|(_, sequence)| sequence)
        .collect();
    assert_eq!(sequences, (1..=total).collect::<Vec<_>>());
    assert_eq!(export.staged(), 0);
}

// ---------------------------------------------------------------- scheduling (R1)

/// Waits until no background worker runs, or fails after thirty seconds.
async fn worker_exits(export: &HistoryExporter) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while export.schedule().worker_active {
        assert!(Instant::now() < deadline, "the export worker did not exit");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Admits `rounds` models through the production path under the runtime, each admission
/// on a blocking thread with a bound on how long it may take.
async fn admit_under_runtime(
    host: &Arc<Mutex<Option<Accounting<SystemClock>>>>,
    sample: &Snapshot,
    rounds: usize,
) {
    for round in 0..rounds {
        let mut fresh = sample.clone();
        fresh.observed = Instant::now();
        let host = Arc::clone(host);
        let id = format!("model-{round}");
        let admission = tokio::task::spawn_blocking(move || {
            settle_on_host(
                &host,
                || -> Accounting<SystemClock> { unreachable!("the accounting exists") },
                |account| account.settle_and_reserve(&fresh, &id, Some(GIB)),
            )
        });
        tokio::time::timeout(Duration::from_secs(30), admission)
            .await
            .expect("admission waited for the journal")
            .unwrap()
            .unwrap();
    }
}

/// Review finding R1: with the journal writer stalled, admissions under the engine's
/// runtime start exactly one export worker, coalesce every later request into it, and
/// keep completing; the status answers without waiting and says an export is in
/// progress. Once the writer resumes, that worker writes every entry once, in order, and
/// serves the requests that arrived while it was stalled before it exits.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stalled_journal_holds_one_export_worker_and_admission_continues() {
    let directory = tempfile::tempdir().unwrap();
    let export = journal_in(directory.path(), bounds());
    let (sample, account) = accounting(&export);
    let host: Arc<Mutex<Option<Accounting<SystemClock>>>> = Arc::new(Mutex::new(Some(account)));
    // Open the journal first, so what stalls below is a writer, not the first open.
    assert_eq!(export.flush(), FlushOutcome::Exported { entries: 0 });
    let held = export.hold_journal();

    let rounds = 12;
    let started = Instant::now();
    admit_under_runtime(&host, &sample, rounds).await;
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "admission waited for the stalled journal"
    );
    // The worker is stalled in its write; the later requests wait for it, not for a
    // thread each.
    let deadline = Instant::now() + Duration::from_secs(30);
    while export.schedule().worker_runs == 0 {
        assert!(
            Instant::now() < deadline,
            "the worker never started its write"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let schedule = export.schedule();
    assert_eq!(schedule.workers_started, 1, "{schedule:?}");
    assert_eq!(schedule.requests, rounds as u64, "{schedule:?}");
    assert_eq!(schedule.coalesced, rounds as u64 - 1, "{schedule:?}");
    assert!(schedule.worker_active, "{schedule:?}");
    assert!(export.staged() > 0);
    let status = respond(&export, None).unwrap();
    assert_eq!(status["exports"]["in_progress"], true, "{status}");
    assert_eq!(status["journal"]["state"], "open", "{status}");
    assert_eq!(status["journal"]["in_progress"], true, "{status}");
    assert_eq!(status["exports"]["scheduling"]["workers_started"], 1);
    assert_eq!(
        status["exports"]["scheduling"]["coalesced"],
        rounds as u64 - 1
    );

    drop(held);
    worker_exits(&export).await;
    let schedule = export.schedule();
    assert_eq!(schedule.workers_started, 1, "{schedule:?}");
    assert!(
        schedule.worker_runs >= 1,
        "the one worker wrote the coalesced requests: {schedule:?}"
    );
    assert!(!schedule.pending, "{schedule:?}");
    let total = {
        let host = host.lock().unwrap();
        collected(host.as_ref().unwrap())
    };
    let sequences: Vec<u64> = numbered(&export)
        .into_iter()
        .map(|(_, sequence)| sequence)
        .collect();
    assert_eq!(sequences, (1..=total).collect::<Vec<_>>());
    assert_eq!(export.staged(), 0);
    let status = respond(&export, None).unwrap();
    assert_eq!(status["exports"]["in_progress"], false);
    assert_eq!(status["journal"]["through"], total);

    // Requests after the worker exited start one worker again, not one per request.
    admit_under_runtime(&host, &sample, 3).await;
    worker_exits(&export).await;
    let schedule = export.schedule();
    assert!(
        schedule.workers_started >= 2 && schedule.workers_started <= 4,
        "{schedule:?}"
    );
    assert_eq!(export.staged(), 0);
    let total = {
        let host = host.lock().unwrap();
        collected(host.as_ref().unwrap())
    };
    assert_eq!(numbered(&export).len() as u64, total);
}

/// Review finding R1: a journal that cannot be opened fails the worker's export, which is
/// reported and counted, while admissions under the runtime keep completing and the
/// entries wait in staging for a later export.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unopenable_journal_is_reported_while_admission_continues_under_the_runtime() {
    let directory = tempfile::tempdir().unwrap();
    // A journal that cannot be opened: its directory would lie inside a file.
    let blocker = directory.path().join("blocker");
    std::fs::write(&blocker, b"not a directory").unwrap();
    let export = journal_in(&blocker.join("history"), bounds());
    let (sample, account) = accounting(&export);
    let host: Arc<Mutex<Option<Accounting<SystemClock>>>> = Arc::new(Mutex::new(Some(account)));
    admit_under_runtime(&host, &sample, 3).await;
    worker_exits(&export).await;
    let status = respond(&export, None).unwrap();
    assert_eq!(status["journal"]["state"], "not_open", "{status}");
    assert!(
        status["exports"]["failures"].as_u64().unwrap() >= 1,
        "{status}"
    );
    assert!(status["exports"]["last_failure"]["reason"]
        .as_str()
        .unwrap()
        .contains("could not be opened"));
    assert_eq!(status["exports"]["in_progress"], false);
    assert!(
        status["exports"]["scheduling"]["workers_started"]
            .as_u64()
            .unwrap()
            >= 1
    );
    assert!(!export.schedule().worker_active);
    let total = {
        let host = host.lock().unwrap();
        collected(host.as_ref().unwrap())
    };
    assert_eq!(u64::try_from(export.staged()).unwrap(), total);
    assert!(numbered(&export).is_empty());
}
