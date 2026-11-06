//! The history owner takes shared-extent and transition-peak records with the rest of the
//! ledger's history (S03): numbered in the same bounded window, exported in order to the
//! durable journal and read back strictly with each holder's cost; records the ledger
//! dropped before they were collected become an explicit entry and count as lost; and the
//! window bounds and counts them like any other entry.

use super::*;
use crate::foundation::events::{DurableStreamId, LogConfig, LogEntry, ProducerId, ReadItem};

fn key(name: &[u8]) -> ExtentKey {
    ExtentKey::new(digest("yougori/test/extent/v1", &[name]))
}

/// Shares a 4 GB extent between two holders of `execution`, `step` apart, and lets both
/// leave, `step` apart, so the extent closes; returns the extent's reservation.
fn share_and_close(
    ledger: &mut Ledger<&ManualClock>,
    clock: &ManualClock,
    execution: &str,
    step: Duration,
) -> ReservationId {
    let first = granted(ledger.reserve(on_gpu(execution, Priority::Foreground, GB)));
    let second = granted(ledger.reserve(on_gpu(execution, Priority::Foreground, GB)));
    let extent_key = key(execution.as_bytes());
    let extent = ledger
        .share_extent(
            extent_key,
            on_gpu(execution, Priority::Foreground, 4 * GB),
            first,
        )
        .unwrap()
        .reservation();
    clock.advance(step);
    ledger.join_extent(extent_key, second).unwrap();
    clock.advance(step);
    ledger.leave_extent(extent_key, first).unwrap();
    clock.advance(step);
    assert!(matches!(
        ledger.leave_extent(extent_key, second),
        Ok(ShareRelease::Released { .. })
    ));
    ledger.cancel(first).unwrap();
    ledger.cancel(second).unwrap();
    extent
}

/// A 4 GB reservation whose workload is created, so it is never reclaimed as unused.
fn created_steady(ledger: &mut Ledger<&ManualClock>) -> ReservationId {
    let steady = granted(ledger.reserve(on_gpu("exe-steady", Priority::Foreground, 4 * GB)));
    ledger.begin_create(steady).unwrap();
    steady
}

/// Opens a 1 GB transition peak on `steady` and completes it a second later, as the host
/// observed.
fn peak_and_complete(
    ledger: &mut Ledger<&ManualClock>,
    clock: &ManualClock,
    steady: ReservationId,
) {
    ledger
        .begin_transition_peak(steady, Amounts::new().vram_bytes(gpu(0), GB), MINUTE)
        .unwrap();
    clock.advance(SECOND);
    ledger
        .end_transition_peak(steady, PeakEnd::Completed, SourceClass::HostProbe)
        .unwrap();
}

fn kind(item: &HistoryItem) -> &'static str {
    match item {
        HistoryItem::Closed { .. } => "closed",
        HistoryItem::ExtentClosed { .. } => "extent",
        HistoryItem::PeakEnded { .. } => "peak",
        HistoryItem::RecordsDropped { .. } => "dropped",
        HistoryItem::QueueGranted { .. }
        | HistoryItem::QueueRefused { .. }
        | HistoryItem::Reclaimed { .. } => "event",
    }
}

#[test]
fn extent_and_peak_records_are_collected_numbered_and_exported_with_their_costs() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let extent = share_and_close(&mut ledger, &clock, "exe-shared", 5 * SECOND);
    let steady = created_steady(&mut ledger);
    peak_and_complete(&mut ledger, &clock, steady);
    assert_eq!(ledger.extent_records().len(), 1);
    assert_eq!(ledger.peak_records().len(), 1);

    let mut history = LedgerHistory::new(HistoryLimits::DEFAULT);
    let added = history.collect(&mut ledger);
    // The ledger keeps none of them now.
    assert!(ledger.extent_records().is_empty());
    assert!(ledger.peak_records().is_empty());
    assert!(ledger.closed_records().is_empty());
    let kinds: Vec<&str> = history.entries().map(|entry| kind(&entry.item)).collect();
    assert_eq!(kinds, vec!["closed", "closed", "closed", "extent", "peak"]);
    assert_eq!(added, kinds.len());
    let sequences: Vec<u64> = history.entries().map(|entry| entry.sequence).collect();
    assert_eq!(sequences, vec![1, 2, 3, 4, 5]);

    // Each holder's cost adds up to the extent's own integral, without double counting.
    let record = history.extent_records().next().unwrap();
    assert_eq!(record.reservation, extent);
    assert_eq!(record.costs.len(), 2);
    let closed = history
        .records()
        .find(|closed| closed.id() == extent)
        .unwrap();
    let charged: u128 = record
        .costs
        .iter()
        .map(|cost| cost.amount_nanoseconds)
        .sum();
    assert_eq!(
        charged,
        closed.held_amount_nanoseconds(vram(0), record.closed_at)
    );
    assert!(charged > u128::from(u64::MAX));
    let peak = history.peak_records().next().unwrap();
    assert_eq!(
        (peak.steady, peak.outcome),
        (steady, PeakOutcome::Completed)
    );

    // The durable journal takes them in order and gives them back whole.
    let directory = tempfile::tempdir().unwrap();
    let (mut journal, _) = HistoryJournal::open(
        directory.path(),
        DurableStreamId::new("ledger.history").unwrap(),
        ProducerId::new("ledger.history").unwrap(),
        LogConfig {
            max_entries: 64,
            max_bytes: 1 << 24,
            segment_entries: 64,
            segment_bytes: 1 << 20,
        },
    )
    .unwrap();
    assert_eq!(journal.export(&mut history), Ok(5));
    let log = journal.log();
    let read: Vec<HistoryEntry> = log
        .read(&log.start(), 64)
        .unwrap()
        .items
        .into_iter()
        .filter_map(|item| match item {
            ReadItem::Entry {
                entry: LogEntry::Record(JournalRecord::Entry(entry)),
                ..
            } => Some(entry),
            _ => None,
        })
        .collect();
    let kept: Vec<HistoryEntry> = history.entries().cloned().collect();
    assert_eq!(read, kept);
}

#[test]
fn extent_and_peak_records_read_back_strictly() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    share_and_close(&mut ledger, &clock, "exe-strict", SECOND);
    let steady = created_steady(&mut ledger);
    peak_and_complete(&mut ledger, &clock, steady);
    let mut history = LedgerHistory::new(HistoryLimits::DEFAULT);
    history.collect(&mut ledger);
    for entry in history.entries() {
        let json = serde_json::to_value(entry).unwrap();
        let back: HistoryEntry = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(&back, entry);
    }
    let extent = history
        .entries()
        .find(|entry| kind(&entry.item) == "extent")
        .unwrap();
    let mut json = serde_json::to_value(extent).unwrap();
    json["item"]["extent_closed"]["record"]["spans"][0]["extra"] = serde_json::json!(1);
    assert!(serde_json::from_value::<HistoryEntry>(json).is_err());
    let peak = history
        .entries()
        .find(|entry| kind(&entry.item) == "peak")
        .unwrap();
    let mut json = serde_json::to_value(peak).unwrap();
    json["item"]["peak_ended"]["record"]["outcome"] = serde_json::json!("abandoned");
    assert!(serde_json::from_value::<HistoryEntry>(json).is_err());
}

#[test]
fn records_the_ledger_dropped_before_collection_become_an_entry_and_count_as_lost() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let mut history = LedgerHistory::new(HistoryLimits::new(8_192, 4).unwrap());
    let steady = created_steady(&mut ledger);
    for index in 0..MAX_EXTENT_RECORDS + 2 {
        share_and_close(&mut ledger, &clock, &format!("exe-{index}"), Duration::ZERO);
    }
    for _ in 0..MAX_PEAK_RECORDS + 1 {
        peak_and_complete(&mut ledger, &clock, steady);
    }
    assert_eq!(ledger.extent_records_dropped(), 2);
    assert_eq!(ledger.peak_records_dropped(), 1);

    history.collect(&mut ledger);
    let dropped: Vec<&HistoryItem> = history
        .entries()
        .map(|entry| &entry.item)
        .filter(|item| kind(item) == "dropped")
        .collect();
    assert_eq!(
        dropped,
        vec![&HistoryItem::RecordsDropped {
            extent_records: 2,
            peak_records: 1
        }]
    );
    assert_eq!(history.totals().lost_before_collect, 3);
    assert_eq!(history.extent_records().count(), MAX_EXTENT_RECORDS);
    assert_eq!(history.peak_records().count(), MAX_PEAK_RECORDS);

    // Collecting regularly loses nothing more; a later overflow counts only what is new.
    share_and_close(&mut ledger, &clock, "exe-next", Duration::ZERO);
    history.collect(&mut ledger);
    assert_eq!(history.totals().lost_before_collect, 3);
    for index in 0..MAX_EXTENT_RECORDS + 1 {
        share_and_close(
            &mut ledger,
            &clock,
            &format!("exe-again-{index}"),
            Duration::ZERO,
        );
    }
    history.collect(&mut ledger);
    let last_dropped = history
        .entries()
        .filter(|entry| kind(&entry.item) == "dropped")
        .last()
        .map(|entry| entry.item.clone());
    assert_eq!(
        last_dropped,
        Some(HistoryItem::RecordsDropped {
            extent_records: 1,
            peak_records: 0
        })
    );
    assert_eq!(history.totals().lost_before_collect, 4);
}

#[test]
fn the_window_bounds_extent_and_peak_entries_like_any_other() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let mut history = LedgerHistory::new(HistoryLimits::new(2, 4).unwrap());
    share_and_close(&mut ledger, &clock, "exe-one", Duration::ZERO);
    share_and_close(&mut ledger, &clock, "exe-two", Duration::ZERO);
    let steady = created_steady(&mut ledger);
    peak_and_complete(&mut ledger, &clock, steady);
    // Six closed reservations, two extents and one peak: nine entries, two kept.
    assert_eq!(history.collect(&mut ledger), 9);
    let kinds: Vec<&str> = history.entries().map(|entry| kind(&entry.item)).collect();
    assert_eq!(kinds, vec!["extent", "peak"]);
    assert_eq!(history.totals().lost_unexported, 7);
    assert_eq!(history.totals().collected, 9);
}
