//! The setup scheduler: the times a setup's own work comes round, kept in the setup registry so
//! they survive a restart.
//!
//! This is not the CPU and memory allocator in `scheduler.rs`. It holds one record per scheduled
//! piece of work (today: one volume's backup), each with the moment it is next due, in UTC. A
//! template writes the times in words (`daily 02:00`) and a time zone; `yougori_setup::resource::
//! schedule` turns the two into moments, so the engine, the CLI and the website read one schedule
//! the same way.
//!
//! The policies of plan 9.4:
//!
//! - **Time zone.** Written by the template, read as UTC internally. `local` follows this
//!   computer's own clock, including its daylight-saving changes.
//! - **Daylight saving.** A time the clocks skip runs with the offset in force before the change
//!   (02:30 becomes 03:30); a time the clocks repeat runs once, the first time.
//! - **Missed runs.** `run_once` makes one run as soon as it can, however many were missed;
//!   `skip` waits for the next time.
//! - **Overlap.** `skip` leaves a run out while the previous one is still going; `queue` runs it
//!   once straight after, and never queues more than one.
//! - **Retries.** A failed run is tried again up to the schedule's limit, waiting longer each
//!   time, then waits for its next time.
//!
//! Stopping a setup pauses its schedules; starting it resumes them; removing it deletes them
//! (`Service::sync_schedules`). Nothing starts while the engine is shutting down, and a run in
//! flight is asked to stop.
use super::backups::Backup;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use yougori_setup::resource::{schedule as times, BackupConsistency, BackupMissed, BackupOverlap};

/// How long the loop sleeps at most, so a change to this computer's clock or time zone is
/// noticed without waiting for the next run.
const TICK: Duration = Duration::from_secs(60);
/// How long the first retry waits; each later one waits twice as long, to a quarter of an hour.
const RETRY_BACKOFF: u64 = 30;
const RETRY_BACKOFF_MAX: u64 = 900;
/// A run that has not finished in this long is given up on, so a wedged copy cannot hold the
/// schedule for ever.
const RUN_LIMIT: Duration = Duration::from_secs(6 * 60 * 60);

/// What a schedule runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Work {
    /// A backup of one of the setup's volumes.
    VolumeBackup,
}

/// How the last run went.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Outcome {
    #[default]
    NeverRun,
    Done,
    Failed,
    /// Left out by the overlap or missed-run policy.
    Skipped,
}

impl Outcome {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Outcome::NeverRun => "never_run",
            Outcome::Done => "done",
            Outcome::Failed => "failed",
            Outcome::Skipped => "skipped",
        }
    }
}

/// One scheduled piece of work, as the registry keeps it. Everything here is the setup's own
/// declaration plus what happened; no credential and no path a template chose.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Schedule {
    /// `<setup>/<resource>`.
    pub id: String,
    pub setup: String,
    pub resource: String,
    pub work: Work,
    /// The times as the template wrote them.
    pub schedule: String,
    /// The time zone they are read in.
    pub timezone: String,
    pub keep: u32,
    pub consistency: BackupConsistency,
    pub missed: BackupMissed,
    pub overlap: BackupOverlap,
    pub retries: u32,
    /// The setup's sandbox the volume is read and restored through.
    pub through: String,
    /// Where that sandbox mounts the volume, such as `/data`.
    pub path: String,
    /// Set while the setup is stopped: nothing runs, and the times stay where they are.
    pub paused: bool,
    /// The next moment this is due, in Unix seconds. Saved, so a restart knows what was missed.
    pub next_at: i64,
    pub last_started_at: Option<i64>,
    pub last_finished_at: Option<i64>,
    pub last_outcome: Outcome,
    /// One plain sentence about the last run.
    pub last_detail: String,
    /// Failures in a row, which the retries are counted against.
    pub failures: u32,
    /// The backups kept for this volume, oldest first.
    pub backups: Vec<Backup>,
}

impl Schedule {
    pub(crate) fn key(setup: &str, resource: &str) -> String {
        format!("{setup}/{resource}")
    }

    /// The times and the zone as this module reads them. `None` when the saved text no longer
    /// parses, which only a hand-edited registry can cause: the schedule then simply never runs.
    pub(crate) fn when(&self) -> Option<(times::Times, times::Zone)> {
        Some((self.schedule.parse().ok()?, self.timezone.parse().ok()?))
    }

    /// The schedule in a sentence, for the setup page and the review.
    pub(crate) fn describe(&self) -> String {
        match self.when() {
            Some((when, zone)) => format!("{}, {}", when.describe(), zone.describe()),
            None => format!("{} ({})", self.schedule, self.timezone),
        }
    }
}

/// Seconds east of UTC on this computer at `utc`, with the daylight-saving rules the operating
/// system keeps.
pub(crate) fn local_offset(utc: i64) -> i64 {
    use chrono::Offset;
    let at = chrono::DateTime::from_timestamp(utc, 0).unwrap_or_default();
    i64::from(chrono::Local.offset_from_utc_datetime(&at.naive_utc()).fix().local_minus_utc())
}

use chrono::TimeZone as _;

pub(crate) fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// The first moment after `after` that `schedule` names.
pub(crate) fn next_due(schedule: &Schedule, after: i64) -> Option<i64> {
    let (when, zone) = schedule.when()?;
    Some(times::next_after(&when, &zone, after, &local_offset))
}

/// What a run of a schedule needs from the engine, so the loop can be tested without touching a
/// sandbox or a disk.
pub(crate) trait Runner: Send + Sync {
    /// Does the work the schedule names. The token is cancelled when the engine is stopping.
    fn run<'a>(&'a self, schedule: &'a Schedule, cancel: &'a CancellationToken) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>>;
}

/// What the loop reads and writes. The service implements it over the setup registry.
pub(crate) trait Records: Send + Sync {
    fn schedules(&self) -> Vec<Schedule>;
    /// Changes one schedule in place and saves it. Does nothing if it is no longer there.
    fn change(&self, id: &str, change: &mut dyn FnMut(&mut Schedule));
}

/// The running loop. One per engine.
pub(crate) struct Scheduler {
    records: Arc<dyn Records>,
    runner: Arc<dyn Runner>,
    /// Schedules running right now, and whether one more is queued behind them.
    running: Mutex<HashMap<String, bool>>,
    /// Woken when a schedule changes, so a new one does not wait for the next tick.
    wake: Arc<tokio::sync::Notify>,
    /// How long the first retry waits, in seconds. Only a test shortens it.
    backoff: std::sync::atomic::AtomicU64,
}

impl Scheduler {
    pub(crate) fn new(records: Arc<dyn Records>, runner: Arc<dyn Runner>) -> Arc<Scheduler> {
        Arc::new(Scheduler {
            records,
            runner,
            running: Default::default(),
            wake: Default::default(),
            backoff: std::sync::atomic::AtomicU64::new(RETRY_BACKOFF),
        })
    }

    /// Shortens the wait between retries, so a test of the retry limit does not wait minutes.
    #[cfg(test)]
    pub(crate) fn retry_quickly(&self) {
        self.backoff.store(0, std::sync::atomic::Ordering::SeqCst);
    }

    /// Tells the loop to look again now, after a setup was created, stopped or removed.
    pub(crate) fn changed(&self) {
        self.wake.notify_one();
    }

    /// Whether a run of this schedule is going right now, its record writes included. Deleting
    /// a volume's backups drops the schedule first and then waits for this to be false, so a
    /// copy still being written can't land after the folder is gone.
    pub(crate) fn running_now(&self, id: &str) -> bool {
        self.running.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).contains_key(id)
    }

    /// Takes a backup of one volume now, as its schedule would, without moving its regular times:
    /// the one after it is worked out from now as usual. When it can't, says why: the setup is
    /// stopped (its backups pause with it), or a backup of that volume is being taken right now.
    pub(crate) fn back_up_now(&self, id: &str) -> Result<String, String> {
        let schedule = self.records.schedules().into_iter().find(|schedule| schedule.id == id).ok_or_else(|| "This setup doesn't back up that volume.".to_owned())?;
        let volume = &schedule.resource;
        if schedule.paused {
            return Err(format!("{volume} isn't backed up while its setup is stopped. Start the setup, then back it up."));
        }
        if schedule.when().is_none() {
            return Err(format!("Yougori can't read when {volume} is backed up, so it can't take a backup of it now."));
        }
        if self.running_now(id) {
            return Err(format!("A backup of {volume} is being taken right now. It shows in the list when it finishes."));
        }
        let at = now();
        self.records.change(id, &mut |saved| saved.next_at = saved.next_at.min(at));
        self.wake.notify_one();
        Ok(format!("A backup of {volume} starts now. It shows in the list when it finishes, and the regular times stay as they are."))
    }

    /// Settles what a stopped engine missed, for every schedule, and says how long to sleep.
    /// Called once at the start and then after every tick.
    fn settle(&self, at: i64) -> Vec<Schedule> {
        let mut due = Vec::new();
        for schedule in self.records.schedules() {
            if schedule.paused {
                continue;
            }
            let Some(_) = schedule.when() else { continue };
            if schedule.next_at > at {
                continue;
            }
            // The time has passed. A first run (next_at 0) is treated as due now, not as a
            // hundred missed nights.
            let missed = schedule.last_started_at.is_some() || schedule.next_at > 0;
            match (missed, schedule.missed) {
                // Nothing ran while the engine was away and the setup asked to skip: move on.
                (true, BackupMissed::Skip) if schedule.next_at < at - TICK.as_secs() as i64 => {
                    let advance = next_due(&schedule, at).unwrap_or(at + 3600);
                    let detail = format!("The backup due at {} was left out: the setup asks to skip a backup it misses. The next one is at {}.", stamp(schedule.next_at), stamp(advance));
                    self.records.change(&schedule.id, &mut |saved| {
                        saved.next_at = advance;
                        saved.last_outcome = Outcome::Skipped;
                        saved.last_detail = detail.clone();
                    });
                }
                // Due now, or missed with run_once: one run, however many times passed.
                _ => due.push(schedule),
            }
        }
        due
    }

    /// Whether this schedule may start now, and marks it running. `false` when one is already
    /// going: with `queue`, one more is remembered.
    fn claim(&self, id: &str, overlap: BackupOverlap) -> bool {
        let mut running = self.running.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        match running.get_mut(id) {
            None => {
                running.insert(id.to_owned(), false);
                true
            }
            Some(queued) => {
                if overlap == BackupOverlap::Queue {
                    *queued = true;
                }
                false
            }
        }
    }

    /// Drops the claim, and says whether one more run was queued behind it.
    fn release(&self, id: &str) -> bool {
        let mut running = self.running.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        running.remove(id).unwrap_or(false)
    }

    /// Runs one schedule to its end, with its retries, and writes down what happened. The next
    /// time is worked out from when the run was due, so a long backup never shifts the schedule.
    async fn carry_out(self: &Arc<Self>, schedule: Schedule, cancel: CancellationToken) {
        let started = now();
        self.records.change(&schedule.id, &mut |saved| {
            saved.last_started_at = Some(started);
            saved.last_detail = "Running.".into();
        });
        let mut attempt = 0;
        let outcome = loop {
            if cancel.is_cancelled() {
                break Err("Yougori was closing, so this backup was left for next time.".to_owned());
            }
            let result = tokio::select! {
                biased;
                _ = cancel.cancelled() => Err("Yougori was closing, so this backup was stopped. Nothing kept is lost; the next one runs as usual.".to_owned()),
                result = tokio::time::timeout(RUN_LIMIT, self.runner.run(&schedule, &cancel)) => match result {
                    Ok(result) => result,
                    Err(_) => Err(format!("This backup was still running after {} hours and was given up on.", RUN_LIMIT.as_secs() / 3600)),
                },
            };
            match result {
                Ok(said) => break Ok(said),
                Err(error) if attempt >= schedule.retries || cancel.is_cancelled() => break Err(error),
                Err(error) => {
                    attempt += 1;
                    let wait = (self.backoff.load(std::sync::atomic::Ordering::SeqCst) << (attempt - 1).min(8)).min(RETRY_BACKOFF_MAX);
                    let detail = format!("{error} Trying again in {} ({} of {}).", span(wait), attempt, schedule.retries);
                    self.records.change(&schedule.id, &mut |saved| saved.last_detail = detail.clone());
                    tokio::select! {
                        _ = cancel.cancelled() => {}
                        _ = tokio::time::sleep(Duration::from_secs(wait)) => {}
                    }
                }
            }
        };
        let finished = now();
        // From the moment it was due, so a run that takes an hour does not push the next one on.
        let advance = next_due(&schedule, schedule.next_at.max(started)).unwrap_or(finished + 3600);
        let tried = attempt;
        self.records.change(&schedule.id, &mut |saved| {
            saved.last_finished_at = Some(finished);
            saved.next_at = advance;
            match &outcome {
                Ok(said) => {
                    saved.last_outcome = Outcome::Done;
                    saved.failures = 0;
                    saved.last_detail = format!("{said} The next backup is at {}.", stamp(advance));
                }
                Err(error) => {
                    saved.last_outcome = Outcome::Failed;
                    saved.failures += 1;
                    let again = if tried > 0 { format!(" Tried {} more time{} first.", tried, if tried == 1 { "" } else { "s" }) } else { String::new() };
                    saved.last_detail = format!("{error}{again} The next backup is at {}.", stamp(advance));
                }
            }
        });
        if self.release(&schedule.id) && !cancel.is_cancelled() {
            // One more fell due while this ran, and the setup asks to queue it: it becomes due
            // now, and the loop picks it up on its next pass rather than running from in here.
            self.records.change(&schedule.id, &mut |saved| saved.next_at = saved.next_at.min(now()));
            self.wake.notify_one();
        }
    }

    /// The loop. It returns when `cancel` is cancelled; a run already going is asked to stop.
    pub(crate) async fn run(self: Arc<Self>, cancel: CancellationToken) {
        loop {
            if cancel.is_cancelled() {
                return;
            }
            for schedule in self.settle(now()) {
                if cancel.is_cancelled() {
                    return;
                }
                if !self.claim(&schedule.id, schedule.overlap) {
                    // One is still going. `skip` says so and waits for the next time; `queue`
                    // remembered it above.
                    if schedule.overlap == BackupOverlap::Skip {
                        let advance = next_due(&schedule, now()).unwrap_or(now() + 3600);
                        let detail = format!("The backup due at {} was left out: the previous one was still running. The next one is at {}.", stamp(schedule.next_at), stamp(advance));
                        self.records.change(&schedule.id, &mut |saved| {
                            saved.next_at = advance;
                            saved.last_outcome = Outcome::Skipped;
                            saved.last_detail = detail.clone();
                        });
                    }
                    continue;
                }
                // This due time is taken by the run starting now. Until its next time the schedule
                // is not due, so a pass while it runs (a backup asked for now wakes the loop) does
                // not count the same time again and record it as skipped over the live run.
                let taken = next_due(&schedule, now()).unwrap_or(now() + 3600);
                self.records.change(&schedule.id, &mut |saved| saved.next_at = saved.next_at.max(taken));
                let scheduler = self.clone();
                let token = cancel.clone();
                tokio::spawn(async move { scheduler.carry_out(schedule, token).await });
            }
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = self.wake.notified() => {}
                _ = tokio::time::sleep(self.sleep_for()) => {}
            }
        }
    }

    /// How long until the next schedule is due, never more than a tick.
    fn sleep_for(&self) -> Duration {
        let at = now();
        let soonest = self
            .records
            .schedules()
            .into_iter()
            .filter(|schedule| !schedule.paused)
            .map(|schedule| schedule.next_at.saturating_sub(at).max(0) as u64)
            .min();
        Duration::from_secs(soonest.unwrap_or(TICK.as_secs())).min(TICK).max(Duration::from_millis(50))
    }

    #[cfg(test)]
    pub(crate) fn busy(&self) -> std::collections::HashSet<String> {
        self.running.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).keys().cloned().collect()
    }

    /// Runs whatever is due once, in this task, and returns when every run has finished. Tests
    /// use it so they never wait on a timer.
    #[cfg(test)]
    pub(crate) async fn tick(self: &Arc<Self>, cancel: &CancellationToken) {
        for schedule in self.settle(now()) {
            if self.claim(&schedule.id, schedule.overlap) {
                self.carry_out(schedule, cancel.clone()).await;
            } else if schedule.overlap == BackupOverlap::Skip {
                let advance = next_due(&schedule, now()).unwrap_or(now() + 3600);
                self.records.change(&schedule.id, &mut |saved| {
                    saved.next_at = advance;
                    saved.last_outcome = Outcome::Skipped;
                    saved.last_detail = "The previous backup was still running, so this one was left out.".into();
                });
            }
        }
    }
}

/// A moment people read: `2026-10-27 02:00` in this computer's own time.
pub(crate) fn stamp(utc: i64) -> String {
    chrono::DateTime::from_timestamp(utc, 0)
        .map(|at| at.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_else(|| "an unknown time".into())
}

/// A length of time in words: `30 seconds`, `5 minutes`.
fn span(seconds: u64) -> String {
    if seconds < 120 {
        format!("{seconds} seconds")
    } else {
        format!("{} minutes", seconds / 60)
    }
}

/// How `consistency` reads in a review or on the setup page.
pub(crate) fn consistency_words(consistency: BackupConsistency, volume: &str, through: &str) -> String {
    match consistency {
        BackupConsistency::Stop => format!(
            "Before each backup the sandboxes that write to {volume} are stopped, so the copy is of data nothing is changing, and they start again straight after. They are unavailable while it is copied."
        ),
        BackupConsistency::Live => format!(
            "{volume} is copied while everything keeps running, so a file being written at that moment can be copied half-written. A database kept on it may not open from such a copy. {through} is the sandbox it is read through."
        ),
    }
}

/// What a backup of a volume cannot carry, said plainly rather than implied (plan 15, row
/// `backup-workflow`; plan 18.5).
pub(crate) const LIMITS: &str = "A backup is a copy of the volume's files and nothing else. A database on the volume is copied as its files, not through the database's own backup tool: the copy is only as consistent as the files were at that moment, so take it with the sandboxes that write to it stopped (the default) or use the database's own backup for one that must be consistent. It does not hold anything sealed to this computer: passwords and keys in Yougori's credential store stay here, so a restored setup asks for them again. It is kept in Yougori's own data folder on this computer, so it does not protect you if this computer or its disk is lost; copy the folder somewhere else for that. Restoring puts files back; it does not undo what an application wrote elsewhere.";

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Schedules in memory, as the registry keeps them.
    #[derive(Default)]
    pub(crate) struct Memory {
        pub saved: Mutex<Vec<Schedule>>,
    }

    impl Records for Memory {
        fn schedules(&self) -> Vec<Schedule> {
            self.saved.lock().unwrap().clone()
        }
        fn change(&self, id: &str, change: &mut dyn FnMut(&mut Schedule)) {
            let mut saved = self.saved.lock().unwrap();
            if let Some(found) = saved.iter_mut().find(|schedule| schedule.id == id) {
                change(found);
            }
        }
    }

    #[derive(Default)]
    struct Counting {
        runs: AtomicU32,
        /// The next N runs fail.
        fail: AtomicU32,
        /// Each run waits for this gate.
        gate: Option<Arc<tokio::sync::Semaphore>>,
        entered: Arc<tokio::sync::Notify>,
    }

    impl Runner for Counting {
        fn run<'a>(&'a self, _schedule: &'a Schedule, _cancel: &'a CancellationToken) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>> {
            Box::pin(async move {
                self.runs.fetch_add(1, Ordering::SeqCst);
                self.entered.notify_one();
                if let Some(gate) = &self.gate {
                    gate.acquire().await.unwrap().forget();
                }
                if self.fail.load(Ordering::SeqCst) > 0 {
                    self.fail.fetch_sub(1, Ordering::SeqCst);
                    return Err("The sandbox did not answer.".into());
                }
                Ok("Backed up 3 files.".to_owned())
            })
        }
    }

    pub(crate) fn schedule(id: &str, when: &str, next_at: i64) -> Schedule {
        Schedule {
            id: id.to_owned(),
            setup: "setup-1".into(),
            resource: "data".into(),
            work: Work::VolumeBackup,
            schedule: when.to_owned(),
            timezone: "UTC".into(),
            keep: 3,
            consistency: BackupConsistency::Stop,
            missed: BackupMissed::RunOnce,
            overlap: BackupOverlap::Skip,
            retries: 0,
            through: "backup".into(),
            path: "/data".into(),
            paused: false,
            next_at,
            last_started_at: None,
            last_finished_at: None,
            last_outcome: Outcome::NeverRun,
            last_detail: String::new(),
            failures: 0,
            backups: Vec::new(),
        }
    }

    fn with(schedules: Vec<Schedule>, runner: Arc<Counting>) -> (Arc<Memory>, Arc<Scheduler>) {
        let records = Arc::new(Memory { saved: Mutex::new(schedules) });
        let scheduler = Scheduler::new(records.clone(), runner);
        (records, scheduler)
    }

    fn saved(records: &Memory, id: &str) -> Schedule {
        records.saved.lock().unwrap().iter().find(|schedule| schedule.id == id).cloned().expect("the schedule is there")
    }

    #[tokio::test]
    async fn a_schedule_that_is_due_runs_once_and_moves_to_its_next_time() {
        let runner = Arc::new(Counting::default());
        let (records, scheduler) = with(vec![schedule("a", "daily 02:00", now() - 10)], runner.clone());
        scheduler.tick(&CancellationToken::new()).await;
        assert_eq!(runner.runs.load(Ordering::SeqCst), 1);
        let after = saved(&records, "a");
        assert_eq!(after.last_outcome, Outcome::Done);
        assert!(after.next_at > now(), "the next time is in the future");
        assert!(after.last_detail.contains("The next backup is at"), "{}", after.last_detail);
        // Nothing is due now, so a second tick runs nothing.
        scheduler.tick(&CancellationToken::new()).await;
        assert_eq!(runner.runs.load(Ordering::SeqCst), 1);
    }

    /// PROVES a backup asked for now runs once, now, and leaves the regular times where they were;
    /// and that one is refused, saying why, while the setup is stopped or a backup is going.
    #[tokio::test]
    async fn a_backup_asked_for_now_runs_at_once_and_keeps_the_regular_times() {
        let runner = Arc::new(Counting::default());
        // Not due for hours: its regular next time.
        let regular = next_due(&schedule("a", "daily 02:00", 0), now()).unwrap();
        let (records, scheduler) = with(vec![schedule("a", "daily 02:00", regular)], runner.clone());
        scheduler.tick(&CancellationToken::new()).await;
        assert_eq!(runner.runs.load(Ordering::SeqCst), 0, "nothing is due yet");
        let said = scheduler.back_up_now("a").unwrap();
        assert!(said.starts_with("A backup of data starts now."), "{said}");
        scheduler.tick(&CancellationToken::new()).await;
        assert_eq!(runner.runs.load(Ordering::SeqCst), 1, "it ran now");
        let after = saved(&records, "a");
        assert_eq!(after.last_outcome, Outcome::Done);
        assert_eq!(after.next_at, regular, "the next one is the regular next time, where it already was");

        // Refused, with the reason, while a backup of it runs.
        assert!(scheduler.claim("a", BackupOverlap::Skip));
        assert_eq!(scheduler.back_up_now("a").unwrap_err(), "A backup of data is being taken right now. It shows in the list when it finishes.");
        scheduler.release("a");
        // And while its setup is stopped, and for a volume it doesn't back up.
        records.change("a", &mut |saved| saved.paused = true);
        assert_eq!(scheduler.back_up_now("a").unwrap_err(), "data isn't backed up while its setup is stopped. Start the setup, then back it up.");
        assert_eq!(scheduler.back_up_now("b").unwrap_err(), "This setup doesn't back up that volume.");
        assert_eq!(runner.runs.load(Ordering::SeqCst), 1, "nothing refused ran");
    }

    /// PROVES the loop takes a due time when it starts the run for it, so a backup asked for now
    /// is not also recorded as skipped "because the previous one was still running" while it is
    /// the one running. Found on a real engine, where every backup asked for now showed that first.
    #[tokio::test]
    async fn a_backup_asked_for_now_is_not_called_skipped_while_it_runs() {
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let runner = Arc::new(Counting { gate: Some(gate.clone()), ..Counting::default() });
        let regular = next_due(&schedule("a", "daily 02:00", 0), now()).unwrap();
        let (records, scheduler) = with(vec![schedule("a", "daily 02:00", regular)], runner.clone());
        let cancel = CancellationToken::new();
        let looping = tokio::spawn({
            let (scheduler, cancel) = (scheduler.clone(), cancel.clone());
            async move { scheduler.run(cancel).await }
        });
        scheduler.back_up_now("a").unwrap();
        runner.entered.notified().await;
        // The loop passes again while the run is held open, as another wake makes it.
        scheduler.wake.notify_one();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let during = saved(&records, "a");
        assert_ne!(during.last_outcome, Outcome::Skipped, "{}", during.last_detail);
        assert_eq!(during.last_detail, "Running.");
        gate.add_permits(1);
        for _ in 0..100 {
            if saved(&records, "a").last_outcome == Outcome::Done {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(saved(&records, "a").last_outcome, Outcome::Done);
        assert_eq!(runner.runs.load(Ordering::SeqCst), 1, "it ran once");
        cancel.cancel();
        looping.await.unwrap();
    }

    #[tokio::test]
    async fn a_paused_schedule_runs_nothing_and_keeps_its_time() {
        let runner = Arc::new(Counting::default());
        let mut paused = schedule("a", "daily 02:00", now() - 10);
        paused.paused = true;
        let due = paused.next_at;
        let (records, scheduler) = with(vec![paused], runner.clone());
        scheduler.tick(&CancellationToken::new()).await;
        assert_eq!(runner.runs.load(Ordering::SeqCst), 0);
        assert_eq!(saved(&records, "a").next_at, due, "a stopped setup does not lose its place");
    }

    #[tokio::test]
    async fn a_missed_run_follows_the_setups_policy() {
        // Two days away from the computer, with run_once: one run, not two.
        let runner = Arc::new(Counting::default());
        let (records, scheduler) = with(vec![schedule("a", "daily 02:00", now() - 2 * 86_400)], runner.clone());
        scheduler.tick(&CancellationToken::new()).await;
        assert_eq!(runner.runs.load(Ordering::SeqCst), 1, "one catch-up backup, not one per missed night");
        assert!(saved(&records, "a").next_at > now());

        let runner = Arc::new(Counting::default());
        let mut skipping = schedule("b", "daily 02:00", now() - 2 * 86_400);
        skipping.missed = BackupMissed::Skip;
        skipping.last_started_at = Some(now() - 3 * 86_400);
        let (records, scheduler) = with(vec![skipping], runner.clone());
        scheduler.tick(&CancellationToken::new()).await;
        assert_eq!(runner.runs.load(Ordering::SeqCst), 0, "skip waits for the next time");
        let after = saved(&records, "b");
        assert_eq!(after.last_outcome, Outcome::Skipped);
        assert!(after.next_at > now());
        assert!(after.last_detail.contains("left out"), "{}", after.last_detail);
    }

    #[tokio::test]
    async fn an_overlapping_run_is_skipped_or_queued() {
        // One still running, overlap skip: the second is left out and the time moves on.
        let runner = Arc::new(Counting::default());
        let (records, scheduler) = with(vec![schedule("a", "daily 02:00", now() - 10)], runner.clone());
        assert!(scheduler.claim("a", BackupOverlap::Skip), "pretend one is running");
        scheduler.tick(&CancellationToken::new()).await;
        assert_eq!(runner.runs.load(Ordering::SeqCst), 0);
        assert_eq!(saved(&records, "a").last_outcome, Outcome::Skipped);
        assert_eq!(scheduler.busy(), ["a".to_owned()].into_iter().collect::<HashSet<_>>());

        // overlap queue: the one behind becomes due when the first finishes, and only one does.
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let runner = Arc::new(Counting { gate: Some(gate.clone()), ..Default::default() });
        let mut queueing = schedule("b", "daily 02:00", now() - 10);
        queueing.overlap = BackupOverlap::Queue;
        let (records, scheduler) = with(vec![queueing], runner.clone());
        let first = {
            let scheduler = scheduler.clone();
            let schedule = saved(&records, "b");
            assert!(scheduler.claim("b", BackupOverlap::Queue));
            tokio::spawn(async move { scheduler.carry_out(schedule, CancellationToken::new()).await })
        };
        runner.entered.notified().await;
        // Two more fall due while it runs; at most one waits.
        assert!(!scheduler.claim("b", BackupOverlap::Queue));
        assert!(!scheduler.claim("b", BackupOverlap::Queue));
        gate.add_permits(2);
        first.await.unwrap();
        assert_eq!(runner.runs.load(Ordering::SeqCst), 1);
        assert!(saved(&records, "b").next_at <= now(), "the one that waited is due now, not at the next time");
        scheduler.tick(&CancellationToken::new()).await;
        assert_eq!(runner.runs.load(Ordering::SeqCst), 2, "exactly one run was queued behind the first");
        assert!(saved(&records, "b").next_at > now(), "and nothing more waits");
        scheduler.tick(&CancellationToken::new()).await;
        assert_eq!(runner.runs.load(Ordering::SeqCst), 2);
    }

    /// Deleting a volume's backups waits on this, so it has to hold for exactly as long as a run
    /// is going, its record writes included, and only for that schedule.
    #[tokio::test]
    async fn running_now_holds_only_while_a_run_is_going() {
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let runner = Arc::new(Counting { gate: Some(gate.clone()), ..Default::default() });
        let (records, scheduler) = with(vec![schedule("a", "daily 02:00", now() - 10)], runner.clone());
        assert!(!scheduler.running_now("a"));
        let going = {
            let scheduler = scheduler.clone();
            let schedule = saved(&records, "a");
            assert!(scheduler.claim("a", BackupOverlap::Skip));
            tokio::spawn(async move { scheduler.carry_out(schedule, CancellationToken::new()).await })
        };
        runner.entered.notified().await;
        assert!(scheduler.running_now("a"));
        assert!(!scheduler.running_now("b"), "only the schedule that is running");
        gate.add_permits(1);
        going.await.unwrap();
        assert!(!scheduler.running_now("a"), "and not once it has finished");
        assert_eq!(saved(&records, "a").last_outcome, Outcome::Done);
    }

    #[tokio::test]
    async fn a_failed_run_is_tried_again_up_to_its_limit() {
        let runner = Arc::new(Counting::default());
        runner.fail.store(5, Ordering::SeqCst);
        let mut retrying = schedule("a", "daily 02:00", now() - 10);
        retrying.retries = 2;
        let (records, scheduler) = with(vec![retrying], runner.clone());
        scheduler.retry_quickly();
        scheduler.tick(&CancellationToken::new()).await;
        assert_eq!(runner.runs.load(Ordering::SeqCst), 3, "the first try and two more");
        let after = saved(&records, "a");
        assert_eq!(after.last_outcome, Outcome::Failed);
        assert_eq!(after.failures, 1);
        assert!(after.last_detail.contains("Tried 2 more times"), "{}", after.last_detail);
        assert!(after.next_at > now(), "a failure still waits for the next time");
    }

    #[tokio::test]
    async fn nothing_starts_while_the_engine_is_closing() {
        let runner = Arc::new(Counting::default());
        let (records, scheduler) = with(vec![schedule("a", "daily 02:00", now() - 10)], runner.clone());
        let cancel = CancellationToken::new();
        cancel.cancel();
        scheduler.clone().run(cancel.clone()).await;
        assert_eq!(runner.runs.load(Ordering::SeqCst), 0);
        assert_eq!(saved(&records, "a").last_outcome, Outcome::NeverRun);
    }

    /// A saved registry holding one setup: an `app` sandbox and a `backup` sandbox that both
    /// mount the `data` volume, and the volume with the backup fields a template declares.
    fn registry_with(backup: serde_json::Value, lifecycle: crate::setups::model::Lifecycle) -> crate::setups::store::Registry {
        use crate::setups::model::{Cost, Desired, Health, Instance, Observed, Resource, Source};
        use serde_json::json;
        let sandbox = |id: &str| Resource {
            id: id.to_owned(),
            kind: yougori_setup::resource::Kind::Environment,
            depends_on: Vec::new(),
            runtime_id: Some(format!("env-{id}")),
            owner: None,
            borrowers: Vec::new(),
            generation: 1,
            desired: Desired::Running,
            observed: Observed::Running,
            retained_data: false,
            cost: Cost::Free,
            last_observed_at: None,
            drift: None,
            spec: json!({"type": "container", "image": "x", "volumes": [{"source": "data", "target": "/data"}]}),
            spec_digest: String::new(),
        };
        let mut volume = sandbox("data");
        volume.kind = yougori_setup::resource::Kind::Volume;
        volume.spec = backup;
        let instance = Instance {
            id: "setup-1".into(),
            name: "Notes".into(),
            source: Source { reference: yougori_setup::dto::SourceRef::LocalFolder { path: "/templates/backup-workflow".into() }, digest: String::new() },
            format_version: 2,
            protocol_version: 1,
            lock_digest: None,
            config_revision: 1,
            revision: 1,
            answers: Default::default(),
            secret_bindings: Default::default(),
            lock: None,
            customizations: Default::default(),
            capabilities: Vec::new(),
            realms: Vec::new(),
            storage: None,
            outputs: Default::default(),
            current_operation: None,
            lifecycle,
            health: Health::Ready,
            history: Vec::new(),
            resources: [("app".to_owned(), sandbox("app")), ("backup".to_owned(), sandbox("backup")), ("data".to_owned(), volume)].into(),
            created_at: String::new(),
            updated_at: String::new(),
        };
        let mut registry = crate::setups::store::Registry::default();
        registry.instances.insert("setup-1".into(), instance);
        registry
    }

    fn service_with(registry: crate::setups::store::Registry) -> (tempfile::TempDir, Arc<crate::setups::Service>) {
        let folder = tempfile::tempdir().unwrap();
        crate::setups::store::Store::new(folder.path()).save(&registry).unwrap();
        let service = Arc::new(crate::setups::Service::open(folder.path(), folder.path(), Default::default()));
        (folder, service)
    }

    #[test]
    fn a_setups_times_follow_what_its_template_declares_and_whether_it_runs() {
        use crate::setups::model::Lifecycle;
        use serde_json::json;
        let declared = json!({
            "backup_schedule": "daily 02:00",
            "backup_timezone": "UTC",
            "backup_keep": 5,
            "backup_consistency": "stop",
            "backup_missed": "run_once",
            "backup_overlap": "skip",
            "backup_retries": 2,
            "backup_through": {"resource": "backup"},
        });
        let (_folder, service) = service_with(registry_with(declared.clone(), Lifecycle::Running));
        service.sync_schedules("setup-1").unwrap();
        let schedules = service.schedules_of("setup-1").unwrap();
        assert_eq!(schedules.len(), 1);
        let saved = &schedules[0];
        assert_eq!(saved.id, "setup-1/data");
        assert_eq!((saved.schedule.as_str(), saved.timezone.as_str()), ("daily 02:00", "UTC"));
        assert_eq!((saved.keep, saved.retries, saved.through.as_str(), saved.path.as_str()), (5, 2, "backup", "/data"));
        assert!(!saved.paused && saved.next_at > now(), "it is due at its next time, not at once");

        // What happened and what is kept survive a change to the setup that leaves the times
        // alone; changing the times works the next one out afresh.
        let due = saved.next_at;
        <crate::setups::Service as Records>::change(&service, "setup-1/data", &mut |schedule| {
            schedule.last_outcome = Outcome::Done;
            schedule.backups.push(crate::setups::backups::Backup {
                id: "backup-1".into(),
                at: 1,
                files: 2,
                bytes: 3,
                checksum: "x".into(),
                consistency: BackupConsistency::Stop,
            });
        });
        service.sync_schedules("setup-1").unwrap();
        let saved = service.schedules_of("setup-1").unwrap().remove(0);
        assert_eq!((saved.next_at, saved.last_outcome, saved.backups.len()), (due, Outcome::Done, 1));
    }

    #[test]
    fn stopping_a_setup_pauses_its_times_and_removing_it_drops_them() {
        use crate::setups::model::Lifecycle;
        use serde_json::json;
        let declared = json!({"backup_schedule": "daily 02:00", "backup_through": {"resource": "backup"}});
        // Stopped: the time is kept, and nothing runs.
        let (_folder, service) = service_with(registry_with(declared.clone(), Lifecycle::Stopped));
        service.sync_schedules("setup-1").unwrap();
        let saved = service.schedules_of("setup-1").unwrap().remove(0);
        assert!(saved.paused);
        assert_eq!((saved.keep, saved.retries, saved.consistency), (7, 2, BackupConsistency::Stop), "the defaults the template left out");

        // A volume that no longer declares a backup loses its times.
        let (_folder, service) = service_with(registry_with(json!({"shared": false}), Lifecycle::Running));
        service.sync_schedules("setup-1").unwrap();
        assert!(service.schedules_of("setup-1").unwrap().is_empty());

        // So does one whose reading sandbox does not mount it: nothing to run, so nothing is kept.
        let mut registry = registry_with(json!({"backup_schedule": "daily 02:00", "backup_through": {"resource": "backup"}}), Lifecycle::Running);
        if let Some(through) = registry.instances.get_mut("setup-1").and_then(|instance| instance.resources.get_mut("backup")) {
            through.spec = json!({"type": "container", "image": "x", "volumes": []});
        }
        let (_folder, service) = service_with(registry);
        service.sync_schedules("setup-1").unwrap();
        assert!(service.schedules_of("setup-1").unwrap().is_empty());

        // A setup that is gone keeps none.
        let (_folder, service) = service_with(crate::setups::store::Registry::default());
        service.sync_schedules("setup-1").unwrap();
        assert!(service.schedules_of("setup-1").unwrap().is_empty());
    }

    #[test]
    fn the_next_time_follows_the_clocks_of_its_zone() {
        let mut london = schedule("a", "daily 01:30", 0);
        london.timezone = "Europe/London".into();
        let before = times::days_from_civil(2026, 3, 28) * 86_400;
        // 01:30 does not exist on 29 March: it runs an hour later by the clock, 01:30 UTC.
        let first = next_due(&london, before).expect("a schedule that reads");
        assert_eq!(first, times::days_from_civil(2026, 3, 28) * 86_400 + 90 * 60);
        let second = next_due(&london, first).expect("a schedule that reads");
        assert_eq!(second, times::days_from_civil(2026, 3, 29) * 86_400 + 90 * 60);
        assert!(london.describe().contains("every day at 01:30"));
        assert!(london.describe().contains("Europe/London"));
        // A saved schedule that no longer reads never runs, rather than running at a wrong time.
        let mut broken = schedule("b", "daily 01:30", 0);
        broken.schedule = "whenever".into();
        assert_eq!(next_due(&broken, 0), None);
    }
}
