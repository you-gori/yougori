//! The supervisor's journal (module docs in `mod.rs`): what it held and ended, written as it
//! happens into a file of its own beside the engine's data, so the next engine start can
//! record in the sandbox's audit stream what the supervisor did while no engine could, and
//! show it. One JSON line per event, flushed at once (and synced for an end or the engine's
//! death), at most [`MAX_JOURNAL_LINES`] lines.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::foundation::ids::ExecutionId;
use crate::foundation::process::ProcessIdentity;
use crate::sandbox::lifecycle::SandboxClass;

use super::protocol::{HeldEnd, SupervisorSettings};

/// The most lines one journal holds; the last one written past it says so.
pub const MAX_JOURNAL_LINES: usize = 4096;

/// The most bytes of one journal the engine reads.
pub const MAX_JOURNAL_BYTES: u64 = 4 << 20;

/// The journals kept after the engine read them, newest first.
pub const KEPT_READ_JOURNALS: usize = 16;

const PREFIX: &str = "supervisor-";
const OPEN_SUFFIX: &str = ".jsonl";
const READ_SUFFIX: &str = ".read.jsonl";

/// One event of the supervisor's life.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum JournalEvent {
    Started {
        supervisor: ProcessIdentity,
        engine: ProcessIdentity,
        settings: SupervisorSettings,
    },
    Held {
        sandbox: ExecutionId,
        class: SandboxClass,
        process: ProcessIdentity,
    },
    Released {
        sandbox: ExecutionId,
    },
    Ended {
        end: HeldEnd,
    },
    /// The engine received these ends in a reply: it recorded them itself, so the next
    /// engine start does not record them again.
    Reported {
        sandboxes: Vec<ExecutionId>,
    },
    /// An end was decided and the host did not observe it within the kill rounds.
    KillUnproven {
        sandbox: ExecutionId,
        detail: String,
    },
    EngineDied,
    EngineSilent {
        quiet_for_ms: u64,
    },
    EngineAnsweringAgain,
    /// The supervisor's own ticks stopped for this long (the computer slept, or the
    /// supervisor was not run); deadlines remain unchanged.
    Gap {
        gap_ms: u64,
    },
    Exit {
        reason: String,
    },
    Truncated,
}

/// One line of a journal: when, on the wall clock, and what.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalLine {
    pub at_unix_ms: u64,
    pub event: JournalEvent,
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or_default()
}

/// The journal one supervisor writes.
pub struct Journal {
    file: Option<File>,
    lines: usize,
}

impl Journal {
    /// A new journal in `dir` for `supervisor`, named by its identity; a journal that cannot
    /// be created is no journal (the supervisor still supervises).
    pub fn create(dir: &Path, supervisor: ProcessIdentity) -> Self {
        let path = dir.join(format!(
            "{PREFIX}{}-{}{OPEN_SUFFIX}",
            supervisor.pid, supervisor.start_time_ticks
        ));
        let file = fs::create_dir_all(dir)
            .and_then(|()| OpenOptions::new().write(true).create_new(true).open(&path))
            .ok();
        Self { file, lines: 0 }
    }

    #[cfg(test)]
    pub fn writing(&self) -> bool {
        self.file.is_some()
    }

    /// Appends `event`; best effort.
    pub fn record(&mut self, event: JournalEvent) {
        let Some(file) = self.file.as_mut() else {
            return;
        };
        let event = if self.lines + 1 >= MAX_JOURNAL_LINES {
            if self.lines + 1 > MAX_JOURNAL_LINES {
                return;
            }
            JournalEvent::Truncated
        } else {
            event
        };
        let durable = matches!(
            event,
            JournalEvent::Ended { .. } | JournalEvent::EngineDied | JournalEvent::Exit { .. }
        );
        let Ok(mut line) = serde_json::to_vec(&JournalLine {
            at_unix_ms: unix_ms(),
            event,
        }) else {
            return;
        };
        line.push(b'\n');
        if file.write_all(&line).is_ok() {
            self.lines += 1;
            if durable {
                let _ = file.sync_data();
            }
        }
    }
}

/// One journal an earlier supervisor wrote.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReadJournal {
    pub file: String,
    pub supervisor: Option<ProcessIdentity>,
    pub lines: Vec<JournalLine>,
    /// Lines that did not read as journal lines.
    pub unreadable: usize,
}

/// The supervisor a journal's name names.
fn supervisor_of(name: &str) -> Option<ProcessIdentity> {
    let rest = name.strip_prefix(PREFIX)?.strip_suffix(OPEN_SUFFIX)?;
    let (pid, ticks) = rest.split_once('-')?;
    Some(ProcessIdentity {
        pid: pid.parse().ok()?,
        start_time_ticks: ticks.parse().ok()?,
    })
}

/// Reads one journal, at most [`MAX_JOURNAL_BYTES`].
fn read_one(path: &Path) -> std::io::Result<(Vec<JournalLine>, usize)> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_JOURNAL_BYTES)
        .read_to_end(&mut bytes)?;
    let mut lines = Vec::new();
    let mut unreadable = 0;
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        match serde_json::from_slice::<JournalLine>(line) {
            Ok(line) => lines.push(line),
            Err(_) => unreadable += 1,
        }
    }
    Ok((lines, unreadable))
}

/// Read-only reconciliation of one remote intent against native observations.
/// Never consumes a journal or treats an unavailable process lookup as death.
pub(crate) fn find_remote_end(
    dir: &Path,
    engine: ProcessIdentity,
    execution: &ExecutionId,
    process: Option<ProcessIdentity>,
) -> Result<Option<HeldEnd>, String> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(PREFIX) && name.ends_with(OPEN_SUFFIX) {
            if paths.len() >= 64 {
                return Err("Too many supervisor journals to reconcile within the bound.".into());
            }
            if entry.file_type().map_err(|e| e.to_string())?.is_file() {
                paths.push(entry.path());
            }
        }
    }
    for path in paths {
        let (lines, _) = read_one(&path).map_err(|e| e.to_string())?;
        let own = lines.first().is_some_and(|line| {
            matches!(&line.event,
            JournalEvent::Started { engine: owner, .. } if *owner == engine)
        });
        if !own {
            continue;
        }
        let mut held = None;
        for line in lines {
            match line.event {
                JournalEvent::Held {
                    sandbox,
                    process: actual,
                    ..
                } if &sandbox == execution => {
                    if process.is_none_or(|expected| expected == actual) {
                        held = Some(actual);
                    }
                }
                JournalEvent::Ended { end }
                    if &end.sandbox == execution
                        && held == Some(end.process)
                        && end.job_processes > 0 =>
                {
                    return Ok(Some(end))
                }
                _ => {}
            }
        }
    }
    Ok(None)
}

/// Reads every journal in `dir` whose supervisor no longer runs (`running` says whether a
/// supervisor does), marks each read, and keeps the newest [`KEPT_READ_JOURNALS`] read ones.
/// A journal of a supervisor still running is left to it.
pub fn take_finished(
    dir: &Path,
    running: impl Fn(&ProcessIdentity) -> bool,
) -> (Vec<ReadJournal>, Vec<String>) {
    let mut read = Vec::new();
    let mut still_running = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return (read, still_running);
    };
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| {
            name.starts_with(PREFIX) && name.ends_with(OPEN_SUFFIX) && !name.ends_with(READ_SUFFIX)
        })
        .collect();
    names.sort();
    for name in names {
        let supervisor = supervisor_of(&name);
        if supervisor.as_ref().is_some_and(&running) {
            still_running.push(name);
            continue;
        }
        let path = dir.join(&name);
        let Ok((lines, unreadable)) = read_one(&path) else {
            continue;
        };
        let read_name = format!("{}{READ_SUFFIX}", name.trim_end_matches(OPEN_SUFFIX));
        let _ = fs::rename(&path, dir.join(&read_name));
        read.push(ReadJournal {
            file: read_name,
            supervisor,
            lines,
            unreadable,
        });
    }
    // Keep the newest read journals only.
    if let Ok(entries) = fs::read_dir(dir) {
        let mut done: Vec<(SystemTime, PathBuf)> = entries
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(READ_SUFFIX))
            .filter_map(|entry| Some((entry.metadata().ok()?.modified().ok()?, entry.path())))
            .collect();
        done.sort_by(|a, b| b.0.cmp(&a.0));
        for (_, path) in done.into_iter().skip(KEPT_READ_JOURNALS) {
            let _ = fs::remove_file(path);
        }
    }
    (read, still_running)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox_vm::supervisor::protocol::EndCause;

    /// PROVES a journal is written line by line, bounded, read back by the next engine
    /// only once its supervisor no longer runs, marked read, and that the read ones kept
    /// are bounded.
    #[test]
    fn a_journal_is_written_bounded_and_read_once_its_supervisor_ended() {
        let dir = tempfile::tempdir().unwrap();
        let supervisor = ProcessIdentity {
            pid: 42,
            start_time_ticks: 1234,
        };
        let mut journal = Journal::create(dir.path(), supervisor);
        assert!(journal.writing());
        journal.record(JournalEvent::EngineDied);
        journal.record(JournalEvent::Ended {
            end: HeldEnd {
                sandbox: ExecutionId::new("exe-a").unwrap(),
                process: supervisor,
                cause: EndCause::EngineDied,
                decided_after_ms: Some(3),
                exit_code: Some(1),
                job_processes: 1,
                kill_rounds: 1,
                ended_within_ms: 2,
                at_ms: 10,
            },
        });
        let (read, running) = take_finished(dir.path(), |_| true);
        assert!(read.is_empty());
        assert_eq!(
            running.len(),
            1,
            "a running supervisor's journal is left to it"
        );
        let (read, running) = take_finished(dir.path(), |_| false);
        assert!(running.is_empty());
        assert_eq!(read.len(), 1);
        assert_eq!(read[0].supervisor, Some(supervisor));
        assert_eq!(read[0].lines.len(), 2);
        assert_eq!(read[0].lines[0].event, JournalEvent::EngineDied);
        assert!(
            take_finished(dir.path(), |_| false).0.is_empty(),
            "read once"
        );
        // Bounded: the line past the bound says the journal was cut.
        let mut long = Journal::create(
            dir.path(),
            ProcessIdentity {
                pid: 43,
                start_time_ticks: 1,
            },
        );
        for _ in 0..MAX_JOURNAL_LINES + 10 {
            long.record(JournalEvent::EngineAnsweringAgain);
        }
        let (read, _) = take_finished(dir.path(), |_| false);
        assert_eq!(read[0].lines.len(), MAX_JOURNAL_LINES);
        assert_eq!(read[0].lines.last().unwrap().event, JournalEvent::Truncated);
        for index in 0..KEPT_READ_JOURNALS + 3 {
            Journal::create(
                dir.path(),
                ProcessIdentity {
                    pid: 100 + index as u32,
                    start_time_ticks: 1,
                },
            )
            .record(JournalEvent::EngineDied);
        }
        take_finished(dir.path(), |_| false);
        let kept = fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(kept, KEPT_READ_JOURNALS);
    }
}

// Append to supervisor/journal.rs after the active compile finishes.
#[cfg(test)]
mod remote_tests {
    use super::*;
    use crate::sandbox_vm::supervisor::protocol::EndCause;

    #[test]
    fn remote_cleanup_needs_its_exact_engine_execution_and_held_process() {
        let dir = tempfile::tempdir().unwrap();
        let engine = ProcessIdentity {
            pid: 101,
            start_time_ticks: 12,
        };
        let observer = ProcessIdentity {
            pid: 102,
            start_time_ticks: 13,
        };
        let process = ProcessIdentity {
            pid: 103,
            start_time_ticks: 14,
        };
        let execution = ExecutionId::new("exe-remote-proof").unwrap();
        let mut journal = Journal::create(dir.path(), observer);
        journal.record(JournalEvent::Started {
            supervisor: observer,
            engine,
            settings: SupervisorSettings {
                silence_ms: 120000,
                grace_ms: 30000,
                kill_wait_ms: 5000,
            },
        });
        let end = HeldEnd {
            sandbox: execution.clone(),
            process,
            cause: EndCause::EngineDied,
            decided_after_ms: Some(1),
            exit_code: None,
            job_processes: 1,
            kill_rounds: 1,
            ended_within_ms: 2,
            at_ms: 10,
        };
        journal.record(JournalEvent::Ended { end: end.clone() });
        assert!(
            find_remote_end(dir.path(), engine, &execution, Some(process))
                .unwrap()
                .is_none(),
            "an end without the native hold is insufficient"
        );
        journal.record(JournalEvent::Held {
            sandbox: execution.clone(),
            class: SandboxClass::Task,
            process,
        });
        assert!(
            find_remote_end(dir.path(), engine, &execution, Some(process))
                .unwrap()
                .is_none(),
            "a later hold cannot validate an earlier end"
        );
        journal.record(JournalEvent::Ended { end: end.clone() });
        assert_eq!(
            find_remote_end(dir.path(), engine, &execution, Some(process)).unwrap(),
            Some(end.clone())
        );
        assert!(
            find_remote_end(dir.path(), observer, &execution, Some(process))
                .unwrap()
                .is_none()
        );
        assert!(find_remote_end(
            dir.path(),
            engine,
            &execution,
            Some(ProcessIdentity {
                start_time_ticks: 15,
                ..process
            })
        )
        .unwrap()
        .is_none());
        assert!(find_remote_end(
            dir.path(),
            engine,
            &ExecutionId::new("exe-other").unwrap(),
            Some(process)
        )
        .unwrap()
        .is_none());
        drop(journal);
        take_finished(dir.path(), |_| false);
        assert_eq!(
            find_remote_end(dir.path(), engine, &execution, None).unwrap(),
            Some(end),
            "renaming the journal during engine recovery preserves proof"
        );
    }
}
