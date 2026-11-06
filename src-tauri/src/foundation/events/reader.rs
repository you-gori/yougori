//! Reading a durable CORE-06 stream without owning it (docs/combined-gpu-memory-and-vm-sandbox-plan.md:
//! S2 CORE-06 "duplicate/lost events reconcile"; VM-W42 "one append authority per stream";
//! VM-CP-22 "a truncated file, a rewritten record and a restart are detected";
//! docs/combined-plan-leftover-tasks.md S06 "readers in other processes").
//!
//! A [`DurableReader`] opens a stream's directory read-only, in this process or another, while
//! the stream's one owner keeps appending. It takes no lock, holds no file open between calls
//! and writes nothing, so it can neither append nor delay the owner, and any number of readers
//! can follow one stream. Like [`DurableLog::read`](super::DurableLog::read), it resumes from
//! a [`LogCursor`] and returns the entries in order, with an explicit gap wherever retention or
//! a truncation removed sequences.
//!
//! What it returns is bounded by the stream's synced high-water mark. An owner syncs a line
//! before it syncs the mark that acknowledges it, so every line up to the mark is whole on
//! disk once the mark is; a line past it may still be in flight and is never read. Each read
//! first reads the mark, then lists the segments, then reads the stream's state: retention
//! persists its low-water mark before a segment goes, so a segment that vanishes while the
//! reader works is either covered by the state read after the listing, and read as a
//! retention gap, or the read starts over. Every line is verified again (its digest bound to
//! the stream instance, its sequence and its owner order, as the owner verifies them), and a
//! retained entry is verified once more when it is returned.
//!
//! The reader refuses what it cannot verify instead of skipping it: a line up to the mark
//! that is torn or does not verify, a sequence out of order, another stream in the directory,
//! a cursor of another stream or past the mark. While the owner is opening the stream (it
//! quarantines a torn tail and records markers), a read may meet a line the owner is about to
//! cut off; the reader starts over a bounded number of times and then reports the damage,
//! and a later read succeeds once the owner has finished.
//!
//! Sequences the mark acknowledges but no line holds yet, such as entries lost from the end
//! of the stream after a crash that the next owner has not recorded as truncated yet, are not
//! given up as a gap: the owner may still write them, and the reader reports them as
//! [`DurableReader::unsettled`] until a line or a [`LogMarker::Truncated`](super::LogMarker)
//! entry settles them.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;

use super::durable::{
    after, check_order, correlation_of, decode_line, list, mark_damage, read_items, read_state,
    segment_path, Correlated, Correlation, CursorError, DurableStreamId, IndexEntry, LineProblem,
    LogCursor, LogDamage, LogError, ReadBatch, StreamInstance,
};
use super::envelope::EventSequence;
use super::high_water::{read_marks, MarkProblem};
use super::reconcile::SequenceRange;
use crate::foundation::ids::{digest, Digest, Incarnation, OperationId};

/// Times one refresh starts over when the owner changed the files between the ones it
/// read; each time verifies the stream from its start.
const MAX_ATTEMPTS: u32 = 8;
/// Times one read refreshes again when a segment it was about to return went meanwhile;
/// each time reads only the mark, the listing and the state, and the lines written since.
const MAX_READ_ATTEMPTS: u32 = 64;
const LINE_DOMAIN: &str = "yougori/events/reader-line/v1";

/// What one reader did since it was opened.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReaderTotals {
    /// Reads of the mark, the segments and the state.
    pub refreshes: u64,
    /// Times a refresh started over because the owner changed a file it was reading.
    pub retries: u64,
    /// Times the reader verified the stream from its start again, because the line it had
    /// verified last was no longer where it was.
    pub rescans: u64,
    /// Lines verified, each counted once per scan.
    pub lines_verified: u64,
}

/// Where the reader's verification stopped: the last line it verified.
#[derive(Clone, Copy, Debug)]
struct Scanned {
    segment: EventSequence,
    /// Where the line starts and ends in its segment, and its number there, from 1.
    start: u64,
    end: u64,
    line: u64,
    sequence: EventSequence,
    owner: Incarnation,
    /// The digest of the line's bytes, to tell that it is still there.
    bytes: Digest,
}

/// Why one attempt at a refresh stopped.
enum Attempt {
    /// The owner may have changed a file between the ones read: start over.
    Retry(LogError),
    Final(LogError),
}

/// A read-only view of one durable stream that another handle, in this process or another,
/// owns (CORE-06; S06).
#[derive(Debug)]
pub struct DurableReader<P> {
    directory: PathBuf,
    stream: StreamInstance,
    /// The retained entries verified so far, oldest first.
    index: VecDeque<IndexEntry>,
    scanned: Option<Scanned>,
    /// The synced high-water mark as of the last refresh.
    high_water: Option<EventSequence>,
    /// Retention's low-water mark as of the last refresh.
    dropped: Option<EventSequence>,
    totals: ReaderTotals,
    _payload: PhantomData<fn() -> P>,
}

impl<P: DeserializeOwned> DurableReader<P> {
    /// Opens the stream `stream` in `directory` for reading, without taking ownership,
    /// and reads it up to its mark. Refuses a directory that holds no stream or another
    /// one, and a stream it cannot verify.
    pub fn open(directory: &Path, stream: DurableStreamId) -> Result<Self, LogError> {
        let state = read_state(directory)?.ok_or_else(|| LogError::Io {
            action: "open the durable stream",
            kind: io::ErrorKind::NotFound,
            message: format!("{} holds no durable stream", directory.display()),
        })?;
        if state.stream.stream != stream {
            return Err(LogError::Damaged(LogDamage::OtherStream {
                found: state.stream,
            }));
        }
        let mut reader = Self {
            directory: directory.to_path_buf(),
            stream: state.stream,
            index: VecDeque::new(),
            scanned: None,
            high_water: None,
            dropped: None,
            totals: ReaderTotals::default(),
            _payload: PhantomData,
        };
        reader.refresh()?;
        Ok(reader)
    }

    /// Reads at most `max_items` items after `cursor`, as [`DurableLog::read`] does, up to
    /// the stream's synced high-water mark. `caught_up` says whether the batch reached the
    /// mark. Refuses a cursor of another stream or past the mark.
    ///
    /// [`DurableLog::read`]: super::DurableLog::read
    pub fn read(&mut self, cursor: &LogCursor, max_items: usize) -> Result<ReadBatch<P>, LogError> {
        if cursor.stream != self.stream {
            return Err(LogError::Cursor(CursorError::WrongStream {
                expected: self.stream.clone(),
                found: cursor.stream.clone(),
            }));
        }
        let mut attempt = 1;
        loop {
            self.refresh()?;
            let last = self.high_water;
            if let Some(after) = cursor.after {
                if last.is_none_or(|last| after > last) {
                    return Err(LogError::Cursor(CursorError::Future { after, last }));
                }
            }
            // Gaps are proven up to the last line verified and retention's low-water mark;
            // past them the mark's sequences are unsettled, not lost.
            let settled = self.verified_through().max(self.dropped);
            match read_items(
                &self.directory,
                &self.stream,
                &self.index,
                self.dropped,
                cursor.after,
                settled,
                max_items,
            ) {
                Ok((items, reached)) => {
                    return Ok(ReadBatch {
                        items,
                        caught_up: reached == last,
                        cursor: LogCursor {
                            stream: self.stream.clone(),
                            after: reached,
                        },
                    })
                }
                // A segment went after the refresh verified it: the next refresh finds
                // what retention dropped and reads it as a gap.
                Err(LogError::Io { kind, .. }) if attempt < MAX_READ_ATTEMPTS && gone(kind) => {
                    attempt += 1;
                    self.totals.retries = self.totals.retries.saturating_add(1);
                }
                // A line changed after the refresh verified it: verify everything again.
                Err(LogError::Damaged(LogDamage::Entry { .. })) if attempt < MAX_READ_ATTEMPTS => {
                    attempt += 1;
                    self.totals.retries = self.totals.retries.saturating_add(1);
                    self.reset();
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Reads the stream's mark, segments and state again, and verifies every line written
    /// since the last refresh, up to the mark.
    pub fn refresh(&mut self) -> Result<(), LogError> {
        self.totals.refreshes = self.totals.refreshes.saturating_add(1);
        let mut attempt = 1;
        loop {
            match self.try_refresh() {
                Ok(()) => return Ok(()),
                Err(Attempt::Retry(_)) if attempt < MAX_ATTEMPTS => {
                    attempt += 1;
                    self.totals.retries = self.totals.retries.saturating_add(1);
                    self.reset();
                }
                Err(Attempt::Retry(error) | Attempt::Final(error)) => {
                    self.reset();
                    return Err(error);
                }
            }
        }
    }

    /// The cursor before every entry.
    pub fn start(&self) -> LogCursor {
        LogCursor {
            stream: self.stream.clone(),
            after: None,
        }
    }

    /// The cursor at the mark as of the last refresh, for a reader that wants only what
    /// comes next.
    pub fn end(&self) -> LogCursor {
        LogCursor {
            stream: self.stream.clone(),
            after: self.high_water,
        }
    }

    /// The stream's synced high-water mark as of the last refresh: the last sequence it
    /// acknowledged.
    pub fn high_water(&self) -> Option<EventSequence> {
        self.high_water
    }

    /// Sequences the mark acknowledges that the reader cannot read yet: no line holds them
    /// and no marker recorded them as truncated. They are not a gap; the owner either
    /// writes them or records them as truncated when it next opens the stream.
    pub fn unsettled(&self) -> Option<SequenceRange> {
        let first = after(self.verified_through().max(self.dropped))?;
        SequenceRange::new(first, self.high_water?)
    }

    pub fn stream(&self) -> &StreamInstance {
        &self.stream
    }

    pub fn totals(&self) -> ReaderTotals {
        self.totals
    }

    /// The last sequence verified on disk.
    fn verified_through(&self) -> Option<EventSequence> {
        self.scanned.map(|scanned| scanned.sequence)
    }

    /// Forgets what was verified, so the next refresh verifies the stream from its start.
    fn reset(&mut self) {
        self.index.clear();
        self.scanned = None;
    }

    fn try_refresh(&mut self) -> Result<(), Attempt> {
        // The mark first: every line up to it was whole on disk before it was synced.
        let marks = match read_marks(&self.directory, &self.stream) {
            Ok(Some(marks)) => marks,
            Ok(None) => {
                return Err(Attempt::Final(LogError::Damaged(
                    LogDamage::HighWaterMissing,
                )))
            }
            // A read between two writes can find both slots in flux, but a mark of another
            // instance of the stream never verifies: tell the two apart by the state.
            Err(problem @ (MarkProblem::Spoiled | MarkProblem::Io { .. })) => {
                self.read_dropped()?;
                return Err(Attempt::Retry(mark_damage(problem)));
            }
            Err(problem) => return Err(Attempt::Final(mark_damage(problem))),
        };
        // Then the segments, then the state: a segment missing from the listing went after
        // retention persisted its low-water mark, which the state read now covers.
        let listing = list(&self.directory).map_err(Attempt::Retry)?;
        let mut dropped = self.read_dropped()?;
        let through = marks.through.max(dropped);
        if let Some(scanned) = self.scanned {
            let listed = listing
                .segments
                .iter()
                .any(|(first, _)| *first == scanned.segment);
            // The last line verified is still where it was, or retention dropped it.
            let holds = if listed {
                match read_range(&self.directory, scanned.segment, scanned.start, scanned.end) {
                    Ok(bytes) => line_digest(&bytes) == scanned.bytes,
                    Err(error) if vanished(&error) => dropped >= Some(scanned.sequence),
                    // Cut back since: whatever replaced the line is verified afresh.
                    Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => false,
                    Err(error) => {
                        return Err(Attempt::Retry(LogError::io("read a segment", &error)))
                    }
                }
            } else {
                dropped >= Some(scanned.sequence)
            };
            if !holds || Some(scanned.sequence) > through {
                self.reset();
                self.totals.rescans = self.totals.rescans.saturating_add(1);
            }
        }
        let resume = self.scanned;
        let mut previous = resume.map(|scanned| (scanned.sequence, scanned.owner));
        for (position, (first, path)) in listing.segments.iter().enumerate() {
            if previous.map(|(sequence, _)| sequence) >= through {
                break;
            }
            let (offset, mut line) = match resume {
                Some(scanned) if *first < scanned.segment => continue,
                Some(scanned) if *first == scanned.segment => (scanned.end, scanned.line),
                _ => (0, 0),
            };
            let bytes = match read_from(path, offset) {
                Ok(bytes) => bytes,
                Err(error) if vanished(&error) => {
                    // Gone after the listing: retention dropped it, if the state says so
                    // now; it never drops the last segment.
                    let fresh = self.read_dropped()?;
                    let covered = listing
                        .segments
                        .get(position + 1)
                        .and_then(|(next, _)| next.previous())
                        .is_some_and(|last| fresh >= Some(last));
                    if !covered {
                        return Err(Attempt::Retry(LogError::io("read a segment", &error)));
                    }
                    dropped = dropped.max(fresh);
                    continue;
                }
                Err(error) => return Err(Attempt::Retry(LogError::io("read a segment", &error))),
            };
            let mut consumed_total = 0usize;
            while let Some(rest) = bytes.get(consumed_total..).filter(|rest| !rest.is_empty()) {
                if previous.map(|(sequence, _)| sequence) >= through {
                    break;
                }
                line = line.saturating_add(1);
                let damaged = |problem| {
                    Attempt::Retry(LogError::Damaged(LogDamage::Line {
                        segment: *first,
                        line,
                        problem,
                    }))
                };
                let end = rest
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .ok_or_else(|| damaged(LineProblem::Unterminated))?;
                let body = rest.get(..end).unwrap_or_default();
                let stored = decode_line::<P>(&self.stream, body).map_err(damaged)?;
                // A whole line past the mark is not acknowledged yet.
                if Some(stored.sequence) > through {
                    break;
                }
                check_order(previous, &stored, dropped, None).map_err(damaged)?;
                let start =
                    offset.saturating_add(u64::try_from(consumed_total).unwrap_or(u64::MAX));
                if start == 0 && stored.sequence != *first {
                    return Err(Attempt::Retry(LogError::Damaged(LogDamage::SegmentName {
                        segment: *first,
                        first: stored.sequence,
                    })));
                }
                let length = u64::try_from(end + 1).unwrap_or(u64::MAX);
                if dropped.is_none_or(|dropped| stored.sequence > dropped) {
                    self.index.push_back(IndexEntry {
                        sequence: stored.sequence,
                        segment: *first,
                        offset: start,
                        length,
                    });
                }
                self.scanned = Some(Scanned {
                    segment: *first,
                    start,
                    end: start.saturating_add(length),
                    line,
                    sequence: stored.sequence,
                    owner: stored.owner,
                    bytes: line_digest(rest.get(..=end).unwrap_or_default()),
                });
                self.totals.lines_verified = self.totals.lines_verified.saturating_add(1);
                previous = Some((stored.sequence, stored.owner));
                consumed_total += end + 1;
            }
        }
        while self
            .index
            .front()
            .is_some_and(|entry| Some(entry.sequence) <= dropped)
        {
            self.index.pop_front();
        }
        self.dropped = dropped;
        self.high_water = through.max(dropped);
        Ok(())
    }

    /// Retention's low-water mark, from the stream's state, which must still be this
    /// stream's.
    fn read_dropped(&self) -> Result<Option<EventSequence>, Attempt> {
        let state = read_state(&self.directory)
            .map_err(Attempt::Retry)?
            .ok_or(Attempt::Final(LogError::Damaged(LogDamage::StateMissing)))?;
        if state.stream != self.stream {
            return Err(Attempt::Final(LogError::Damaged(LogDamage::OtherStream {
                found: state.stream,
            })));
        }
        Ok(state.dropped_through)
    }
}

impl<P: Correlated + DeserializeOwned> DurableReader<P> {
    /// The retained records of `operation`, in order, and the stream's gaps, as
    /// [`DurableLog::correlate`](super::DurableLog::correlate) finds them, up to the mark.
    pub fn correlate(&mut self, operation: &OperationId) -> Result<Correlation<P>, LogError> {
        let batch = self.read(&self.start(), usize::MAX)?;
        Ok(correlation_of(operation, batch.items))
    }
}

/// Whether a file is gone, or going: Windows refuses to open a file whose deletion is
/// pending while another handle still has it open.
fn gone(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
    )
}

fn vanished(error: &io::Error) -> bool {
    gone(error.kind())
}

fn line_digest(bytes: &[u8]) -> Digest {
    digest(LINE_DOMAIN, &[bytes])
}

/// The bytes of `path` from `offset` to its current end, through a handle that cannot
/// write and is closed before this returns.
fn read_from(path: &Path, offset: u64) -> io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// The bytes from `start` to `end` of the segment starting at `segment`.
fn read_range(
    directory: &Path,
    segment: EventSequence,
    start: u64,
    end: u64,
) -> io::Result<Vec<u8>> {
    let length = usize::try_from(end.saturating_sub(start)).map_err(io::Error::other)?;
    let mut file = File::open(segment_path(directory, segment))?;
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = vec![0; length];
    file.read_exact(&mut bytes)?;
    Ok(bytes)
}
