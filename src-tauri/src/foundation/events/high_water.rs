//! The high-water mark of a durable CORE-06 stream (docs/combined-gpu-memory-and-vm-sandbox-plan.md:
//! VM-CP-22 "a truncated file, a rewritten record and a restart are detected"; S06).
//!
//! A stream's segments cannot attest to their own loss: a segment cut back or deleted after
//! a crash reads as a shorter stream. So the stream keeps, in a small file of its own, the
//! highest sequence it ever used and the sequence of its last record, and persists both
//! with every append before the append is acknowledged. Opening the stream again compares
//! the segments with the mark: whatever the segments lost is reported as a truncation, and
//! no sequence up to the mark is given out again.
//!
//! The file has a fixed length and two slots, in different sectors. Each write goes to the
//! slot that does not hold the current mark, in place, and is synced; a write torn by a
//! crash spoils at most that slot, and the other still holds the mark before it. Each slot
//! binds its values to the stream instance with a digest, so a slot from another stream, or
//! one rewritten by hand, does not verify. The cost of an append is one more in-place write
//! and data sync, with no rename and no directory flush, since the file never changes length
//! after it is created.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use super::durable::StreamInstance;
use super::envelope::EventSequence;
use super::owner::sync_dir;
use crate::foundation::ids::{Digest, DigestBuilder};

pub(super) const HIGH_WATER_FILE: &str = "high-water.bin";
const DOMAIN: &str = "yougori/events/durable-high-water/v1";
/// Where each slot starts: one sector apart, so a torn sector spoils one slot at most.
const SLOT_SPAN: usize = 512;
const SLOTS: usize = 2;
/// The highest sequence used, the last record's sequence, then the digest.
const SLOT_BYTES: usize = 8 + 8 + 32;
const FILE_BYTES: usize = SLOT_SPAN * SLOTS;

/// What the stream used, as far as its owners acknowledged it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Marks {
    /// The highest sequence the stream used: every entry an append returned, every marker
    /// written, and every sequence an owner gave up.
    pub through: Option<EventSequence>,
    /// The sequence of the last record appended.
    pub last_record: Option<EventSequence>,
}

/// Why the mark cannot be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum MarkProblem {
    /// The file does not have the length it was created with.
    Length { found: u64 },
    /// Neither slot verifies, though both were written.
    Spoiled,
    Io {
        kind: io::ErrorKind,
        message: String,
    },
}

impl From<io::Error> for MarkProblem {
    fn from(error: io::Error) -> Self {
        Self::Io {
            kind: error.kind(),
            message: error.to_string(),
        }
    }
}

/// The high-water mark file of one stream, open for its owner.
#[derive(Debug)]
pub(super) struct HighWater {
    file: File,
    marks: Marks,
    /// The slot holding `marks`; `None` while neither holds any.
    current: Option<usize>,
}

impl HighWater {
    /// Creates the mark of a new stream, holding nothing, in place of any file there.
    pub fn create(directory: &Path) -> io::Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(directory.join(HIGH_WATER_FILE))?;
        file.write_all(&[0; FILE_BYTES])?;
        file.sync_all()?;
        sync_dir(directory)?;
        Ok(Self {
            file,
            marks: Marks::default(),
            current: None,
        })
    }

    /// Opens the mark of the stream `stream`; `None` when the file does not exist.
    pub fn open(directory: &Path, stream: &StreamInstance) -> Result<Option<Self>, MarkProblem> {
        let mut file = match OpenOptions::new()
            .read(true)
            .write(true)
            .open(directory.join(HIGH_WATER_FILE))
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let best = newest_slot(stream, &mut file)?;
        Ok(Some(Self {
            file,
            marks: best.map(|(_, marks)| marks).unwrap_or_default(),
            current: best.map(|(slot, _)| slot),
        }))
    }

    pub fn marks(&self) -> Marks {
        self.marks
    }

    /// Persists `marks` in the slot that does not hold the current ones, and syncs it. On
    /// `Err` the marks held stay those before; the slot written may be spoiled, never the
    /// other.
    pub fn record(&mut self, stream: &StreamInstance, marks: Marks) -> io::Result<()> {
        let slot = self.current.map_or(0, |current| (current + 1) % SLOTS);
        let offset = u64::try_from(slot * SLOT_SPAN).map_err(io::Error::other)?;
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(&encode(stream, marks))?;
        self.file.sync_data()?;
        self.marks = marks;
        self.current = Some(slot);
        Ok(())
    }
}

/// Reads the mark of the stream `stream` through a handle that cannot write, as a reader
/// that does not own the stream does; `None` when the file does not exist. The owner
/// writes one slot at a time, so a read concurrent with an append finds the mark before
/// it or after it in the other slot, never a mix.
pub(super) fn read_marks(
    directory: &Path,
    stream: &StreamInstance,
) -> Result<Option<Marks>, MarkProblem> {
    let mut file = match File::open(directory.join(HIGH_WATER_FILE)) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let best = newest_slot(stream, &mut file)?;
    Ok(Some(best.map(|(_, marks)| marks).unwrap_or_default()))
}

/// The newest marks a slot of `file` holds and that slot; `None` while neither holds any.
fn newest_slot(
    stream: &StreamInstance,
    file: &mut File,
) -> Result<Option<(usize, Marks)>, MarkProblem> {
    let length = file.metadata()?.len();
    if usize::try_from(length).ok() != Some(FILE_BYTES) {
        return Err(MarkProblem::Length { found: length });
    }
    let mut bytes = vec![0; FILE_BYTES];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut bytes)?;
    let mut best: Option<(usize, Marks)> = None;
    let mut spoiled = 0;
    for slot in 0..SLOTS {
        let start = slot * SLOT_SPAN;
        let Some(raw) = bytes.get(start..start + SLOT_BYTES) else {
            return Err(MarkProblem::Length { found: length });
        };
        match decode(stream, raw) {
            Slot::Empty => {}
            Slot::Spoiled => spoiled += 1,
            Slot::Marks(marks) => {
                let newer = best.is_none_or(|(_, held)| {
                    (marks.through, marks.last_record) > (held.through, held.last_record)
                });
                if newer {
                    best = Some((slot, marks));
                }
            }
        }
    }
    // One append writes one slot, so a crash spoils one at most.
    // One spoiled slot beside an empty one is the first write, torn: no mark yet.
    if spoiled == SLOTS {
        return Err(MarkProblem::Spoiled);
    }
    Ok(best)
}

enum Slot {
    Empty,
    Spoiled,
    Marks(Marks),
}

fn value(sequence: Option<EventSequence>) -> u64 {
    sequence.map_or(0, EventSequence::get)
}

fn check(stream: &StreamInstance, through: u64, last_record: u64) -> Digest {
    DigestBuilder::new(DOMAIN)
        .str(stream.stream.as_str())
        .digest(&stream.instance)
        .u64(through)
        .u64(last_record)
        .finish()
}

fn encode(stream: &StreamInstance, marks: Marks) -> [u8; SLOT_BYTES] {
    let through = value(marks.through);
    let last_record = value(marks.last_record);
    let mut slot = [0; SLOT_BYTES];
    slot[..8].copy_from_slice(&through.to_le_bytes());
    slot[8..16].copy_from_slice(&last_record.to_le_bytes());
    slot[16..].copy_from_slice(check(stream, through, last_record).as_bytes());
    slot
}

fn decode(stream: &StreamInstance, raw: &[u8]) -> Slot {
    if raw.iter().all(|byte| *byte == 0) {
        return Slot::Empty;
    }
    let number = |range: std::ops::Range<usize>| {
        raw.get(range)
            .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
            .map(u64::from_le_bytes)
    };
    let (Some(through), Some(last_record), Some(digest)) =
        (number(0..8), number(8..16), raw.get(16..SLOT_BYTES))
    else {
        return Slot::Spoiled;
    };
    if check(stream, through, last_record).as_bytes().as_slice() != digest || last_record > through
    {
        return Slot::Spoiled;
    }
    Slot::Marks(Marks {
        through: EventSequence::new(through),
        last_record: EventSequence::new(last_record),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::events::durable::DurableStreamId;

    fn stream() -> StreamInstance {
        StreamInstance::create(DurableStreamId::new("engine.audit").unwrap())
    }

    fn marks(through: u64, last_record: u64) -> Marks {
        Marks {
            through: EventSequence::new(through),
            last_record: EventSequence::new(last_record),
        }
    }

    fn reopen(directory: &Path, stream: &StreamInstance) -> Result<Marks, MarkProblem> {
        HighWater::open(directory, stream).map(|found| found.unwrap().marks())
    }

    fn spoil(directory: &Path, slot: usize) {
        let mut file = OpenOptions::new()
            .write(true)
            .open(directory.join(HIGH_WATER_FILE))
            .unwrap();
        file.seek(SeekFrom::Start(
            u64::try_from(slot * SLOT_SPAN + 3).unwrap(),
        ))
        .unwrap();
        file.write_all(&[0x5a]).unwrap();
    }

    #[test]
    fn marks_alternate_slots_and_survive_one_torn_slot() {
        let directory = tempfile::tempdir().unwrap();
        let stream = stream();
        assert!(HighWater::open(directory.path(), &stream)
            .unwrap()
            .is_none());
        let mut high_water = HighWater::create(directory.path()).unwrap();
        assert_eq!(reopen(directory.path(), &stream), Ok(Marks::default()));
        high_water.record(&stream, marks(1, 1)).unwrap();
        high_water.record(&stream, marks(2, 1)).unwrap();
        high_water.record(&stream, marks(5, 4)).unwrap();
        assert_eq!(reopen(directory.path(), &stream), Ok(marks(5, 4)));
        // The third write went to the first slot again; tearing it leaves the second.
        spoil(directory.path(), 0);
        assert_eq!(reopen(directory.path(), &stream), Ok(marks(2, 1)));
        // Both spoiled is damage, never an empty stream.
        spoil(directory.path(), 1);
        assert_eq!(reopen(directory.path(), &stream), Err(MarkProblem::Spoiled));
    }

    #[test]
    fn a_mark_of_another_stream_or_length_does_not_verify() {
        let directory = tempfile::tempdir().unwrap();
        let stream = stream();
        let mut high_water = HighWater::create(directory.path()).unwrap();
        high_water.record(&stream, marks(3, 3)).unwrap();
        high_water.record(&stream, marks(4, 3)).unwrap();
        assert_eq!(
            reopen(
                directory.path(),
                &StreamInstance::create(stream.stream.clone())
            ),
            Err(MarkProblem::Spoiled)
        );
        drop(high_water);
        let file = OpenOptions::new()
            .write(true)
            .open(directory.path().join(HIGH_WATER_FILE))
            .unwrap();
        file.set_len(512).unwrap();
        assert_eq!(
            reopen(directory.path(), &stream),
            Err(MarkProblem::Length { found: 512 })
        );
    }
}
