//! One bounded run of a VM-CP-12 scan and the report that states its coverage (§17, line
//! 3162: "The check states that it covers only the scanned locations"; VM-P12, line 2787:
//! "state the scan's limited coverage"; §8.1, line 2439).
//!
//! [`scan`] reads every named location through the [`ScanReader`] port: a file's bytes,
//! or every regular file in a directory's tree (each directory's files in name order,
//! then its subdirectories in name order, depth first), each streamed through the
//! [`Search`] in chunks of [`CHUNK_BYTES`]. Only file contents are searched, never names;
//! a directory whose listing holds a name that is not text is not read. A link is never followed and an entry that is neither a regular file nor
//! a directory is not read; either leaves a [`Gap`], as does an entry that could not be
//! read, a name that is not one plain path component, a directory deeper than the
//! limit, and the point where the run's byte or file budget ran out. Once a budget runs
//! out, nothing more is read in that run and every location not yet started is not
//! reached.
//!
//! The [`ScanReport`] states per location exactly what was read: the files read to
//! their end, the bytes searched, each finding (the entry, the encoding and the offset of
//! its first match) and each gap. A location is covered only when it has no gap; nothing
//! is claimed for what a gap left unread. The report never holds the fixture or any of
//! its forms.

use std::fmt;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use serde::Serialize;

use super::super::reader::{io_error, ReadError};
use super::fixture::Encoding;
use super::plan::{LocationRole, NamedLocation, ScanPlan};
use super::port::{EntryKind, ScanReader};
use super::search::Search;
use crate::foundation::evidence::CredentialScanSubject;

/// The bytes read from a file at a time.
pub const CHUNK_BYTES: usize = 64 * 1024;

/// The most findings and gaps one location's report lists; more are counted.
pub const MAX_LISTED: usize = 64;

/// The ceilings of [`ScanLimits::max_depth`] and [`ScanLimits::max_entries`].
pub const MAX_DEPTH_CEILING: usize = 64;
pub const MAX_ENTRIES_CEILING: usize = 65_536;

/// What every report states about its coverage.
pub const COVERAGE_NOTICE: &str = "This scan covers only the locations listed in it, and \
     of those only what it read: the contents of the regular files it read, searched for \
     the fixture credential's exact bytes and the encodings listed. A location with a gap \
     is not covered past it. Names, links, other entries, other locations, other \
     encodings and copies elsewhere, the guest's storage included, are not covered.";

/// The bounds of one run of a scan.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ScanLimits {
    /// The most bytes searched in one run, over all locations.
    pub max_bytes: u64,
    /// The most files opened in one run, over all locations.
    pub max_files: u64,
    /// The deepest directory read below a directory location (the location is depth 0).
    pub max_depth: usize,
    /// The most entries one directory read accepts.
    pub max_entries: usize,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_bytes: 256 * 1024 * 1024,
            max_files: 10_000,
            max_depth: 16,
            max_entries: 4096,
        }
    }
}

/// Why scan limits were refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "limit_error", rename_all = "snake_case")]
pub enum LimitError {
    /// A limit of zero would read nothing.
    Zero { limit: &'static str },
    /// A limit above its ceiling.
    AboveCeiling { limit: &'static str, ceiling: usize },
}

impl fmt::Display for LimitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero { limit } => write!(f, "the scan limit {limit} must not be zero"),
            Self::AboveCeiling { limit, ceiling } => {
                write!(f, "the scan limit {limit} must not exceed {ceiling}")
            }
        }
    }
}

impl std::error::Error for LimitError {}

impl ScanLimits {
    /// Refuses a zero limit and a depth or entry limit above its ceiling.
    pub fn check(&self) -> Result<(), LimitError> {
        let limits = [
            ("max_bytes", self.max_bytes),
            ("max_files", self.max_files),
            ("max_depth", self.max_depth as u64),
            ("max_entries", self.max_entries as u64),
        ];
        if let Some((limit, _)) = limits.into_iter().find(|(_, value)| *value == 0) {
            return Err(LimitError::Zero { limit });
        }
        if self.max_depth > MAX_DEPTH_CEILING {
            return Err(LimitError::AboveCeiling {
                limit: "max_depth",
                ceiling: MAX_DEPTH_CEILING,
            });
        }
        if self.max_entries > MAX_ENTRIES_CEILING {
            return Err(LimitError::AboveCeiling {
                limit: "max_entries",
                ceiling: MAX_ENTRIES_CEILING,
            });
        }
        Ok(())
    }
}

/// Where in a location the fixture was found: the entry's names below the location
/// (none for a file location), the encoding and the offset of its first match.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub entry: Vec<String>,
    pub encoding: Encoding,
    pub offset: u64,
}

/// Why part of a location was not read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "gap", rename_all = "snake_case")]
pub enum GapReason {
    /// The entry could not be read, or not to its end.
    Unreadable { error: ReadError },
    /// A symbolic link or junction, never followed.
    Link,
    /// Neither a regular file nor a directory.
    Other,
    /// A listed name that is not one plain path component.
    BadName,
    /// A directory deeper than the limit.
    TooDeep { limit: usize },
    /// The run's byte budget ran out inside this file.
    ByteBudget { limit: u64 },
    /// The run's file budget ran out at this file.
    FileBudget { limit: u64 },
    /// The run's budget ran out before this location was started.
    NotReached,
}

impl fmt::Display for GapReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable { error } => write!(f, "it could not be read: {error}"),
            Self::Link => f.write_str("it is a link, which is never followed"),
            Self::Other => f.write_str("it is neither a regular file nor a directory"),
            Self::BadName => f.write_str("its name is not one plain path component"),
            Self::TooDeep { limit } => {
                write!(f, "it is more than {limit} directories below the location")
            }
            Self::ByteBudget { limit } => {
                write!(f, "the run's budget of {limit} bytes ran out inside it")
            }
            Self::FileBudget { limit } => {
                write!(f, "the run's budget of {limit} files ran out at it")
            }
            Self::NotReached => f.write_str("the run's budget ran out before it was started"),
        }
    }
}

/// An entry not read, or not read to its end: its names below the location (none for
/// the location itself) and why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Gap {
    pub entry: Vec<String>,
    pub reason: GapReason,
}

/// What one run read of one named location.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LocationReport {
    pub role: LocationRole,
    pub path: String,
    /// Regular files read to their end.
    pub files_read: u64,
    /// Bytes searched, those of files not read to their end included.
    pub bytes_read: u64,
    /// The first [`MAX_LISTED`] findings, one per file and encoding.
    pub findings: Vec<Finding>,
    /// Findings beyond those listed.
    pub more_findings: u64,
    /// The first [`MAX_LISTED`] gaps.
    pub gaps: Vec<Gap>,
    /// Gaps beyond those listed.
    pub more_gaps: u64,
}

impl LocationReport {
    fn new(location: &NamedLocation) -> Self {
        Self {
            role: location.role,
            path: location.path_text().to_owned(),
            files_read: 0,
            bytes_read: 0,
            findings: Vec::new(),
            more_findings: 0,
            gaps: Vec::new(),
            more_gaps: 0,
        }
    }

    /// Whether every byte of the location was read: it has no gap.
    pub fn covered(&self) -> bool {
        self.gaps.is_empty() && self.more_gaps == 0
    }

    /// Whether the fixture was found in what was read.
    pub fn found(&self) -> bool {
        !self.findings.is_empty() || self.more_findings > 0
    }

    fn gap(&mut self, entry: &[String], reason: GapReason) {
        if self.gaps.len() < MAX_LISTED {
            self.gaps.push(Gap {
                entry: entry.to_vec(),
                reason,
            });
        } else {
            self.more_gaps += 1;
        }
    }

    fn finding(&mut self, entry: &[String], encoding: Encoding, offset: u64) {
        if self.findings.len() < MAX_LISTED {
            self.findings.push(Finding {
                entry: entry.to_vec(),
                encoding,
                offset,
            });
        } else {
            self.more_findings += 1;
        }
    }
}

/// What one run of a scan read and found, location by location in the plan's order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ScanReport {
    pub subject: CredentialScanSubject,
    /// Every form searched, in the order a shared form is attributed: the exact bytes,
    /// then each encoding.
    pub encodings: &'static [Encoding],
    pub limits: ScanLimits,
    pub locations: Vec<LocationReport>,
    pub notice: &'static str,
}

impl ScanReport {
    /// Whether every named location was read without a gap.
    pub fn covered(&self) -> bool {
        self.locations.iter().all(LocationReport::covered)
    }

    /// Whether the fixture is in `role`'s locations: `Some(true)` when it was found in
    /// what was read, `Some(false)` when every one of them was read without a gap, held
    /// at least one byte and showed no match, `None` otherwise.
    pub fn presence(&self, role: LocationRole) -> Option<bool> {
        let named: Vec<&LocationReport> = self
            .locations
            .iter()
            .filter(|location| location.role == role)
            .collect();
        if named.is_empty() {
            return None;
        }
        if named.iter().any(|location| location.found()) {
            return Some(true);
        }
        let covered = named.iter().all(|location| location.covered());
        let bytes: u64 = named.iter().map(|location| location.bytes_read).sum();
        (covered && bytes > 0).then_some(false)
    }
}

/// The run's remaining budget.
struct Budget {
    limits: ScanLimits,
    bytes: u64,
    files: u64,
    spent: bool,
}

/// Reads every location of `plan` through `reader` within `limits` and reports what it
/// read and found. The limits are taken as given; [`ScanLimits::check`] them first.
pub fn scan<R: ScanReader>(reader: &R, plan: &ScanPlan, limits: ScanLimits) -> ScanReport {
    let search = Search::new(plan.fixture());
    let mut walk = Walk {
        reader,
        search: &search,
        budget: Budget {
            limits,
            bytes: limits.max_bytes,
            files: limits.max_files,
            spent: false,
        },
        buffer: vec![0; CHUNK_BYTES],
    };
    let locations = plan
        .locations()
        .iter()
        .map(|location| walk.location(location))
        .collect();
    ScanReport {
        subject: plan.subject(),
        encodings: &Encoding::ALL,
        limits,
        locations,
        notice: COVERAGE_NOTICE,
    }
}

struct Walk<'a, R> {
    reader: &'a R,
    search: &'a Search,
    budget: Budget,
    buffer: Vec<u8>,
}

impl<R: ScanReader> Walk<'_, R> {
    fn location(&mut self, location: &NamedLocation) -> LocationReport {
        let mut report = LocationReport::new(location);
        if self.budget.spent {
            report.gap(&[], GapReason::NotReached);
            return report;
        }
        match self.reader.entry(&location.path) {
            Err(error) => report.gap(&[], GapReason::Unreadable { error }),
            Ok(EntryKind::File) => self.file(&location.path, &[], &mut report),
            Ok(EntryKind::Directory) => self.tree(&location.path, &mut report),
            Ok(EntryKind::Link) => report.gap(&[], GapReason::Link),
            Ok(EntryKind::Other) => report.gap(&[], GapReason::Other),
        }
        report
    }

    /// Every regular file below the directory `root`: each directory's files in name
    /// order, then its subdirectories in name order, depth first.
    fn tree(&mut self, root: &Path, report: &mut LocationReport) {
        let mut pending: Vec<(PathBuf, Vec<String>)> = vec![(root.to_path_buf(), Vec::new())];
        while let Some((directory, entry)) = pending.pop() {
            let names = match self.reader.list(&directory, self.budget.limits.max_entries) {
                Ok(names) => names,
                Err(error) => {
                    report.gap(&entry, GapReason::Unreadable { error });
                    continue;
                }
            };
            let mut below = Vec::new();
            for name in names {
                let mut child = entry.clone();
                child.push(name.clone());
                if !plain_name(&name) {
                    report.gap(&child, GapReason::BadName);
                    continue;
                }
                let path = directory.join(&name);
                match self.reader.entry(&path) {
                    Err(error) => report.gap(&child, GapReason::Unreadable { error }),
                    Ok(EntryKind::File) => self.file(&path, &child, report),
                    Ok(EntryKind::Directory) if child.len() > self.budget.limits.max_depth => {
                        report.gap(
                            &child,
                            GapReason::TooDeep {
                                limit: self.budget.limits.max_depth,
                            },
                        );
                    }
                    Ok(EntryKind::Directory) => below.push((path, child)),
                    Ok(EntryKind::Link) => report.gap(&child, GapReason::Link),
                    Ok(EntryKind::Other) => report.gap(&child, GapReason::Other),
                }
                if self.budget.spent {
                    return;
                }
            }
            pending.extend(below.into_iter().rev());
        }
    }

    /// The regular file at `path`, searched to its end or until the budget runs out.
    fn file(&mut self, path: &Path, entry: &[String], report: &mut LocationReport) {
        if self.budget.files == 0 {
            self.budget.spent = true;
            let limit = self.budget.limits.max_files;
            report.gap(entry, GapReason::FileBudget { limit });
            return;
        }
        self.budget.files -= 1;
        let mut file = match self.reader.open(path) {
            Ok(file) => file,
            Err(error) => {
                report.gap(entry, GapReason::Unreadable { error });
                return;
            }
        };
        let search = self.search;
        let mut matcher = search.matcher();
        let ended = loop {
            let room = usize::try_from(self.budget.bytes)
                .unwrap_or(usize::MAX)
                .min(self.buffer.len());
            if room == 0 {
                let mut probe = [0u8; 1];
                break match file.read(&mut probe) {
                    Ok(0) => Ok(()),
                    Ok(_) => {
                        self.budget.spent = true;
                        let limit = self.budget.limits.max_bytes;
                        Err(GapReason::ByteBudget { limit })
                    }
                    Err(error) => Err(GapReason::Unreadable {
                        error: io_error(error),
                    }),
                };
            }
            match file.read(&mut self.buffer[..room]) {
                Ok(0) => break Ok(()),
                Ok(read) => {
                    let read = read.min(room);
                    matcher.feed(&self.buffer[..read]);
                    self.budget.bytes -= read as u64;
                }
                Err(error) => {
                    break Err(GapReason::Unreadable {
                        error: io_error(error),
                    })
                }
            }
        };
        report.bytes_read += matcher.offset();
        for (encoding, offset) in matcher.found() {
            report.finding(entry, encoding, offset);
        }
        match ended {
            Ok(()) => report.files_read += 1,
            Err(reason) => report.gap(entry, reason),
        }
    }
}

/// Whether `name` is one plain path component, as a directory listing must give it.
fn plain_name(name: &str) -> bool {
    let mut components = Path::new(name).components();
    matches!(components.next(), Some(Component::Normal(only)) if only == name)
        && components.next().is_none()
        && !name.contains(['/', '\\'])
}
