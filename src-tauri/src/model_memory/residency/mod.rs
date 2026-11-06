//! Model-side admission and retention: GPU §2.7 and the §1.1 rows at lines 304 and 307 of
//! docs/combined-gpu-memory-and-vm-sandbox-plan.md.
//!
//! - [`vram`]: the §2.7 inequality for each device and each time interval. Physically
//!   shared weights count once, each process's contexts, KV and scratch count separately,
//!   KV must be bounded, and piecewise demand catches transient peaks.
//! - [`host`]: the same accounting for host RAM, pinned RAM, cgroups and the WSL VM. Page
//!   cache is not free, reclaimable memory is not guaranteed residency, mincore is
//!   advisory, and an address reservation supplies no physical capacity.
//! - [`eviction`]: a clean GPU copy is dropped without copying it back only when a verified
//!   reconstructible copy exists (line 307).
//! - [`retention`]: size-constrained caching with shared prerequisites: LRU, cost per byte,
//!   marginal saved latency per retained byte and GreedyDual-Size/Landlord, with shared
//!   bases charged once, pinned objects and session leases (§2.7, line 304).
//! - [`simulator`]: a deterministic trace simulator that compares the policies by hit rate,
//!   saved latency and bytes moved.
//! - [`reservation`]: the thin adapter that turns admitted plans into one CORE-03 ledger
//!   reservation request of peak amounts and hands it to the ledger.
//!
//! This module computes model-side demand and fit only. The CORE-03 host ledger stays the
//! capacity authority (S3.2; §3.1, line 491): every capacity arrives as an input, nothing
//! here keeps global state, and a fit is the content of a reservation request, never a
//! grant; only the ledger reserves.
//!
//! Bytes are `u64` and every sum is checked; latencies are finite `f64` seconds; time is a
//! [`MonotonicTime`] read from a [`Clock`](crate::foundation::ids::Clock).

use std::fmt;

use serde::Serialize;

use crate::foundation::ids::MonotonicTime;

pub mod eviction;
pub mod host;
pub mod reservation;
pub mod retention;
pub mod simulator;
pub mod vram;

/// Why an input was refused before any accounting ran.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InputError {
    /// An interval does not end after it starts.
    EmptyInterval {
        start: MonotonicTime,
        end: MonotonicTime,
    },
    /// A name is empty.
    EmptyName { field: &'static str },
    /// A name appears twice where each must be unique.
    Duplicate { field: &'static str, name: String },
    /// A name refers to nothing that was declared.
    Unknown { field: &'static str, name: String },
    /// A value that must be more than zero is not.
    NotPositive { field: &'static str },
    /// A number is NaN or infinite.
    NotFinite { field: &'static str },
    /// A number that must be zero or more is negative.
    Negative { field: &'static str },
    /// A value lies outside the range this module accepts.
    OutOfRange { field: &'static str },
    /// A byte total, count or time does not fit in 64 bits.
    Overflow { field: &'static str },
    /// References form a cycle, such as an object that is its own prerequisite.
    Cycle { field: &'static str, name: String },
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInterval { start, end } => write!(
                f,
                "the interval [{}, {}) ns does not end after it starts",
                start.as_nanos(),
                end.as_nanos()
            ),
            Self::EmptyName { field } => write!(f, "{field} is empty"),
            Self::Duplicate { field, name } => write!(f, "{field} lists {name:?} twice"),
            Self::Unknown { field, name } => write!(f, "{field} names unknown {name:?}"),
            Self::NotPositive { field } => write!(f, "{field} must be more than zero"),
            Self::NotFinite { field } => write!(f, "{field} is not a finite number"),
            Self::Negative { field } => write!(f, "{field} is negative"),
            Self::OutOfRange { field } => write!(f, "{field} is out of range"),
            Self::Overflow { field } => write!(f, "{field} does not fit in 64 bits"),
            Self::Cycle { field, name } => write!(f, "{field} forms a cycle through {name:?}"),
        }
    }
}

impl std::error::Error for InputError {}

/// A half-open time interval `[start, end)` on one monotonic clock; never empty.
///
/// GPU §2.7 checks admission "for each device and time interval": demand is declared
/// over intervals and checked on every piece of time they cut.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Interval {
    start: MonotonicTime,
    end: MonotonicTime,
}

impl Interval {
    /// `[start, end)`, refused unless `start < end`.
    pub fn new(start: MonotonicTime, end: MonotonicTime) -> Result<Self, InputError> {
        if start < end {
            Ok(Self { start, end })
        } else {
            Err(InputError::EmptyInterval { start, end })
        }
    }

    pub const fn start(&self) -> MonotonicTime {
        self.start
    }

    pub const fn end(&self) -> MonotonicTime {
        self.end
    }

    pub const fn length_nanos(&self) -> u64 {
        self.end.as_nanos().saturating_sub(self.start.as_nanos())
    }

    /// Whether the two intervals share any instant.
    pub fn overlaps(&self, other: &Interval) -> bool {
        self.start < other.end && other.start < self.end
    }

    /// Whether `other` lies entirely inside this interval.
    pub fn contains(&self, other: &Interval) -> bool {
        self.start <= other.start && other.end <= self.end
    }
}

/// A capacity figure and what backs it (GPU §2.7, §3.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Capacity {
    /// A limit on physical bytes: a ledger sub-budget, a device's usable VRAM, a cgroup
    /// `memory.max`, a pinned-memory cap or the WSL VM's memory setting.
    Physical { bytes: u64 },
    /// Reserved address space only, such as a CUDA virtual address range or a
    /// `MAP_NORESERVE` mapping. It supplies no physical capacity (§2.7), so admission
    /// refuses it as a capacity.
    VirtualReservation { bytes: u64 },
}

impl Capacity {
    /// The physical bytes; `None` for an address reservation, which supplies none.
    pub const fn physical_bytes(self) -> Option<u64> {
        match self {
            Self::Physical { bytes } => Some(bytes),
            Self::VirtualReservation { .. } => None,
        }
    }
}

/// The pieces of time cut at every start and end in `intervals`, keeping the pieces that
/// at least one interval covers, in time order. Each interval covers a piece entirely or
/// not at all, so piecewise-constant demand is constant on every piece (GPU §2.7).
pub(crate) fn pieces(intervals: &[Interval]) -> Vec<Interval> {
    let mut points: Vec<MonotonicTime> = intervals
        .iter()
        .flat_map(|interval| [interval.start, interval.end])
        .collect();
    points.sort_unstable();
    points.dedup();
    points
        .windows(2)
        .filter_map(|pair| match pair {
            [start, end] => Some(Interval {
                start: *start,
                end: *end,
            }),
            _ => None,
        })
        .filter(|piece| intervals.iter().any(|interval| interval.overlaps(piece)))
        .collect()
}

/// The time-weighted mean of piecewise byte totals, rounded down; `None` without pieces
/// or if the weighted sum does not fit in 128 bits.
pub(crate) fn time_weighted_average(pieces: impl Iterator<Item = (Interval, u64)>) -> Option<u64> {
    let mut weighted: u128 = 0;
    let mut nanos: u128 = 0;
    for (piece, bytes) in pieces {
        let length = u128::from(piece.length_nanos());
        weighted = weighted.checked_add(u128::from(bytes).checked_mul(length)?)?;
        nanos = nanos.checked_add(length)?;
    }
    weighted
        .checked_div(nanos)
        .and_then(|mean| u64::try_from(mean).ok())
}

pub(crate) fn check_name(field: &'static str, name: &str) -> Result<(), InputError> {
    if name.is_empty() {
        Err(InputError::EmptyName { field })
    } else {
        Ok(())
    }
}

/// A finite number of seconds, zero or more.
pub(crate) fn check_seconds(field: &'static str, seconds: f64) -> Result<f64, InputError> {
    if !seconds.is_finite() {
        Err(InputError::NotFinite { field })
    } else if seconds < 0.0 {
        Err(InputError::Negative { field })
    } else {
        Ok(seconds)
    }
}

pub(crate) fn add_bytes(field: &'static str, total: u64, bytes: u64) -> Result<u64, InputError> {
    total
        .checked_add(bytes)
        .ok_or(InputError::Overflow { field })
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::Interval;
    use crate::foundation::ids::{digest, Digest, GpuDeviceKey, MonotonicTime};

    /// Decimal gigabyte, as the plan writes "14 GB" and "24 GB".
    pub const GB: u64 = 1_000_000_000;
    pub const MB: u64 = 1_000_000;
    /// Binary gibibyte, so retention arithmetic in tests stays exact.
    pub const GIB: u64 = 1 << 30;

    pub fn at(seconds: u64) -> MonotonicTime {
        MonotonicTime::from_nanos(seconds * 1_000_000_000)
    }

    pub fn span(start_seconds: u64, end_seconds: u64) -> Interval {
        Interval::new(at(start_seconds), at(end_seconds)).unwrap()
    }

    /// The test host's identity digest.
    pub fn machine() -> Digest {
        digest("yougori/test/residency/machine/v1", &[b"host-1"])
    }

    /// A GPU on the test host.
    pub fn gpu(name: &str) -> GpuDeviceKey {
        GpuDeviceKey {
            machine: machine(),
            device: digest("yougori/test/residency/device/v1", &[name.as_bytes()]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{at, span};
    use super::*;

    #[test]
    fn an_interval_must_end_after_it_starts() {
        assert_eq!(
            Interval::new(at(5), at(5)),
            Err(InputError::EmptyInterval {
                start: at(5),
                end: at(5)
            })
        );
        assert!(Interval::new(at(6), at(5)).is_err());
        let interval = span(2, 7);
        assert_eq!(interval.length_nanos(), 5_000_000_000);
        assert!(interval.contains(&span(2, 7)));
        assert!(interval.contains(&span(3, 4)));
        assert!(!interval.contains(&span(1, 4)));
        // Half-open: [2, 7) and [7, 9) share no instant.
        assert!(!interval.overlaps(&span(7, 9)));
        assert!(interval.overlaps(&span(6, 9)));
    }

    #[test]
    fn pieces_are_cut_at_every_boundary_and_skip_gaps() {
        let cut = pieces(&[span(0, 10), span(4, 5), span(20, 30)]);
        assert_eq!(cut, vec![span(0, 4), span(4, 5), span(5, 10), span(20, 30)]);
        assert!(pieces(&[]).is_empty());
    }

    #[test]
    fn the_average_weights_each_piece_by_its_length() {
        let average = time_weighted_average([(span(0, 9), 10), (span(9, 10), 100)].into_iter());
        // (9 × 10 + 1 × 100) / 10 = 19.
        assert_eq!(average, Some(19));
        assert_eq!(time_weighted_average(std::iter::empty()), None);
    }

    #[test]
    fn an_address_reservation_supplies_no_physical_capacity() {
        assert_eq!(Capacity::Physical { bytes: 7 }.physical_bytes(), Some(7));
        assert_eq!(
            Capacity::VirtualReservation { bytes: u64::MAX }.physical_bytes(),
            None
        );
    }

    #[test]
    fn seconds_must_be_finite_and_not_negative() {
        assert_eq!(check_seconds("t", 1.5), Ok(1.5));
        assert_eq!(
            check_seconds("t", f64::NAN),
            Err(InputError::NotFinite { field: "t" })
        );
        assert_eq!(
            check_seconds("t", -0.1),
            Err(InputError::Negative { field: "t" })
        );
        assert_eq!(
            add_bytes("b", u64::MAX, 1),
            Err(InputError::Overflow { field: "b" })
        );
    }
}
