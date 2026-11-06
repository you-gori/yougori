//! Byte ranges and canonical range sets: the range part of a transfer's scope and the
//! verified extents a retry reuses (S2 CORE-05 "object/range scope"; CORE-02 "resumable
//! verified data").

use std::fmt;

use serde::{Deserialize, Serialize};

/// Why a byte range or range set was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RangeError {
    /// A range must hold at least one byte.
    Empty {
        at_bytes: u64,
    },
    Reversed {
        start_bytes: u64,
        end_bytes: u64,
    },
    /// The end of the range does not fit in 64 bits.
    Overflow {
        start_bytes: u64,
        length_bytes: u64,
    },
    /// A serialized range set must be sorted, with gaps between its ranges, so one set
    /// has exactly one encoding.
    NotCanonical,
}

impl fmt::Display for RangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty { at_bytes } => write!(f, "the byte range at {at_bytes} is empty"),
            Self::Reversed {
                start_bytes,
                end_bytes,
            } => write!(
                f,
                "the byte range ends at {end_bytes}, before its start at {start_bytes}"
            ),
            Self::Overflow {
                start_bytes,
                length_bytes,
            } => write!(
                f,
                "{length_bytes} bytes from {start_bytes} run past the largest offset"
            ),
            Self::NotCanonical => f.write_str(
                "the ranges must be sorted, must not overlap and must not touch; merge them",
            ),
        }
    }
}

impl std::error::Error for RangeError {}

/// A non-empty, half-open range of byte offsets `[start_bytes, end_bytes)` in one object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "RawByteRange", into = "RawByteRange")]
pub struct ByteRange {
    start_bytes: u64,
    end_bytes: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawByteRange {
    start_bytes: u64,
    end_bytes: u64,
}

impl TryFrom<RawByteRange> for ByteRange {
    type Error = RangeError;

    fn try_from(raw: RawByteRange) -> Result<Self, Self::Error> {
        Self::new(raw.start_bytes, raw.end_bytes)
    }
}

impl From<ByteRange> for RawByteRange {
    fn from(range: ByteRange) -> Self {
        Self {
            start_bytes: range.start_bytes,
            end_bytes: range.end_bytes,
        }
    }
}

impl ByteRange {
    /// The bytes from `start_bytes` up to, not including, `end_bytes`.
    pub fn new(start_bytes: u64, end_bytes: u64) -> Result<Self, RangeError> {
        if start_bytes == end_bytes {
            return Err(RangeError::Empty {
                at_bytes: start_bytes,
            });
        }
        if end_bytes < start_bytes {
            return Err(RangeError::Reversed {
                start_bytes,
                end_bytes,
            });
        }
        Ok(Self {
            start_bytes,
            end_bytes,
        })
    }

    /// `length_bytes` bytes starting at `start_bytes`.
    pub fn starting_at(start_bytes: u64, length_bytes: u64) -> Result<Self, RangeError> {
        let end_bytes = start_bytes
            .checked_add(length_bytes)
            .ok_or(RangeError::Overflow {
                start_bytes,
                length_bytes,
            })?;
        Self::new(start_bytes, end_bytes)
    }

    pub const fn start_bytes(self) -> u64 {
        self.start_bytes
    }

    /// The first offset after the range.
    pub const fn end_bytes(self) -> u64 {
        self.end_bytes
    }

    pub const fn length_bytes(self) -> u64 {
        self.end_bytes.saturating_sub(self.start_bytes)
    }

    pub const fn overlaps(self, other: ByteRange) -> bool {
        self.start_bytes < other.end_bytes && other.start_bytes < self.end_bytes
    }
}

impl fmt::Display for ByteRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bytes {}..{}", self.start_bytes, self.end_bytes)
    }
}

/// A set of byte offsets, kept as sorted ranges with gaps between them, so equal sets are
/// equal values and have one serialized form.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "Vec<ByteRange>", into = "Vec<ByteRange>")]
pub struct RangeSet {
    ranges: Vec<ByteRange>,
}

impl TryFrom<Vec<ByteRange>> for RangeSet {
    type Error = RangeError;

    /// Only the canonical form is accepted; [`RangeSet::from_ranges`] merges instead.
    fn try_from(ranges: Vec<ByteRange>) -> Result<Self, Self::Error> {
        let canonical = ranges
            .windows(2)
            .all(|pair| matches!(pair, [left, right] if left.end_bytes < right.start_bytes));
        if canonical {
            Ok(Self { ranges })
        } else {
            Err(RangeError::NotCanonical)
        }
    }
}

impl From<RangeSet> for Vec<ByteRange> {
    fn from(set: RangeSet) -> Self {
        set.ranges
    }
}

impl RangeSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// The union of `ranges`, in any order, merging overlapping and touching ranges.
    pub fn from_ranges(ranges: impl IntoIterator<Item = ByteRange>) -> Self {
        let mut ranges: Vec<ByteRange> = ranges.into_iter().collect();
        ranges.sort_unstable();
        let mut merged: Vec<ByteRange> = Vec::with_capacity(ranges.len());
        for range in ranges {
            match merged.last_mut() {
                Some(last) if range.start_bytes <= last.end_bytes => {
                    last.end_bytes = last.end_bytes.max(range.end_bytes);
                }
                _ => merged.push(range),
            }
        }
        Self { ranges: merged }
    }

    pub fn single(range: ByteRange) -> Self {
        Self {
            ranges: vec![range],
        }
    }

    pub fn ranges(&self) -> &[ByteRange] {
        &self.ranges
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// The number of offsets in the set. The ranges are disjoint offsets below
    /// `u64::MAX`, so the sum cannot overflow.
    pub fn total_bytes(&self) -> u64 {
        self.ranges.iter().fold(0u64, |total, range| {
            total.saturating_add(range.length_bytes())
        })
    }

    /// The first offset after the last range; `None` for the empty set.
    pub fn end_bytes(&self) -> Option<u64> {
        self.ranges.last().map(|range| range.end_bytes)
    }

    pub fn insert(&mut self, range: ByteRange) {
        let mut ranges = std::mem::take(&mut self.ranges);
        ranges.push(range);
        *self = Self::from_ranges(ranges);
    }

    /// Whether every offset of `range` is in the set.
    pub fn covers(&self, range: ByteRange) -> bool {
        self.ranges.iter().any(|member| {
            member.start_bytes <= range.start_bytes && range.end_bytes <= member.end_bytes
        })
    }

    /// Whether any offset of `range` is in the set.
    pub fn overlaps(&self, range: ByteRange) -> bool {
        self.ranges.iter().any(|member| member.overlaps(range))
    }

    pub fn is_subset_of(&self, other: &RangeSet) -> bool {
        self.ranges.iter().all(|range| other.covers(*range))
    }

    pub fn union(&self, other: &RangeSet) -> RangeSet {
        Self::from_ranges(self.ranges.iter().chain(&other.ranges).copied())
    }

    pub fn intersection(&self, other: &RangeSet) -> RangeSet {
        let mut pieces = Vec::new();
        let mut left = self.ranges.iter().peekable();
        let mut right = other.ranges.iter().peekable();
        while let (Some(&&l), Some(&&r)) = (left.peek(), right.peek()) {
            let start_bytes = l.start_bytes.max(r.start_bytes);
            let end_bytes = l.end_bytes.min(r.end_bytes);
            if start_bytes < end_bytes {
                pieces.push(ByteRange {
                    start_bytes,
                    end_bytes,
                });
            }
            if l.end_bytes < r.end_bytes {
                left.next();
            } else {
                right.next();
            }
        }
        Self::from_ranges(pieces)
    }

    /// The offsets of `self` that are not in `other`.
    pub fn difference(&self, other: &RangeSet) -> RangeSet {
        let mut pieces = Vec::new();
        for range in &self.ranges {
            let mut start_bytes = range.start_bytes;
            for cut in &other.ranges {
                if cut.end_bytes <= start_bytes {
                    continue;
                }
                if cut.start_bytes >= range.end_bytes {
                    break;
                }
                if cut.start_bytes > start_bytes {
                    pieces.push(ByteRange {
                        start_bytes,
                        end_bytes: cut.start_bytes,
                    });
                }
                start_bytes = cut.end_bytes;
                if start_bytes >= range.end_bytes {
                    break;
                }
            }
            if start_bytes < range.end_bytes {
                pieces.push(ByteRange {
                    start_bytes,
                    end_bytes: range.end_bytes,
                });
            }
        }
        Self::from_ranges(pieces)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(start_bytes: u64, end_bytes: u64) -> ByteRange {
        ByteRange::new(start_bytes, end_bytes).unwrap()
    }

    fn set(pairs: &[(u64, u64)]) -> RangeSet {
        RangeSet::from_ranges(pairs.iter().map(|&(start, end)| range(start, end)))
    }

    #[test]
    fn ranges_are_non_empty_and_ordered() {
        assert_eq!(ByteRange::new(5, 5), Err(RangeError::Empty { at_bytes: 5 }));
        assert_eq!(
            ByteRange::new(6, 5),
            Err(RangeError::Reversed {
                start_bytes: 6,
                end_bytes: 5
            })
        );
        assert_eq!(range(5, 9).length_bytes(), 4);
        assert_eq!(ByteRange::starting_at(5, 4), Ok(range(5, 9)));
        assert_eq!(
            ByteRange::starting_at(u64::MAX, 1),
            Err(RangeError::Overflow {
                start_bytes: u64::MAX,
                length_bytes: 1
            })
        );
        assert_eq!(
            ByteRange::starting_at(3, 0),
            Err(RangeError::Empty { at_bytes: 3 })
        );
        assert!(range(0, 10).overlaps(range(9, 12)));
        assert!(!range(0, 10).overlaps(range(10, 12)));
    }

    #[test]
    fn sets_merge_overlapping_and_touching_ranges() {
        let merged = set(&[(20, 30), (0, 10), (10, 12), (25, 40), (50, 60)]);
        assert_eq!(
            merged.ranges(),
            [range(0, 12), range(20, 40), range(50, 60)]
        );
        assert_eq!(merged.total_bytes(), 12 + 20 + 10);
        assert_eq!(merged.end_bytes(), Some(60));
        assert_eq!(RangeSet::new().end_bytes(), None);
        let mut grown = merged.clone();
        grown.insert(range(12, 20));
        assert_eq!(grown.ranges(), [range(0, 40), range(50, 60)]);
    }

    #[test]
    fn covering_overlap_and_subsets() {
        let granted = set(&[(0, 100), (200, 300)]);
        assert!(granted.covers(range(0, 100)));
        assert!(granted.covers(range(250, 260)));
        assert!(!granted.covers(range(90, 210)));
        assert!(!granted.covers(range(300, 301)));
        assert!(granted.overlaps(range(90, 210)));
        assert!(!granted.overlaps(range(100, 200)));
        assert!(set(&[(10, 20), (210, 220)]).is_subset_of(&granted));
        assert!(!set(&[(10, 20), (100, 101)]).is_subset_of(&granted));
        assert!(RangeSet::new().is_subset_of(&granted));
    }

    #[test]
    fn union_intersection_and_difference() {
        let a = set(&[(0, 10), (20, 30)]);
        let b = set(&[(5, 25), (40, 50)]);
        assert_eq!(a.union(&b), set(&[(0, 30), (40, 50)]));
        assert_eq!(a.intersection(&b), set(&[(5, 10), (20, 25)]));
        assert_eq!(a.difference(&b), set(&[(0, 5), (25, 30)]));
        assert_eq!(b.difference(&a), set(&[(10, 20), (40, 50)]));
        assert_eq!(a.difference(&a), RangeSet::new());
        assert_eq!(a.difference(&RangeSet::new()), a);
        let whole = set(&[(0, 100)]);
        let holes = set(&[(0, 10), (20, 30), (90, 100)]);
        assert_eq!(whole.difference(&holes), set(&[(10, 20), (30, 90)]));
        assert_eq!(
            whole.difference(&holes).total_bytes() + holes.total_bytes(),
            100
        );
    }

    #[test]
    fn serialized_sets_must_be_canonical() {
        let canonical = set(&[(0, 10), (20, 30)]);
        let json = serde_json::to_string(&canonical).unwrap();
        assert_eq!(
            json,
            r#"[{"start_bytes":0,"end_bytes":10},{"start_bytes":20,"end_bytes":30}]"#
        );
        assert_eq!(serde_json::from_str::<RangeSet>(&json).unwrap(), canonical);
        for refused in [
            r#"[{"start_bytes":20,"end_bytes":30},{"start_bytes":0,"end_bytes":10}]"#,
            r#"[{"start_bytes":0,"end_bytes":10},{"start_bytes":10,"end_bytes":30}]"#,
            r#"[{"start_bytes":0,"end_bytes":10},{"start_bytes":5,"end_bytes":30}]"#,
            r#"[{"start_bytes":10,"end_bytes":10}]"#,
            r#"[{"start_bytes":10,"end_bytes":5}]"#,
            r#"[{"start_bytes":0,"end_bytes":10,"extra":1}]"#,
        ] {
            assert!(
                serde_json::from_str::<RangeSet>(refused).is_err(),
                "{refused}"
            );
        }
    }
}
