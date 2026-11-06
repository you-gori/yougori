//! Representation selection under contention (GPU §4.9, plan lines 740–750; GPU-W08;
//! GPU-T36).
//!
//! For each artifact range, raw or compressed transfer is chosen from the remaining link
//! time, the decoder work, scratch, compute interference and which representations the
//! source has. The serial model is §2.8's, evaluated per range through
//! [`CompressionCase`]. The pipelined model generalizes §2.8's bulk term
//! `max(r·S/B, S/D)` to several ranges sharing one link and one decoder: the link carries
//! raw and encoded ranges, the decoder only encoded ones, and the fixed overhead is
//! charged outside the maximum as [`CompressionCase::pipelined_estimate`] does, so one
//! compressed range gives exactly that estimate.
//!
//! Decoder interference is a hard foreground budget (GPU-T36) and also part of the
//! objective, `completion + interference`. Comparisons with DFloat11 and ZipNN/nvCOMP are
//! recorded as unavailable ([`EXTERNAL_COMPARISONS`]), not invented.

use std::fmt;

use crate::foundation::report::BaselineUnavailable;
use crate::model_memory::math::compression::{CompressionCase, CompressionError};
use crate::model_memory::math::{non_negative, positive, InputError};

/// Ranges [`select_exhaustive`] accepts: 2^16 assignments.
pub const MAX_ORACLE_RANGES: usize = 16;

/// Why a selection was refused.
#[derive(Clone, Debug, PartialEq)]
pub enum SelectionError {
    Input(InputError),
    Compression(CompressionError),
    NoRanges,
    /// The range has neither an available raw copy nor a usable compressed form.
    NoUsableRepresentation {
        range: usize,
    },
    /// An assignment uses a representation the range cannot use.
    Infeasible {
        range: usize,
    },
    /// Ranges that must be decoded already exceed the foreground budget (GPU-T36).
    ForegroundBudgetExceeded {
        interference_seconds: f64,
        budget_seconds: f64,
    },
    TooManyRangesForOracle {
        ranges: usize,
        max: usize,
    },
    LengthMismatch {
        ranges: usize,
        choices: usize,
    },
}

impl From<InputError> for SelectionError {
    fn from(error: InputError) -> Self {
        Self::Input(error)
    }
}

impl From<CompressionError> for SelectionError {
    fn from(error: CompressionError) -> Self {
        Self::Compression(error)
    }
}

impl fmt::Display for SelectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(error) => error.fmt(f),
            Self::Compression(error) => error.fmt(f),
            Self::NoRanges => f.write_str("no ranges to select for"),
            Self::NoUsableRepresentation { range } => {
                write!(f, "range {range} has no usable representation")
            }
            Self::Infeasible { range } => {
                write!(f, "range {range} cannot use the assigned representation")
            }
            Self::ForegroundBudgetExceeded {
                interference_seconds,
                budget_seconds,
            } => write!(
                f,
                "decoding needs {interference_seconds} s of foreground time; the budget is \
                 {budget_seconds} s"
            ),
            Self::TooManyRangesForOracle { ranges, max } => {
                write!(f, "{ranges} ranges exceed the oracle's {max}")
            }
            Self::LengthMismatch { ranges, choices } => {
                write!(f, "{choices} choices for {ranges} ranges")
            }
        }
    }
}

impl std::error::Error for SelectionError {}

/// A compressed representation of one range, as prepared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompressedForm {
    pub stored_bytes: u64,
    /// Headers, offsets and checksums sent with it.
    pub metadata_bytes: u64,
    /// Scratch the decoder needs while it decodes this range.
    pub scratch_bytes: u64,
}

impl CompressedForm {
    fn link_bytes(&self) -> u64 {
        self.stored_bytes.saturating_add(self.metadata_bytes)
    }
}

/// One artifact range and the representations its source can serve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RangeCandidate {
    pub raw_bytes: u64,
    /// The source holds the raw bytes.
    pub raw_available: bool,
    /// The source holds a compressed form; `None` for a raw escape block or an
    /// unprepared range.
    pub compressed: Option<CompressedForm>,
}

/// Which §2.8 model the selection uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CostModel {
    /// Transfer, then decode, range after range.
    Serial,
    /// Independently decodable ranges: transfer and decoding overlap.
    Pipelined,
}

/// The current bottleneck state (GPU §4.9 line 744).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Conditions {
    /// Link capacity left for this transfer.
    pub link_bytes_per_second: f64,
    /// Link time already committed to other transfers.
    pub link_backlog_seconds: f64,
    /// Decoder throughput in raw bytes per second, after interference.
    pub decoder_raw_bytes_per_second: f64,
    /// Decoder work already queued.
    pub decoder_backlog_seconds: f64,
    /// `o` of each compressed range.
    pub overhead_seconds_per_compressed_range: f64,
    /// Pipeline fill and drain when any range is decoded (pipelined model only).
    pub fill_drain_seconds: f64,
    pub scratch_available_bytes: u64,
    /// Foreground delay each decoded byte causes.
    pub interference_seconds_per_decoded_byte: f64,
    /// The most foreground delay decoding may cause (GPU-T36).
    pub foreground_budget_seconds: f64,
    pub model: CostModel,
}

/// The representation used for one range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Representation {
    Raw,
    Compressed,
}

/// An assignment and its estimated cost.
#[derive(Clone, Debug, PartialEq)]
pub struct Selection {
    pub choices: Vec<Representation>,
    pub link_seconds: f64,
    pub decoder_seconds: f64,
    pub completion_seconds: f64,
    pub interference_seconds: f64,
    /// `completion + interference`, the quantity minimized.
    pub objective_seconds: f64,
}

impl Selection {
    /// Ranges sent compressed.
    pub fn compressed_ranges(&self) -> usize {
        self.choices
            .iter()
            .filter(|choice| **choice == Representation::Compressed)
            .count()
    }
}

struct Checked {
    link: f64,
    link_backlog: f64,
    decoder: f64,
    decoder_backlog: f64,
    overhead: f64,
    fill_drain: f64,
    interference: f64,
    budget: f64,
}

fn check(conditions: &Conditions) -> Result<Checked, SelectionError> {
    Ok(Checked {
        link: positive("link_bytes_per_second", conditions.link_bytes_per_second)?,
        link_backlog: non_negative("link_backlog_seconds", conditions.link_backlog_seconds)?,
        decoder: positive(
            "decoder_raw_bytes_per_second",
            conditions.decoder_raw_bytes_per_second,
        )?,
        decoder_backlog: non_negative(
            "decoder_backlog_seconds",
            conditions.decoder_backlog_seconds,
        )?,
        overhead: non_negative(
            "overhead_seconds_per_compressed_range",
            conditions.overhead_seconds_per_compressed_range,
        )?,
        fill_drain: non_negative("fill_drain_seconds", conditions.fill_drain_seconds)?,
        interference: non_negative(
            "interference_seconds_per_decoded_byte",
            conditions.interference_seconds_per_decoded_byte,
        )?,
        budget: non_negative(
            "foreground_budget_seconds",
            conditions.foreground_budget_seconds,
        )?,
    })
}

fn compressed_usable(range: &RangeCandidate, conditions: &Conditions) -> bool {
    range
        .compressed
        .is_some_and(|form| form.scratch_bytes <= conditions.scratch_available_bytes)
}

/// The §2.8 serial case of one range: `S`, `r = (encoded + metadata)/S`, `B`, `D`, `o`.
fn serial_case(
    range: &RangeCandidate,
    form: &CompressedForm,
    checked: &Checked,
) -> Result<CompressionCase, SelectionError> {
    let compressed_fraction = form.link_bytes() as f64 / range.raw_bytes as f64;
    Ok(CompressionCase::new(
        range.raw_bytes,
        compressed_fraction,
        checked.link,
        checked.decoder,
        checked.overhead,
    )?)
}

/// Costs `choices` under `conditions`; refuses an assignment a range cannot use or one
/// over the foreground budget.
pub fn evaluate(
    ranges: &[RangeCandidate],
    conditions: &Conditions,
    choices: &[Representation],
) -> Result<Selection, SelectionError> {
    if ranges.is_empty() {
        return Err(SelectionError::NoRanges);
    }
    if ranges.len() != choices.len() {
        return Err(SelectionError::LengthMismatch {
            ranges: ranges.len(),
            choices: choices.len(),
        });
    }
    let checked = check(conditions)?;
    let mut link_seconds = checked.link_backlog;
    let mut decode_bulk_seconds = 0.0;
    let mut overhead_seconds = 0.0;
    let mut serial_seconds = checked.link_backlog;
    let mut decoded_bytes = 0u64;
    let mut any_compressed = false;
    for (range_index, (range, choice)) in ranges.iter().zip(choices).enumerate() {
        if range.raw_bytes == 0 {
            return Err(InputError::NotPositive { field: "raw_bytes" }.into());
        }
        match choice {
            Representation::Raw => {
                if !range.raw_available {
                    return Err(SelectionError::Infeasible { range: range_index });
                }
                let seconds = range.raw_bytes as f64 / checked.link;
                link_seconds += seconds;
                serial_seconds += seconds;
            }
            Representation::Compressed => {
                let form = match range.compressed {
                    Some(form) if compressed_usable(range, conditions) => form,
                    _ => return Err(SelectionError::Infeasible { range: range_index }),
                };
                any_compressed = true;
                let case = serial_case(range, &form, &checked)?;
                serial_seconds += case.compressed_serial_seconds();
                link_seconds += form.link_bytes() as f64 / checked.link;
                decode_bulk_seconds += range.raw_bytes as f64 / checked.decoder;
                overhead_seconds += checked.overhead;
                decoded_bytes = decoded_bytes.saturating_add(range.raw_bytes);
            }
        }
    }
    let interference_seconds = decoded_bytes as f64 * checked.interference;
    if interference_seconds > checked.budget {
        return Err(SelectionError::ForegroundBudgetExceeded {
            interference_seconds,
            budget_seconds: checked.budget,
        });
    }
    let decoder_backlog = if any_compressed {
        checked.decoder_backlog
    } else {
        0.0
    };
    let decoder_seconds = decoder_backlog + decode_bulk_seconds;
    let completion_seconds = match conditions.model {
        CostModel::Serial => serial_seconds + decoder_backlog,
        CostModel::Pipelined => {
            let fill_drain = if any_compressed {
                checked.fill_drain
            } else {
                0.0
            };
            link_seconds.max(decoder_seconds) + overhead_seconds + fill_drain
        }
    };
    Ok(Selection {
        choices: choices.to_vec(),
        link_seconds,
        decoder_seconds,
        completion_seconds,
        interference_seconds,
        objective_seconds: completion_seconds + interference_seconds,
    })
}

/// Ranges that can only be raw, can only be compressed, or may be either.
fn classify(
    ranges: &[RangeCandidate],
    conditions: &Conditions,
) -> Result<(Vec<Representation>, Vec<usize>), SelectionError> {
    if ranges.is_empty() {
        return Err(SelectionError::NoRanges);
    }
    let mut base = Vec::with_capacity(ranges.len());
    let mut free = Vec::new();
    for (index, range) in ranges.iter().enumerate() {
        match (range.raw_available, compressed_usable(range, conditions)) {
            (true, true) => {
                base.push(Representation::Raw);
                free.push(index);
            }
            (true, false) => base.push(Representation::Raw),
            (false, true) => base.push(Representation::Compressed),
            (false, false) => return Err(SelectionError::NoUsableRepresentation { range: index }),
        }
    }
    Ok((base, free))
}

fn best_of(
    ranges: &[RangeCandidate],
    conditions: &Conditions,
    assignments: impl Iterator<Item = Vec<Representation>>,
) -> Result<Selection, SelectionError> {
    let mut best: Option<Selection> = None;
    let mut over_budget: Option<SelectionError> = None;
    for choices in assignments {
        match evaluate(ranges, conditions, &choices) {
            Ok(selection) => {
                if best
                    .as_ref()
                    .is_none_or(|current| selection.objective_seconds < current.objective_seconds)
                {
                    best = Some(selection);
                }
            }
            Err(error @ SelectionError::ForegroundBudgetExceeded { .. }) => {
                over_budget.get_or_insert(error);
            }
            Err(error) => return Err(error),
        }
    }
    match (best, over_budget) {
        (Some(best), _) => Ok(best),
        (None, Some(error)) => Err(error),
        (None, None) => Err(SelectionError::NoRanges),
    }
}

/// Chooses raw or compressed per range (GPU §4.9). Ranges that may use either are
/// ordered by the fraction compression saves, best first, and every prefix of that order
/// is compressed in turn; the cheapest feasible prefix wins, ties going to fewer
/// compressed ranges. The empty prefix is all-raw and the full one all-compressed, so
/// the result is never worse than either uniform choice that is feasible.
pub fn select(
    ranges: &[RangeCandidate],
    conditions: &Conditions,
) -> Result<Selection, SelectionError> {
    let (base, mut free) = classify(ranges, conditions)?;
    let saving = |index: &usize| -> f64 {
        ranges.get(*index).map_or(0.0, |range| {
            let link = range
                .compressed
                .map_or(range.raw_bytes, |form| form.link_bytes());
            1.0 - link as f64 / range.raw_bytes.max(1) as f64
        })
    };
    free.sort_by(|a, b| saving(b).total_cmp(&saving(a)).then(a.cmp(b)));
    let prefixes = (0..=free.len()).map(|count| {
        let mut choices = base.clone();
        for index in free.iter().take(count) {
            if let Some(choice) = choices.get_mut(*index) {
                *choice = Representation::Compressed;
            }
        }
        choices
    });
    best_of(ranges, conditions, prefixes)
}

/// The exhaustive oracle over every assignment of the free ranges; at most
/// [`MAX_ORACLE_RANGES`] of them.
pub fn select_exhaustive(
    ranges: &[RangeCandidate],
    conditions: &Conditions,
) -> Result<Selection, SelectionError> {
    let (base, free) = classify(ranges, conditions)?;
    if free.len() > MAX_ORACLE_RANGES {
        return Err(SelectionError::TooManyRangesForOracle {
            ranges: free.len(),
            max: MAX_ORACLE_RANGES,
        });
    }
    let assignments = (0u32..(1u32 << free.len())).map(|mask| {
        let mut choices = base.clone();
        for (bit, index) in free.iter().enumerate() {
            if mask & (1 << bit) != 0 {
                if let Some(choice) = choices.get_mut(*index) {
                    *choice = Representation::Compressed;
                }
            }
        }
        choices
    });
    best_of(ranges, conditions, assignments)
}

/// A uniform baseline: every range raw, or every range compressed where it has a
/// usable compressed form (and raw where it has none).
pub fn uniform(
    ranges: &[RangeCandidate],
    conditions: &Conditions,
    representation: Representation,
) -> Result<Selection, SelectionError> {
    let (mut choices, free) = classify(ranges, conditions)?;
    if representation == Representation::Compressed {
        for index in free {
            if let Some(choice) = choices.get_mut(index) {
                *choice = Representation::Compressed;
            }
        }
    }
    evaluate(ranges, conditions, &choices)
}

/// The stronger of the two uniform baselines, ties going to all-raw.
pub fn strongest_uniform(
    ranges: &[RangeCandidate],
    conditions: &Conditions,
) -> Result<Selection, SelectionError> {
    let raw = uniform(ranges, conditions, Representation::Raw);
    let compressed = uniform(ranges, conditions, Representation::Compressed);
    match (raw, compressed) {
        (Ok(raw), Ok(compressed)) => Ok(if compressed.objective_seconds < raw.objective_seconds {
            compressed
        } else {
            raw
        }),
        (Ok(raw), Err(_)) => Ok(raw),
        (Err(_), Ok(compressed)) => Ok(compressed),
        (Err(error), Err(_)) => Err(error),
    }
}

/// A codec comparison GPU §4.9 line 746 asks for and its status here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExternalCodecComparison {
    pub codec: &'static str,
    pub reason: BaselineUnavailable,
    pub detail: &'static str,
}

/// DFloat11 and ZipNN/nvCOMP-compatible comparisons are unavailable here: no
/// implementation is in the dependency set (S1 grants no new crates) and the GPU ones
/// need hardware this work may not use. Marked unavailable, never invented (line 746).
pub const EXTERNAL_COMPARISONS: [ExternalCodecComparison; 3] = [
    ExternalCodecComparison {
        codec: "DFloat11",
        reason: BaselineUnavailable::NeedsUnauthorizedEnvironment,
        detail: "dfloat11-decoder-needs-a-cuda-gpu",
    },
    ExternalCodecComparison {
        codec: "ZipNN",
        reason: BaselineUnavailable::NoCompatibleUpstreamRelease,
        detail: "zipnn-not-in-the-dependency-set",
    },
    ExternalCodecComparison {
        codec: "nvCOMP",
        reason: BaselineUnavailable::NeedsUnauthorizedEnvironment,
        detail: "nvcomp-needs-a-cuda-gpu",
    },
];
