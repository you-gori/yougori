//! Compression cost (GPU §2.8).
//!
//! For raw size `S`, compressed fraction `r`, link bandwidth `B`, decoder throughput `D`
//! in raw bytes per second and fixed overhead `o`: `T_raw = S/B` and
//! `T_compressed_serial = r*S/B + S/D + o`. With `o = 0` the serial model favours
//! compression only when `D > B/(1-r)`. Valid pipelining approximates the bulk term as
//! `max(r*S/B, S/D)`, plus fill/drain and contention.

use std::fmt;

use super::{non_negative, positive, InputError};

/// Why a compression computation was refused.
#[derive(Clone, Debug, PartialEq)]
pub enum CompressionError {
    Input(InputError),
    /// With `r >= 1` the compressed form is no smaller, so no decoder speed makes the
    /// serial model favour compression.
    NoBreakEven {
        compressed_fraction: f64,
    },
}

impl From<InputError> for CompressionError {
    fn from(error: InputError) -> Self {
        Self::Input(error)
    }
}

impl fmt::Display for CompressionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(error) => error.fmt(f),
            Self::NoBreakEven {
                compressed_fraction,
            } => write!(
                f,
                "a compressed fraction of {compressed_fraction} never beats raw transfer"
            ),
        }
    }
}

impl std::error::Error for CompressionError {}

/// The decoder throughput, in raw bytes per second, above which the serial model with
/// `o = 0` favours compression: `B/(1-r)` (GPU §2.8).
pub fn break_even_decoder_bytes_per_second(
    compressed_fraction: f64,
    link_bytes_per_second: f64,
) -> Result<f64, CompressionError> {
    let compressed_fraction = non_negative("compressed_fraction", compressed_fraction)?;
    let link_bytes_per_second = positive("link_bytes_per_second", link_bytes_per_second)?;
    if compressed_fraction >= 1.0 {
        return Err(CompressionError::NoBreakEven {
            compressed_fraction,
        });
    }
    Ok(link_bytes_per_second / (1.0 - compressed_fraction))
}

/// One transfer, raw or compressed (GPU §2.8).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CompressionCase {
    raw_bytes: f64,
    compressed_fraction: f64,
    link_bytes_per_second: f64,
    decoder_raw_bytes_per_second: f64,
    overhead_seconds: f64,
}

/// The pipelined approximation with its terms kept apart.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PipelinedEstimate {
    /// `max(r*S/B, S/D)`.
    pub bulk_seconds: f64,
    pub fill_drain_seconds: f64,
    pub contention_seconds: f64,
    /// `o`, paid once as in the serial model.
    pub overhead_seconds: f64,
    pub total_seconds: f64,
}

impl CompressionCase {
    /// `S`, `r`, `B`, `D` and `o` of GPU §2.8; `S`, `B` and `D` must be positive.
    pub fn new(
        raw_bytes: u64,
        compressed_fraction: f64,
        link_bytes_per_second: f64,
        decoder_raw_bytes_per_second: f64,
        overhead_seconds: f64,
    ) -> Result<Self, CompressionError> {
        if raw_bytes == 0 {
            return Err(InputError::NotPositive { field: "raw_bytes" }.into());
        }
        Ok(Self {
            raw_bytes: raw_bytes as f64,
            compressed_fraction: non_negative("compressed_fraction", compressed_fraction)?,
            link_bytes_per_second: positive("link_bytes_per_second", link_bytes_per_second)?,
            decoder_raw_bytes_per_second: positive(
                "decoder_raw_bytes_per_second",
                decoder_raw_bytes_per_second,
            )?,
            overhead_seconds: non_negative("overhead_seconds", overhead_seconds)?,
        })
    }

    /// `T_raw = S/B`.
    pub fn raw_seconds(&self) -> f64 {
        self.raw_bytes / self.link_bytes_per_second
    }

    fn compressed_transfer_seconds(&self) -> f64 {
        self.compressed_fraction * self.raw_bytes / self.link_bytes_per_second
    }

    fn decode_seconds(&self) -> f64 {
        self.raw_bytes / self.decoder_raw_bytes_per_second
    }

    /// `T_compressed_serial = r*S/B + S/D + o`.
    pub fn compressed_serial_seconds(&self) -> f64 {
        self.compressed_transfer_seconds() + self.decode_seconds() + self.overhead_seconds
    }

    /// Whether the serial model favours compression.
    pub fn serial_compression_wins(&self) -> bool {
        self.compressed_serial_seconds() < self.raw_seconds()
    }

    /// `max(r*S/B, S/D)` plus measured fill/drain and contention, plus `o`: an
    /// approximation for valid pipelining (GPU §2.8).
    pub fn pipelined_estimate(
        &self,
        fill_drain_seconds: f64,
        contention_seconds: f64,
    ) -> Result<PipelinedEstimate, CompressionError> {
        let fill_drain_seconds = non_negative("fill_drain_seconds", fill_drain_seconds)?;
        let contention_seconds = non_negative("contention_seconds", contention_seconds)?;
        let bulk_seconds = self
            .compressed_transfer_seconds()
            .max(self.decode_seconds());
        Ok(PipelinedEstimate {
            bulk_seconds,
            fill_drain_seconds,
            contention_seconds,
            overhead_seconds: self.overhead_seconds,
            total_seconds: bulk_seconds
                + fill_drain_seconds
                + contention_seconds
                + self.overhead_seconds,
        })
    }

    /// Transfer and decode as a two-stage pipeline over independently decodable blocks
    /// of `block_raw_bytes`, without contention, plus `o`. Exact for this model: with
    /// `n` equal blocks it is `n*max(a,d) + min(a,d)`, where `a` and `d` are one
    /// block's transfer and decode times, so fill/drain is `min(a,d)`.
    pub fn two_stage_pipeline_seconds(
        &self,
        block_raw_bytes: u64,
    ) -> Result<f64, CompressionError> {
        if block_raw_bytes == 0 {
            return Err(InputError::NotPositive {
                field: "block_raw_bytes",
            }
            .into());
        }
        let block = block_raw_bytes as f64;
        let full_blocks = (self.raw_bytes / block).floor();
        let last_bytes = self.raw_bytes - full_blocks * block;
        let transfer = |bytes: f64| self.compressed_fraction * bytes / self.link_bytes_per_second;
        let decode = |bytes: f64| bytes / self.decoder_raw_bytes_per_second;
        let (a, d) = (transfer(block), decode(block));
        let full_finish = if full_blocks >= 1.0 {
            a.min(d) + full_blocks * a.max(d)
        } else {
            0.0
        };
        let finish = if last_bytes > 0.0 {
            let transfer_end = full_blocks * a + transfer(last_bytes);
            transfer_end.max(full_finish) + decode(last_bytes)
        } else {
            full_finish
        };
        Ok(finish + self.overhead_seconds)
    }
}

/// Bytes in one BF16 value.
pub const BF16_BYTES: u64 = 2;

/// Bits of a BF16 value an exponent coder keeps verbatim: the sign and 7 mantissa bits.
pub const BF16_VERBATIM_BITS: f64 = 8.0;

/// Counts of BF16 exponent fields taken from BF16 bit patterns (GPU §2.8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bf16ExponentHistogram {
    counts: [u64; 256],
    values: u64,
}

impl Default for Bf16ExponentHistogram {
    fn default() -> Self {
        Self::new()
    }
}

impl Bf16ExponentHistogram {
    /// An empty histogram.
    pub fn new() -> Self {
        Self {
            counts: [0; 256],
            values: 0,
        }
    }

    /// Builds from `(bit pattern, count)` pairs.
    pub fn from_bit_patterns(histogram: &[(u16, u64)]) -> Result<Self, CompressionError> {
        let mut built = Self::new();
        for &(bits, count) in histogram {
            built.add(bits, count)?;
        }
        Ok(built)
    }

    /// The 8-bit exponent field of a BF16 bit pattern.
    pub const fn exponent(bits: u16) -> u8 {
        ((bits >> 7) & 0xFF) as u8
    }

    /// Counts `count` values with this bit pattern.
    pub fn add(&mut self, bits: u16, count: u64) -> Result<(), CompressionError> {
        let exponent = usize::from(Self::exponent(bits));
        let values = self
            .values
            .checked_add(count)
            .ok_or(InputError::Overflow { field: "values" })?;
        self.counts[exponent] += count;
        self.values = values;
        Ok(())
    }

    /// How many values were counted.
    pub fn values(&self) -> u64 {
        self.values
    }

    /// How many counted values have this exponent.
    pub fn exponent_count(&self, exponent: u8) -> u64 {
        self.counts[usize::from(exponent)]
    }

    /// `H(exponent)` in bits.
    pub fn exponent_entropy_bits(&self) -> Result<f64, CompressionError> {
        if self.values == 0 {
            return Err(InputError::Empty {
                field: "BF16 histogram",
            }
            .into());
        }
        let total = self.values as f64;
        Ok(self
            .counts
            .iter()
            .filter(|&&count| count > 0)
            .map(|&count| {
                let p = count as f64 / total;
                -p * p.log2()
            })
            .sum::<f64>()
            .max(0.0))
    }

    /// `8 + H(exponent)`: the ideal bits per value with sign and mantissa kept verbatim,
    /// before any real coding overhead (GPU §2.8).
    pub fn ideal_bits_per_value(&self) -> Result<f64, CompressionError> {
        Ok(BF16_VERBATIM_BITS + self.exponent_entropy_bits()?)
    }

    /// The ideal bits per value plus `metadata_bytes_per_group` spread over
    /// `values_per_group` values: bounded codes, headers, offsets, escapes and
    /// checksums are not free.
    pub fn bits_per_value_with_metadata(
        &self,
        metadata_bytes_per_group: u64,
        values_per_group: u64,
    ) -> Result<f64, CompressionError> {
        if values_per_group == 0 {
            return Err(InputError::NotPositive {
                field: "values_per_group",
            }
            .into());
        }
        Ok(self.ideal_bits_per_value()?
            + 8.0 * metadata_bytes_per_group as f64 / values_per_group as f64)
    }
}

/// Metadata bytes per group of BF16 values as a fraction of the group's raw bytes
/// (GPU §2.8): 3–4 bytes per 32 values is 4.69–6.25% of 64 bytes, not under 1%.
pub fn metadata_overhead_fraction(
    metadata_bytes_per_group: u64,
    values_per_group: u64,
) -> Result<f64, CompressionError> {
    let raw_bytes = values_per_group
        .checked_mul(BF16_BYTES)
        .ok_or(InputError::Overflow {
            field: "values_per_group",
        })?;
    if raw_bytes == 0 {
        return Err(InputError::NotPositive {
            field: "values_per_group",
        }
        .into());
    }
    Ok(metadata_bytes_per_group as f64 / raw_bytes as f64)
}

#[cfg(test)]
mod tests;
