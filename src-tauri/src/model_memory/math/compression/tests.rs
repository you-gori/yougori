use super::*;
use crate::model_memory::math::overlap::{finish_times, GroupTiming};
use crate::model_memory::math::test_support::close;

const GB: f64 = 1e9;
const FOURTEEN_GB: u64 = 14_000_000_000;
const MIB: u64 = 1 << 20;

#[test]
fn compression_breaks_even_at_83_3_gb_per_second() {
    let break_even = break_even_decoder_bytes_per_second(0.70, 25.0 * GB).unwrap();
    assert!(close(break_even, 25.0 * GB / 0.30, 1e-3));
    assert!(close(break_even / GB, 83.3, 0.05));

    let below = CompressionCase::new(FOURTEEN_GB, 0.70, 25.0 * GB, 83.0 * GB, 0.0).unwrap();
    let above = CompressionCase::new(FOURTEEN_GB, 0.70, 25.0 * GB, 84.0 * GB, 0.0).unwrap();
    assert!(close(below.raw_seconds(), 0.56, 1e-12));
    assert!(!below.serial_compression_wins());
    assert!(above.serial_compression_wins());
    assert!(close(
        above.compressed_serial_seconds(),
        0.392 + 14.0 / 84.0,
        1e-12
    ));

    assert_eq!(
        break_even_decoder_bytes_per_second(1.0, 25.0 * GB),
        Err(CompressionError::NoBreakEven {
            compressed_fraction: 1.0
        })
    );
    assert!(break_even_decoder_bytes_per_second(1.2, 25.0 * GB).is_err());
    assert_eq!(
        break_even_decoder_bytes_per_second(0.0, 25.0 * GB),
        Ok(25.0 * GB)
    );
    assert!(break_even_decoder_bytes_per_second(0.7, 0.0).is_err());
    assert!(break_even_decoder_bytes_per_second(f64::NAN, 25.0 * GB).is_err());
}

#[test]
fn the_serial_model_adds_transfer_decode_and_overhead() {
    let case = CompressionCase::new(FOURTEEN_GB, 0.70, 25.0 * GB, 70.0 * GB, 0.010).unwrap();
    assert!(close(case.raw_seconds(), 14.0 / 25.0, 1e-12));
    assert!(close(
        case.compressed_serial_seconds(),
        0.70 * 14.0 / 25.0 + 14.0 / 70.0 + 0.010,
        1e-12
    ));
    assert!(CompressionCase::new(0, 0.7, GB, GB, 0.0).is_err());
    assert!(CompressionCase::new(1, -0.1, GB, GB, 0.0).is_err());
    assert!(CompressionCase::new(1, 0.7, GB, 0.0, 0.0).is_err());
    assert!(CompressionCase::new(1, 0.7, GB, GB, -1.0).is_err());
}

#[test]
fn pipelining_bulk_is_the_slower_stage_plus_fill_drain_and_contention() {
    // Below the serial break-even, a valid pipeline can still favour compression.
    let case = CompressionCase::new(FOURTEEN_GB, 0.70, 25.0 * GB, 40.0 * GB, 0.0).unwrap();
    assert!(!case.serial_compression_wins());
    let estimate = case.pipelined_estimate(0.001, 0.010).unwrap();
    assert!(close(estimate.bulk_seconds, 0.392, 1e-12));
    assert!(close(estimate.total_seconds, 0.392 + 0.001 + 0.010, 1e-12));
    assert!(estimate.total_seconds < case.raw_seconds());
    assert_eq!(estimate.overhead_seconds, 0.0);

    // When decoding is the slower stage, it sets the bulk term.
    let slow_decoder = CompressionCase::new(FOURTEEN_GB, 0.70, 25.0 * GB, 20.0 * GB, 0.0).unwrap();
    assert!(close(
        slow_decoder
            .pipelined_estimate(0.0, 0.0)
            .unwrap()
            .bulk_seconds,
        0.7,
        1e-12
    ));
    assert!(case.pipelined_estimate(-1.0, 0.0).is_err());
    assert!(case.pipelined_estimate(0.0, f64::NAN).is_err());
}

/// The same pipeline computed block by block with the GPU §2.6 recurrence.
fn pipeline_by_recurrence(case: &CompressionCase, raw_bytes: u64, block: u64) -> f64 {
    let mut groups = Vec::new();
    let mut sent = 0;
    let mut transfer_end = 0.0;
    while sent < raw_bytes {
        let bytes = block.min(raw_bytes - sent) as f64;
        transfer_end += case.compressed_fraction * bytes / case.link_bytes_per_second;
        groups.push(GroupTiming {
            usable_at_seconds: transfer_end,
            compute_seconds: bytes / case.decoder_raw_bytes_per_second,
        });
        sent += block;
    }
    *finish_times(&groups).unwrap().last().unwrap() + case.overhead_seconds
}

#[test]
fn the_two_stage_pipeline_is_bulk_plus_one_block_of_fill_drain() {
    let block = MIB;
    let raw = 64 * block;
    for decoder in [10.0 * GB, 40.0 * GB, 100.0 * GB] {
        let case = CompressionCase::new(raw, 0.70, 25.0 * GB, decoder, 0.002).unwrap();
        let exact = case.two_stage_pipeline_seconds(block).unwrap();
        let a = 0.70 * block as f64 / (25.0 * GB);
        let d = block as f64 / decoder;
        let estimate = case.pipelined_estimate(a.min(d), 0.0).unwrap();
        assert!(close(exact, estimate.total_seconds, 1e-12));
        assert!(close(
            exact,
            pipeline_by_recurrence(&case, raw, block),
            1e-12
        ));

        // A partial final block follows the recurrence too.
        let uneven =
            CompressionCase::new(10 * block + block / 2, 0.70, 25.0 * GB, decoder, 0.0).unwrap();
        assert!(close(
            uneven.two_stage_pipeline_seconds(block).unwrap(),
            pipeline_by_recurrence(&uneven, 10 * block + block / 2, block),
            1e-12
        ));
        let single = CompressionCase::new(block / 4, 0.70, 25.0 * GB, decoder, 0.0).unwrap();
        assert!(close(
            single.two_stage_pipeline_seconds(block).unwrap(),
            single.compressed_serial_seconds(),
            1e-15
        ));
    }
    let case = CompressionCase::new(raw, 0.70, 25.0 * GB, GB, 0.0).unwrap();
    assert!(case.two_stage_pipeline_seconds(0).is_err());
}

#[test]
fn bf16_exponent_entropy_of_known_histograms() {
    assert_eq!(Bf16ExponentHistogram::exponent(0x3F80), 127); // 1.0
    assert_eq!(Bf16ExponentHistogram::exponent(0xBF80), 127); // -1.0: sign ignored
    assert_eq!(Bf16ExponentHistogram::exponent(0x3FFF), 127); // mantissa ignored
    assert_eq!(Bf16ExponentHistogram::exponent(0x4000), 128); // 2.0

    // One exponent, varied signs and mantissas: H = 0, so 8 bits per value.
    let single =
        Bf16ExponentHistogram::from_bit_patterns(&[(0x3F80, 5), (0xBF80, 3), (0x3FC0, 8)]).unwrap();
    assert_eq!(single.values(), 16);
    assert_eq!(single.exponent_count(127), 16);
    assert_eq!(single.exponent_entropy_bits().unwrap(), 0.0);
    assert_eq!(single.ideal_bits_per_value().unwrap(), 8.0);

    let halves = Bf16ExponentHistogram::from_bit_patterns(&[(0x3F80, 50), (0x4000, 50)]).unwrap();
    assert!(close(halves.exponent_entropy_bits().unwrap(), 1.0, 1e-12));
    assert!(close(halves.ideal_bits_per_value().unwrap(), 9.0, 1e-12));

    // 1.0, 0.5 and 0.25 at 50%, 25% and 25%: H = 1.5 bits.
    let mixed =
        Bf16ExponentHistogram::from_bit_patterns(&[(0x3F80, 2), (0x3F00, 1), (0x3E80, 1)]).unwrap();
    assert!(close(mixed.exponent_entropy_bits().unwrap(), 1.5, 1e-12));
    assert!(close(mixed.ideal_bits_per_value().unwrap(), 9.5, 1e-12));
    // Four metadata bytes per 32 values add one bit per value.
    assert!(close(
        mixed.bits_per_value_with_metadata(4, 32).unwrap(),
        10.5,
        1e-12
    ));
    assert!(mixed.bits_per_value_with_metadata(4, 0).is_err());

    // Every exponent equally likely: H = 8, so no gain over 16 raw bits.
    let mut uniform = Bf16ExponentHistogram::new();
    for exponent in 0..=255u16 {
        uniform.add(exponent << 7, 1).unwrap();
    }
    assert!(close(uniform.ideal_bits_per_value().unwrap(), 16.0, 1e-12));

    assert!(Bf16ExponentHistogram::default()
        .exponent_entropy_bits()
        .is_err());
    let mut full = Bf16ExponentHistogram::new();
    full.add(0x3F80, u64::MAX).unwrap();
    assert!(full.add(0x3F80, 1).is_err());
    assert_eq!(full.values(), u64::MAX);
}

#[test]
fn metadata_is_4_69_to_6_25_percent_not_under_1_percent() {
    let three = metadata_overhead_fraction(3, 32).unwrap();
    let four = metadata_overhead_fraction(4, 32).unwrap();
    assert_eq!(three, 3.0 / 64.0);
    assert_eq!(four, 4.0 / 64.0);
    assert!(close(three * 100.0, 4.69, 0.005));
    assert!(close(four * 100.0, 6.25, 1e-12));
    assert!(three > 0.01 && four > 0.01);
    assert!(metadata_overhead_fraction(3, 0).is_err());
    assert!(metadata_overhead_fraction(3, u64::MAX).is_err());
}
