//! §4.9 representation selection: the §2.8 worked numbers per range, the pipelined
//! generalization, scratch, availability, the foreground budget, raw escapes and the
//! unavailable external comparisons.

use super::super::codec::{prepare_file, EscapePolicy};
use super::super::selection::*;
use super::*;
use crate::foundation::report::BaselineUnavailable;
use crate::model_memory::math::compression::{
    break_even_decoder_bytes_per_second, metadata_overhead_fraction, CompressionCase,
};

const GB: u64 = 1_000_000_000;

fn conditions(link: f64, decoder: f64, model: CostModel) -> Conditions {
    Conditions {
        link_bytes_per_second: link,
        link_backlog_seconds: 0.0,
        decoder_raw_bytes_per_second: decoder,
        decoder_backlog_seconds: 0.0,
        overhead_seconds_per_compressed_range: 0.0,
        fill_drain_seconds: 0.0,
        scratch_available_bytes: u64::MAX,
        interference_seconds_per_decoded_byte: 0.0,
        foreground_budget_seconds: f64::MAX,
        model,
    }
}

fn range(raw: u64, compressed_fraction: f64) -> RangeCandidate {
    RangeCandidate {
        raw_bytes: raw,
        raw_available: true,
        compressed: Some(CompressedForm {
            stored_bytes: (raw as f64 * compressed_fraction).round() as u64,
            metadata_bytes: 0,
            scratch_bytes: 0,
        }),
    }
}

fn choice(ranges: &[RangeCandidate], conditions: &Conditions) -> Vec<Representation> {
    select(ranges, conditions).unwrap().choices
}

use Representation::{Compressed, Raw};

#[test]
fn the_serial_break_even_of_section_2_8_decides_one_range() {
    // r = 0.70 and B = 25 GB/s: compression wins only above 83.3 GB/s.
    let break_even = break_even_decoder_bytes_per_second(0.70, 25.0e9).unwrap();
    assert!((break_even / 1e9 - 83.333).abs() < 0.001);
    let ranges = [range(GB, 0.70)];
    for (decoder, expected) in [
        (100.0e9, Compressed),
        (83.4e9, Compressed),
        (83.2e9, Raw),
        (50.0e9, Raw),
    ] {
        let at = conditions(25.0e9, decoder, CostModel::Serial);
        assert_eq!(choice(&ranges, &at), vec![expected], "{decoder}");
        // The same verdict as the committed §2.8 model.
        let case = CompressionCase::new(GB, 0.70, 25.0e9, decoder, 0.0).unwrap();
        assert_eq!(case.serial_compression_wins(), expected == Compressed);
    }
}

#[test]
fn a_cold_remote_transfer_prefers_compression_and_a_gpu_peer_copy_prefers_raw() {
    let ranges = [range(GB, 0.70)];
    for model in [CostModel::Serial, CostModel::Pipelined] {
        // 100 MB/s from a remote store, 1 GB/s of decoding.
        assert_eq!(
            choice(&ranges, &conditions(0.1e9, 1.0e9, model)),
            vec![Compressed]
        );
        // 50 GB/s from a GPU peer, 10 GB/s of decoding.
        assert_eq!(
            choice(&ranges, &conditions(50.0e9, 10.0e9, model)),
            vec![Raw]
        );
    }
}

#[test]
fn one_pipelined_range_is_exactly_the_section_2_8_estimate() {
    let mut at = conditions(25.0e9, 40.0e9, CostModel::Pipelined);
    at.overhead_seconds_per_compressed_range = 0.002;
    at.fill_drain_seconds = 0.003;
    let ranges = [range(GB, 0.70)];
    let selection = evaluate(&ranges, &at, &[Compressed]).unwrap();
    let estimate = CompressionCase::new(GB, 0.70, 25.0e9, 40.0e9, 0.002)
        .unwrap()
        .pipelined_estimate(0.003, 0.0)
        .unwrap();
    assert!((selection.completion_seconds - estimate.total_seconds).abs() < 1e-12);
    let mut serial = at;
    serial.model = CostModel::Serial;
    let case = CompressionCase::new(GB, 0.70, 25.0e9, 40.0e9, 0.002).unwrap();
    let serial_selection = evaluate(&ranges, &serial, &[Compressed]).unwrap();
    assert!((serial_selection.completion_seconds - case.compressed_serial_seconds()).abs() < 1e-12);
}

#[test]
fn per_range_selection_beats_both_uniform_choices_when_the_decoder_limits() {
    // Two ranges compress to half, two to 90%; the link carries 10 GB/s and the decoder
    // 4 GB/s. All-raw takes 0.4 s, all-compressed 1.0 s (decoder bound), compressing
    // only one well-compressing range 0.35 s.
    let ranges = [
        range(GB, 0.5),
        range(GB, 0.9),
        range(GB, 0.5),
        range(GB, 0.9),
    ];
    let at = conditions(10.0e9, 4.0e9, CostModel::Pipelined);
    let selection = select(&ranges, &at).unwrap();
    assert_eq!(selection.compressed_ranges(), 1);
    assert_eq!(selection.choices[0], Compressed);
    assert!((selection.completion_seconds - 0.35).abs() < 1e-12);
    let raw = uniform(&ranges, &at, Raw).unwrap();
    let compressed = uniform(&ranges, &at, Compressed).unwrap();
    assert!((raw.completion_seconds - 0.4).abs() < 1e-12);
    assert!((compressed.completion_seconds - 1.0).abs() < 1e-12);
    assert_eq!(
        strongest_uniform(&ranges, &at).unwrap().choices,
        raw.choices
    );
    // A busy link (1 s of other transfers ahead) moves the balance towards compression.
    let mut busy = at;
    busy.link_backlog_seconds = 1.0;
    let contended = select(&ranges, &busy).unwrap();
    assert!(contended.compressed_ranges() >= 3);
    assert!(
        contended.objective_seconds <= strongest_uniform(&ranges, &busy).unwrap().objective_seconds
    );
}

#[test]
fn scratch_and_source_availability_constrain_each_range() {
    let mut big = range(GB, 0.5);
    if let Some(form) = big.compressed.as_mut() {
        form.scratch_bytes = 2 * GB;
    }
    let mut at = conditions(0.1e9, 1.0e9, CostModel::Serial);
    at.scratch_available_bytes = GB;
    // Compression would win, but its scratch does not fit.
    assert_eq!(choice(&[big], &at), vec![Raw]);
    assert_eq!(
        evaluate(&[big], &at, &[Compressed]),
        Err(SelectionError::Infeasible { range: 0 })
    );
    // Without a raw copy the compressed form is used even on a fast link.
    let mut only_compressed = range(GB, 0.9);
    only_compressed.raw_available = false;
    let fast = conditions(50.0e9, 1.0e9, CostModel::Serial);
    assert_eq!(choice(&[only_compressed], &fast), vec![Compressed]);
    assert_eq!(
        evaluate(&[only_compressed], &fast, &[Raw]),
        Err(SelectionError::Infeasible { range: 0 })
    );
    // Neither usable: refused, never guessed.
    let mut neither = big;
    neither.raw_available = false;
    assert_eq!(
        select(&[neither], &at),
        Err(SelectionError::NoUsableRepresentation { range: 0 })
    );
    assert_eq!(select(&[], &at), Err(SelectionError::NoRanges));
}

#[test]
fn decoder_interference_respects_the_foreground_budget() {
    let ranges = [range(GB, 0.5), range(GB, 0.5)];
    let mut at = conditions(0.1e9, 10.0e9, CostModel::Serial);
    at.interference_seconds_per_decoded_byte = 1e-9;
    // One decoded gigabyte costs 1 s of foreground time; a 1.5 s budget allows one.
    at.foreground_budget_seconds = 1.5;
    let selection = select(&ranges, &at).unwrap();
    assert_eq!(selection.compressed_ranges(), 1);
    assert!(selection.interference_seconds <= 1.5);
    assert!(matches!(
        evaluate(&ranges, &at, &[Compressed, Compressed]),
        Err(SelectionError::ForegroundBudgetExceeded { .. })
    ));
    // A range that can only be decoded but would exceed the budget is refused.
    let mut forced = range(GB, 0.5);
    forced.raw_available = false;
    at.foreground_budget_seconds = 0.5;
    assert!(matches!(
        select(&[forced], &at),
        Err(SelectionError::ForegroundBudgetExceeded { .. })
    ));
    // Interference is part of the objective: at 30 ns per byte the decoded range costs
    // more foreground time than the transfer it saves.
    let mut costly = conditions(0.1e9, 10.0e9, CostModel::Serial);
    costly.interference_seconds_per_decoded_byte = 30e-9;
    assert_eq!(choice(&[range(GB, 0.5)], &costly), vec![Raw]);
}

#[test]
fn blocks_that_do_not_pay_for_their_metadata_go_raw() {
    // §2.8: 3-4 metadata bytes per 32 BF16 values are 4.69-6.25% of the raw 64 bytes.
    let low = metadata_overhead_fraction(3, 32).unwrap();
    let high = metadata_overhead_fraction(4, 32).unwrap();
    assert!((low - 0.046875).abs() < 1e-12 && (high - 0.0625).abs() < 1e-12);
    // A 64-byte group compressed to 61 bytes plus 4 metadata bytes is larger than raw:
    // raw on any link, with any decoder.
    let group = RangeCandidate {
        raw_bytes: 64,
        raw_available: true,
        compressed: Some(CompressedForm {
            stored_bytes: 61,
            metadata_bytes: 4,
            scratch_bytes: 0,
        }),
    };
    for link in [1.0e6, 1.0e9, 50.0e9] {
        assert_eq!(
            choice(&[group], &conditions(link, 1.0e15, CostModel::Serial)),
            vec![Raw]
        );
    }
    // Already-quantized blocks: random bytes escape raw at preparation, leaving no
    // compressed form to select.
    let quantized = random_bytes(21, 4 * G as usize);
    let prepared = prepare_file(
        &path("quantized.bin"),
        &quantized,
        G,
        &path("prepared/quantized.zst"),
        &EscapePolicy {
            level: 3,
            metadata_bytes_per_encoded_block: 0,
        },
    )
    .unwrap();
    assert_eq!(prepared.encoded_blocks, 0);
    let candidates: Vec<RangeCandidate> = prepared
        .extents
        .iter()
        .map(|extent| RangeCandidate {
            raw_bytes: extent.true_length_bytes,
            raw_available: true,
            compressed: None,
        })
        .collect();
    let slow_link = conditions(1.0e6, 1.0e9, CostModel::Pipelined);
    assert!(select(&candidates, &slow_link)
        .unwrap()
        .choices
        .iter()
        .all(|choice| *choice == Raw));
}

#[test]
fn the_prefix_heuristic_never_beats_the_oracle_nor_loses_to_a_uniform_choice() {
    let mut rng = SeededRng::new(77);
    let mut matches = 0;
    let trials = 300;
    for trial in 0..trials {
        let count = 1 + rng.below(8) as usize;
        let ranges: Vec<RangeCandidate> = (0..count)
            .map(|_| {
                let raw = (1 + rng.below(1000)) * 1_000_000;
                range(raw, 0.3 + rng.below(800) as f64 / 1000.0)
            })
            .collect();
        let model = if trial % 2 == 0 {
            CostModel::Pipelined
        } else {
            CostModel::Serial
        };
        let mut at = conditions(
            (1 + rng.below(100)) as f64 * 1e8,
            (1 + rng.below(100)) as f64 * 1e8,
            model,
        );
        at.link_backlog_seconds = rng.below(3) as f64 * 0.5;
        at.overhead_seconds_per_compressed_range = rng.below(5) as f64 * 1e-3;
        let heuristic = select(&ranges, &at).unwrap();
        let oracle = select_exhaustive(&ranges, &at).unwrap();
        let uniform = strongest_uniform(&ranges, &at).unwrap();
        assert!(heuristic.objective_seconds >= oracle.objective_seconds - 1e-12);
        assert!(heuristic.objective_seconds <= uniform.objective_seconds + 1e-12);
        if (heuristic.objective_seconds - oracle.objective_seconds).abs() <= 1e-12 {
            matches += 1;
        }
    }
    // The serial model is separable per range, so prefixes by saving fraction are
    // optimal there; the pipelined balance is near optimal.
    assert!(matches * 10 >= trials * 9, "{matches} of {trials}");
    let many = vec![range(GB, 0.5); MAX_ORACLE_RANGES + 1];
    assert_eq!(
        select_exhaustive(&many, &conditions(1e9, 1e9, CostModel::Serial)),
        Err(SelectionError::TooManyRangesForOracle {
            ranges: MAX_ORACLE_RANGES + 1,
            max: MAX_ORACLE_RANGES
        })
    );
}

#[test]
fn invalid_conditions_are_refused_not_clamped() {
    let ranges = [range(GB, 0.5)];
    let good = conditions(1e9, 1e9, CostModel::Serial);
    for bad in [
        Conditions {
            link_bytes_per_second: 0.0,
            ..good
        },
        Conditions {
            decoder_raw_bytes_per_second: f64::NAN,
            ..good
        },
        Conditions {
            link_backlog_seconds: -1.0,
            ..good
        },
        Conditions {
            interference_seconds_per_decoded_byte: f64::INFINITY,
            ..good
        },
    ] {
        assert!(matches!(
            select(&ranges, &bad),
            Err(SelectionError::Input(_))
        ));
    }
    assert_eq!(
        evaluate(&ranges, &good, &[]),
        Err(SelectionError::LengthMismatch {
            ranges: 1,
            choices: 0
        })
    );
}

#[test]
fn external_codec_comparisons_are_recorded_unavailable() {
    let names: Vec<&str> = EXTERNAL_COMPARISONS
        .iter()
        .map(|comparison| comparison.codec)
        .collect();
    assert_eq!(names, vec!["DFloat11", "ZipNN", "nvCOMP"]);
    for comparison in EXTERNAL_COMPARISONS {
        assert!(matches!(
            comparison.reason,
            BaselineUnavailable::NeedsUnauthorizedEnvironment
                | BaselineUnavailable::NoCompatibleUpstreamRelease
        ));
        // The detail is a valid report label, so it can be recorded as is.
        assert!(crate::foundation::report::Label::new(comparison.detail).is_ok());
    }
    // §4.10 is a gated non-goal.
    assert!(super::super::COMPRESSED_COMPUTE.clause.contains("§4.10"));
}
