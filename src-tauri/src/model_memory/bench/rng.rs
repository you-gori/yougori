//! The only randomness of the fake runners: a seeded generator for deterministic
//! variation (rollout T12: "driven by ManualClock, with seeded deterministic variation").

use serde::{Deserialize, Serialize};

use super::BenchError;

const GOLDEN_GAMMA: u64 = 0x9E37_79B9_7F4A_7C15;

/// SplitMix64: a 64-bit state advanced by a fixed odd increment and mixed by two
/// multiply-xorshift rounds. The same seed gives the same sequence on every platform; a
/// known-answer test pins it, so a replay with the same seed is identical (T12).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeededRng {
    state: u64,
}

impl SeededRng {
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(GOLDEN_GAMMA);
        let mut mixed = self.state;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        mixed ^ (mixed >> 31)
    }

    /// Uniform in `0..bound` without modulo bias; `0` when `bound` is zero.
    pub fn below(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            return 0;
        }
        // 2^64 mod bound: rejecting draws below it leaves a multiple of `bound` values.
        let threshold = bound.wrapping_neg() % bound;
        loop {
            let draw = self.next_u64();
            if draw >= threshold {
                return draw % bound;
            }
        }
    }

    /// An independent stream, so draws made for one purpose never shift another's.
    pub fn fork(&mut self) -> Self {
        Self::new(self.next_u64())
    }

    /// `nanos` varied uniformly within `variation` either side. Zero spread returns
    /// `nanos` unchanged.
    pub fn vary_nanos(&mut self, nanos: u64, variation: Variation) -> u64 {
        let delta = u128::from(nanos) * u128::from(variation.spread_ppm) / 1_000_000;
        let Ok(delta) = u64::try_from(delta) else {
            return nanos;
        };
        if delta == 0 {
            return nanos;
        }
        // delta <= nanos / 2, so the subtraction cannot underflow.
        let offset = self.below(delta.saturating_mul(2).saturating_add(1));
        (nanos - delta).saturating_add(offset)
    }
}

/// Seeded variation of every fake duration, in parts per million either side (T12).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct Variation {
    spread_ppm: u32,
}

impl Variation {
    /// No variation: durations are exactly their parameters.
    pub const NONE: Self = Self { spread_ppm: 0 };

    /// The largest spread, 50%, so a varied duration stays positive.
    pub const MAX_SPREAD_PPM: u32 = 500_000;

    pub fn new(spread_ppm: u32) -> Result<Self, BenchError> {
        if spread_ppm > Self::MAX_SPREAD_PPM {
            return Err(BenchError::InvalidParameter {
                field: "spread_ppm",
                reason: "at most 500000 parts per million",
            });
        }
        Ok(Self { spread_ppm })
    }

    pub const fn spread_ppm(self) -> u32 {
        self.spread_ppm
    }
}

impl TryFrom<u32> for Variation {
    type Error = BenchError;

    fn try_from(spread_ppm: u32) -> Result<Self, Self::Error> {
        Self::new(spread_ppm)
    }
}

impl From<Variation> for u32 {
    fn from(variation: Variation) -> Self {
        variation.spread_ppm
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitmix64_matches_its_published_sequence() {
        let mut rng = SeededRng::new(0);
        assert_eq!(rng.next_u64(), 0xE220_A839_7B1D_CDAF);
        assert_eq!(rng.next_u64(), 0x6E78_9E6A_A1B9_65F4);
        assert_eq!(rng.next_u64(), 0x06C4_5D18_8009_454F);
    }

    #[test]
    fn the_same_seed_replays_and_another_differs() {
        let draws = |seed| {
            let mut rng = SeededRng::new(seed);
            (0..16).map(|_| rng.below(1_000)).collect::<Vec<_>>()
        };
        assert_eq!(draws(7), draws(7));
        assert_ne!(draws(7), draws(8));
        assert!(draws(7).iter().all(|draw| *draw < 1_000));
        assert_eq!(SeededRng::new(1).below(0), 0);
    }

    #[test]
    fn variation_stays_within_its_spread() {
        let mut rng = SeededRng::new(42);
        assert_eq!(rng.vary_nanos(1_000, Variation::NONE), 1_000);
        let ten_percent = Variation::new(100_000).unwrap();
        let varied: Vec<u64> = (0..200)
            .map(|_| rng.vary_nanos(1_000_000, ten_percent))
            .collect();
        assert!(varied
            .iter()
            .all(|nanos| (900_000..=1_100_000).contains(nanos)));
        assert!(varied.iter().any(|nanos| *nanos != 1_000_000));
        assert!(Variation::new(500_001).is_err());
        assert!(rng.vary_nanos(u64::MAX, Variation::new(500_000).unwrap()) >= u64::MAX / 2);
    }

    #[test]
    fn forks_are_independent_streams() {
        let mut parent = SeededRng::new(3);
        let mut first = parent.fork();
        let mut second = parent.fork();
        assert_ne!(first.next_u64(), second.next_u64());
    }
}
