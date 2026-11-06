//! The seeded generator of the fake substrate (SplitMix64). Every random choice of the
//! prototype comes from it, so a seed reproduces a run exactly (rollout rule 3).

/// SplitMix64: a 64-bit state advanced by a fixed odd increment and mixed on output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeededRng {
    state: u64,
}

impl SeededRng {
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// A generator for one sub-stream, such as one trial or one request, derived from
    /// a seed and the sub-stream's coordinates.
    pub fn derived(seed: u64, coordinates: &[u64]) -> Self {
        let mixed = coordinates.iter().fold(seed, |state, coordinate| {
            Self::new(state ^ coordinate.wrapping_mul(0x9E37_79B9_7F4A_7C15)).next_u64()
        });
        Self::new(mixed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A value in [0, 1) with 53 random bits.
    pub fn next_unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// True with probability `probability`; never for 0, always for 1.
    pub fn chance(&mut self, probability: f64) -> bool {
        self.next_unit() < probability
    }

    /// A value in [0, `bound`); 0 when `bound` is 0.
    pub fn below(&mut self, bound: u64) -> u64 {
        ((u128::from(self.next_u64()) * u128::from(bound)) >> 64) as u64
    }

    /// A value in [`low`, `high`]; `low` when the range is empty.
    pub fn between(&mut self, low: u64, high: u64) -> u64 {
        match high.checked_sub(low).and_then(|span| span.checked_add(1)) {
            Some(span) => low + self.below(span),
            None if high < low => low,
            None => self.next_u64(),
        }
    }
}
