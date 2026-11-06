//! The fuzzer's one source of randomness: SplitMix64 (Steele, Lea and Flood, 2014), from
//! an explicit seed, so every run and every reported input replays exactly (VM-W50).

/// SplitMix64: the explicit seeded generator of the mutation fuzzer.
#[derive(Clone, Debug)]
pub(super) struct SplitMix64(u64);

impl SplitMix64 {
    /// A generator starting from `seed`.
    pub(super) const fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// A generator seeded from `bytes` (64-bit FNV-1a), so choices made for one input,
    /// such as where to split it, depend on that input alone and replay from its hex.
    pub(super) fn for_input(bytes: &[u8]) -> Self {
        let mut hash: u64 = 0xCBF2_9CE4_8422_2325;
        for byte in bytes {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
        }
        Self(hash)
    }

    /// The next 64 random bits.
    pub(super) fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A value in `0..bound`; 0 for a bound of 0.
    pub(super) fn below(&mut self, bound: usize) -> usize {
        let bound = u64::try_from(bound).unwrap();
        if bound == 0 {
            return 0;
        }
        usize::try_from(self.next_u64() % bound).unwrap()
    }

    /// A value in `low..=high`.
    pub(super) fn between(&mut self, low: usize, high: usize) -> usize {
        low + self.below(high - low + 1)
    }

    /// True once in `n` draws on average.
    pub(super) fn one_in(&mut self, n: usize) -> bool {
        self.below(n) == 0
    }

    /// A random byte.
    pub(super) fn byte(&mut self) -> u8 {
        self.next_u64().to_le_bytes()[0]
    }

    /// A random element of the non-empty `items`.
    pub(super) fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }

    /// Cuts `bytes` into random consecutive pieces, empty pieces included, whose
    /// concatenation is `bytes`.
    pub(super) fn split<'a>(&mut self, bytes: &'a [u8]) -> Vec<&'a [u8]> {
        let mut pieces = Vec::new();
        let mut rest = bytes;
        while !rest.is_empty() {
            if self.one_in(8) {
                pieces.push(&rest[..0]);
            }
            let take = match self.below(4) {
                0 => 1,
                1 => self.between(1, rest.len().min(8)),
                _ => self.between(1, rest.len()),
            };
            let (piece, remaining) = rest.split_at(take);
            pieces.push(piece);
            rest = remaining;
        }
        pieces
    }
}

#[test]
fn splitmix64_matches_its_reference_outputs() {
    // The published first outputs of SplitMix64 from seed 0.
    let mut rng = SplitMix64::new(0);
    assert_eq!(rng.next_u64(), 0xE220_A839_7B1D_CDAF);
    assert_eq!(rng.next_u64(), 0x6E78_9E6A_A1B9_65F4);
    assert_eq!(rng.next_u64(), 0x06C4_5D18_8009_454F);
    // Splits always rebuild their input.
    let bytes: Vec<u8> = (0..=255).collect();
    let mut rng = SplitMix64::new(7);
    for _ in 0..100 {
        assert_eq!(rng.split(&bytes).concat(), bytes);
    }
}
