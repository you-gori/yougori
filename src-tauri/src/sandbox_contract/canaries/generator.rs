//! The explicit seeded generator canary values come from (VM-W10; VM-R86 "safe fixtures").
//!
//! Blocks are SHA-256 in counter mode over a secret seed: block `i` is the
//! domain-separated digest of the seed and `i`. The same seed gives the same blocks, so
//! tests are deterministic; a counter is never reused, so no block repeats within one
//! generator.

use std::fmt;

use crate::foundation::ids::digest;

const DRBG_DOMAIN: &str = "yougori/sandbox/canary/drbg/v1";

/// The secret seed of the canary generator (VM-W10). Whoever knows it can predict every
/// value the registry issues, so a host takes it fresh from its own random source when the
/// registry starts (later runtime work); tests pass fixed seeds. Its `Debug` output shows
/// nothing of it, and it is neither serializable nor comparable.
#[derive(Clone)]
pub struct CanarySeed([u8; 32]);

impl CanarySeed {
    /// A seed from 32 secret bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for CanarySeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CanarySeed(..)")
    }
}

/// SHA-256 counter-mode generator over a [`CanarySeed`].
pub(super) struct CanaryGenerator {
    seed: [u8; 32],
    counter: u64,
}

impl CanaryGenerator {
    pub(super) fn new(seed: &CanarySeed) -> Self {
        Self {
            seed: seed.0,
            counter: 0,
        }
    }

    /// The next block; `None` once the counter cannot advance, so no block is ever
    /// produced twice.
    pub(super) fn next_block(&mut self) -> Option<[u8; 32]> {
        let next = self.counter.checked_add(1)?;
        let block = digest(DRBG_DOMAIN, &[&self.seed, &self.counter.to_be_bytes()]);
        self.counter = next;
        Some(*block.as_bytes())
    }
}

impl fmt::Debug for CanaryGenerator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CanaryGenerator {{ blocks_drawn: {} }}", self.counter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_gives_same_blocks_and_blocks_never_repeat() {
        let seed = CanarySeed::from_bytes([7; 32]);
        let mut first = CanaryGenerator::new(&seed);
        let mut second = CanaryGenerator::new(&seed);
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..256 {
            let block = first.next_block().unwrap();
            assert_eq!(Some(block), second.next_block());
            assert!(seen.insert(block), "a block repeated");
        }
        let mut other = CanaryGenerator::new(&CanarySeed::from_bytes([8; 32]));
        let mut fresh = CanaryGenerator::new(&seed);
        assert_ne!(other.next_block(), fresh.next_block());
    }

    #[test]
    fn an_exhausted_counter_stops_instead_of_wrapping() {
        let mut generator = CanaryGenerator::new(&CanarySeed::from_bytes([1; 32]));
        generator.counter = u64::MAX - 1;
        assert!(generator.next_block().is_some());
        assert_eq!(generator.next_block(), None);
        assert_eq!(generator.next_block(), None);
        assert_eq!(generator.counter, u64::MAX);
    }

    #[test]
    fn debug_shows_nothing_of_the_seed() {
        let seed = CanarySeed::from_bytes([0xab; 32]);
        let shown = format!("{seed:?} {:?}", CanaryGenerator::new(&seed));
        assert!(!shown.contains("ab"), "{shown}");
        assert!(!shown.contains("171"), "{shown}");
    }
}
