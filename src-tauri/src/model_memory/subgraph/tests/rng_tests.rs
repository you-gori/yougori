//! The seeded generator of the fake substrate.

use super::rng::SeededRng;

#[test]
fn splitmix64_matches_its_reference_values() {
    let mut rng = SeededRng::new(0);
    assert_eq!(rng.next_u64(), 0xE220_A839_7B1D_CDAF);
    assert_eq!(rng.next_u64(), 0x6E78_9E6A_A1B9_65F4);
    assert_eq!(rng.next_u64(), 0x06C4_5D18_8009_454F);
}

#[test]
fn draws_stay_in_range_and_sub_streams_are_reproducible() {
    let mut rng = SeededRng::new(42);
    for _ in 0..1000 {
        assert!(rng.below(7) < 7);
        let value = rng.between(3, 5);
        assert!((3..=5).contains(&value));
        let unit = rng.next_unit();
        assert!((0.0..1.0).contains(&unit));
    }
    assert_eq!(rng.below(0), 0);
    assert_eq!(rng.between(9, 2), 9);
    assert!(!rng.chance(0.0));
    assert!(rng.chance(1.0));
    let mut first = SeededRng::derived(7, &[1, 2]);
    let mut again = SeededRng::derived(7, &[1, 2]);
    let mut other = SeededRng::derived(7, &[2, 1]);
    let a = first.next_u64();
    assert_eq!(a, again.next_u64());
    assert_ne!(a, other.next_u64());
}
