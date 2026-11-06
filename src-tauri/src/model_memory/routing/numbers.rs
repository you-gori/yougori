//! Explicit numeric conversions for the routing models, so that no conversion can panic
//! or wrap silently. These are the only numeric `as` casts in the module.

/// A count or byte total as seconds-ready `f64`: exact below 2^53, rounded above.
pub(crate) fn approx_f64(value: u64) -> f64 {
    value as f64
}

/// A length or index as `u64`, saturating where `usize` is wider.
pub(crate) fn count_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// An index as `u32`, saturating.
pub(crate) fn index_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

/// The largest whole number not above `value`: zero for negative or NaN input, `u64::MAX`
/// beyond its range.
pub(crate) fn floor_u64(value: f64) -> u64 {
    if value.is_nan() || value <= 0.0 {
        0
    } else if value >= approx_f64(u64::MAX) {
        u64::MAX
    } else {
        value.floor() as u64
    }
}
