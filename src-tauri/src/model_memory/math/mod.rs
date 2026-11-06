//! The GPU memory cost model: GPU §2.2, §2.5, §2.6, §2.8 and §2.9 of
//! docs/combined-gpu-memory-and-vm-sandbox-plan.md.
//!
//! - [`bounds`]: physical transfer lower bounds with shared resources counted once, the
//!   Amdahl bound, and speedup kinds that are never interchangeable (§2.2).
//! - [`chunking`]: the fitted path model, the toy equal-stage seed and the discrete
//!   batch search under memory, alignment and non-preemptible limits (§2.5).
//! - [`sources`]: multi-source planning over shared cuts with bounded work stealing,
//!   per-source concurrency caps and hysteresis (§1.1, §2.5).
//! - [`overlap`]: the execute-while-load recurrence, the no-stall condition, first-token
//!   dependencies and exact MoE experts (§2.6).
//! - [`compression`]: serial and pipelined compression cost, BF16 exponent entropy and
//!   metadata overhead (§2.8).
//! - [`recompute`]: KV recompute versus transfer, and what a discard means (§2.8).
//! - [`prefetch`] and [`calibration`]: prefetch as an investment under a speculative
//!   budget, and the demand-only fallback (§2.9).
//!
//! Everything here is pure, synchronous and deterministic. Bytes are `u64`, durations
//! are `f64` seconds and bandwidths are `f64` bytes per second. Invalid input is refused
//! with a typed error, never clamped into range.

use std::fmt;

/// Why an input to the cost model was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InputError {
    /// A value is NaN or infinite.
    NotFinite { field: &'static str },
    /// A value that must be zero or more is negative.
    Negative { field: &'static str },
    /// A value that must be more than zero, such as a bandwidth or a size, is not.
    NotPositive { field: &'static str },
    /// A value lies outside its range, such as a probability above 1.
    OutOfRange { field: &'static str },
    /// A list or name that needs at least one element is empty.
    Empty { field: &'static str },
    /// Two lists that must have the same length do not.
    LengthMismatch {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    /// A name or value appears twice where each must be unique.
    Duplicate { field: &'static str, name: String },
    /// A name refers to nothing that was declared.
    Unknown { field: &'static str, name: String },
    /// A byte total does not fit in 64 bits.
    Overflow { field: &'static str },
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFinite { field } => write!(f, "{field} is not a finite number"),
            Self::Negative { field } => write!(f, "{field} is negative"),
            Self::NotPositive { field } => write!(f, "{field} must be more than zero"),
            Self::OutOfRange { field } => write!(f, "{field} is out of range"),
            Self::Empty { field } => write!(f, "{field} is empty"),
            Self::LengthMismatch {
                field,
                expected,
                actual,
            } => write!(f, "{field} has {actual} entries; expected {expected}"),
            Self::Duplicate { field, name } => write!(f, "{field} lists {name:?} twice"),
            Self::Unknown { field, name } => write!(f, "{field} names unknown {name:?}"),
            Self::Overflow { field } => write!(f, "{field} does not fit in 64 bits"),
        }
    }
}

impl std::error::Error for InputError {}

/// A finite value of zero or more.
pub(crate) fn non_negative(field: &'static str, value: f64) -> Result<f64, InputError> {
    if !value.is_finite() {
        return Err(InputError::NotFinite { field });
    }
    if value < 0.0 {
        return Err(InputError::Negative { field });
    }
    Ok(value)
}

/// A finite value above zero.
pub(crate) fn positive(field: &'static str, value: f64) -> Result<f64, InputError> {
    if !value.is_finite() {
        return Err(InputError::NotFinite { field });
    }
    if value <= 0.0 {
        return Err(InputError::NotPositive { field });
    }
    Ok(value)
}

/// A probability in [0, 1].
pub(crate) fn probability(field: &'static str, value: f64) -> Result<f64, InputError> {
    if non_negative(field, value)? > 1.0 {
        return Err(InputError::OutOfRange { field });
    }
    Ok(value)
}

/// Longest accepted name.
pub const MAX_NAME_LEN: usize = 128;

macro_rules! name_type {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// Accepts 1–128 characters without control characters.
            pub fn new(value: impl Into<String>) -> Result<Self, InputError> {
                let value = value.into();
                if value.is_empty() {
                    return Err(InputError::Empty { field: stringify!($name) });
                }
                if value.chars().count() > MAX_NAME_LEN || value.chars().any(char::is_control) {
                    return Err(InputError::OutOfRange { field: stringify!($name) });
                }
                Ok(Self(value))
            }

            /// The name as given.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

/// A resource or directional link that bytes cross, such as an NVMe read path, a PCIe
/// root's host-to-device direction or the host memory channels (GPU §2.2). This is the
/// shared foundation identifier, so the cost model and the request graph name a
/// resource the same way.
pub use crate::foundation::ids::ResourceId;

name_type!(
    /// A source of model bytes: local storage, a LAN peer or a remote store (GPU §2.5).
    SourceId
);
name_type!(
    /// A network or storage cut that several sources share (GPU §2.5).
    CutId
);
name_type!(
    /// One stage of a loading pipeline, such as read, verify, transfer or decode
    /// (GPU §2.5).
    StageId
);
name_type!(
    /// One prefetch candidate (GPU §2.9).
    CandidateId
);

pub mod bounds;
pub mod calibration;
pub mod chunking;
pub mod compression;
pub mod overlap;
pub mod prefetch;
pub mod recompute;
pub mod sources;

#[cfg(test)]
mod test_support;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_refuses_instead_of_clamping() {
        assert_eq!(non_negative("x", 0.0), Ok(0.0));
        assert_eq!(
            non_negative("x", -1.0),
            Err(InputError::Negative { field: "x" })
        );
        assert_eq!(
            non_negative("x", f64::NAN),
            Err(InputError::NotFinite { field: "x" })
        );
        assert_eq!(
            positive("x", 0.0),
            Err(InputError::NotPositive { field: "x" })
        );
        assert_eq!(
            positive("x", f64::INFINITY),
            Err(InputError::NotFinite { field: "x" })
        );
        assert_eq!(probability("p", 1.0), Ok(1.0));
        assert_eq!(
            probability("p", 1.0001),
            Err(InputError::OutOfRange { field: "p" })
        );
    }

    #[test]
    fn names_are_checked() {
        use crate::foundation::ids::IdError;

        // Resource names follow the shared identifier rules.
        assert_eq!(
            ResourceId::new("pcie0:h2d").map(|id| id.to_string()),
            Ok("pcie0:h2d".into())
        );
        assert_eq!(
            ResourceId::new("nvme0 read"),
            Err(IdError::InvalidCharacter { character: ' ' })
        );
        assert_eq!(ResourceId::new("-nic0"), Err(IdError::InvalidStart));
        assert_eq!(ResourceId::new(""), Err(IdError::Empty));
        assert!(ResourceId::generate().as_str().starts_with("res-"));
        assert_eq!(
            SourceId::new(""),
            Err(InputError::Empty { field: "SourceId" })
        );
        assert!(CutId::new("a\nb").is_err());
        assert!(StageId::new("x".repeat(MAX_NAME_LEN)).is_ok());
        assert!(StageId::new("x".repeat(MAX_NAME_LEN + 1)).is_err());
    }
}
