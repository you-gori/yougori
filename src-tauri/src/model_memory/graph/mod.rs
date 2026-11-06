//! The request state graph and the four granularities: GPU §2.3 and §2.4 of
//! docs/combined-gpu-memory-and-vm-sandbox-plan.md, with §1's three paths at graph level.
//!
//! - [`node`]: what each node of the request DAG carries (§2.3).
//! - [`dag`]: the validated DAG G=(V,E), the trust-scope rule and the first-correct-token
//!   objective (§2.3).
//! - [`schedule`]: the finish recurrence for a fixed schedule, resource-conflict ordering
//!   edges and capacity checks (§2.3).
//! - [`heuristic`]: bounded list scheduling, critical-path first with one memory-pressure
//!   retry, under one explicit work bound (§2.3).
//! - [`oracle`]: the exhaustive offline oracle for tiny graphs and its comparison with the
//!   heuristic (§2.3).
//! - [`paths`]: use what is ready, materialize only what is missing, overlap the rest (§1).
//! - [`granularity`]: g_h, g_c, g_v and g_t, candidate ranges and canonical padding
//!   (§1.1, §2.4).
//! - [`scatter_gather`]: the map relating the four granularities, and coalescing (§2.4).
//!
//! Everything here is pure, synchronous and deterministic. Times are
//! [`std::time::Duration`] offsets from the start of a plan, absolute times come from
//! [`crate::foundation::ids::Clock`], and byte counts are `u64`. Invalid input is refused
//! with a typed error, never clamped into range. Identities are
//! [`crate::foundation::ids::Digest`] values; the typed identity layers of §3.2 attach
//! later.

use std::fmt;

mod error;
mod problem;

pub mod dag;
pub mod granularity;
pub mod heuristic;
pub mod node;
pub mod oracle;
pub mod paths;
pub mod scatter_gather;
pub mod schedule;

#[cfg(test)]
mod tests;

pub use crate::foundation::ids::{ResourceId, TrustScope};
pub use error::{GranularityError, GraphError, ScheduleError};

/// Longest accepted name.
pub const MAX_NAME_LEN: usize = 128;

macro_rules! name_type {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// Accepts 1–128 characters without control characters.
            pub fn new(value: impl Into<String>) -> Result<Self, GraphError> {
                let value = value.into();
                if value.is_empty()
                    || value.chars().count() > MAX_NAME_LEN
                    || value.chars().any(char::is_control)
                {
                    return Err(GraphError::InvalidName {
                        field: stringify!($name),
                        value,
                    });
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

name_type!(
    /// One node of a request graph (GPU §2.3). Names locate nodes; they never establish
    /// that two nodes hold the same state, which only their identities do (§3.2).
    NodeId
);
