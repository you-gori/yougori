//! Input errors shared by the routing, replication and distributed-execution models
//! (GPU §4.6–§4.8). Domain refusals, such as an unauthorized endpoint or an infeasible
//! schedule, have their own types next to the rule they enforce.

use std::fmt;

use crate::foundation::ids::IdError;
use crate::foundation::report::ReportError;
use crate::model_memory::identity::{GrantRefusal, IdentityError};
use crate::model_memory::math::bounds::BoundsError;
use crate::model_memory::math::sources::SourcesError;
use crate::model_memory::math::InputError;

use super::claims::ClaimError;

/// Why an input was refused. Nothing is clamped into range.
#[derive(Clone, Debug, PartialEq)]
pub enum RoutingError {
    /// A number, list or name is out of its range (GPU §2 cost-model rules).
    Input(InputError),
    /// A duration beats the GPU §2.2 lower bound, or a bandwidth is not measured.
    Bounds(BoundsError),
    /// The GPU §2.5 multi-source planner refused its inputs.
    Sources(SourcesError),
    /// CORE-08 refused a fake-substrate record or comparison.
    Report(ReportError),
    /// A §3.2 identity could not be built.
    Identity(IdentityError),
    /// A shared identifier was refused.
    Id(IdError),
    /// A duration does not fit the record clock in nanoseconds.
    TimeOutOfRange { field: &'static str },
    /// A requested model listed execution specs of more than one logical model; that
    /// would be a model substitution, not a choice among executions (§4.6, line 716).
    MixedLogicalModels,
    /// A §4.17 claim record was refused.
    Claim(ClaimError),
    /// The CORE-02 catalog did not back a scoped grant (S3.3).
    Grant(GrantRefusal),
}

impl From<GrantRefusal> for RoutingError {
    fn from(error: GrantRefusal) -> Self {
        Self::Grant(error)
    }
}

impl From<ClaimError> for RoutingError {
    fn from(error: ClaimError) -> Self {
        Self::Claim(error)
    }
}

impl From<InputError> for RoutingError {
    fn from(error: InputError) -> Self {
        Self::Input(error)
    }
}

impl From<BoundsError> for RoutingError {
    fn from(error: BoundsError) -> Self {
        Self::Bounds(error)
    }
}

impl From<SourcesError> for RoutingError {
    fn from(error: SourcesError) -> Self {
        Self::Sources(error)
    }
}

impl From<ReportError> for RoutingError {
    fn from(error: ReportError) -> Self {
        Self::Report(error)
    }
}

impl From<IdentityError> for RoutingError {
    fn from(error: IdentityError) -> Self {
        Self::Identity(error)
    }
}

impl From<IdError> for RoutingError {
    fn from(error: IdError) -> Self {
        Self::Id(error)
    }
}

impl fmt::Display for RoutingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(error) => error.fmt(f),
            Self::Bounds(error) => error.fmt(f),
            Self::Sources(error) => error.fmt(f),
            Self::Report(error) => error.fmt(f),
            Self::Identity(error) => error.fmt(f),
            Self::Id(error) => error.fmt(f),
            Self::TimeOutOfRange { field } => {
                write!(f, "{field} does not fit the record clock in nanoseconds")
            }
            Self::Claim(error) => error.fmt(f),
            Self::Grant(error) => error.fmt(f),
            Self::MixedLogicalModels => f.write_str(
                "a requested model lists executions of more than one logical model; models are never substituted",
            ),
        }
    }
}

impl std::error::Error for RoutingError {}
