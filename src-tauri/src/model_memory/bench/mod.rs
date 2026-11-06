//! Fake time-controlled runners and the FAST-01 corpus: BENCH-01, BENCH-02 and a short
//! BENCH-07 run on fakes (docs/combined-gpu-memory-and-vm-sandbox-plan.md S10 line 183,
//! S11 lines 193–194 and 199, S12 G0 line 211, S13 FAST-01 line 241; rollout task T12).
//!
//! - [`profile`]: the four S10 baseline modes, with every duration and resource effect a
//!   parameter, checked against the GPU §2.2 lower bound ([`crate::model_memory::math`]).
//! - [`runner`]: the fake runner, driven by a
//!   [`ManualClock`](crate::foundation::ids::ManualClock) with seeded variation
//!   ([`rng`]); the first token after a load follows GPU §2.6.
//! - [`faults`]: crash, disk-full, OOM, lost-event and stalled-provider injection, each
//!   landing in the CORE-08 failure taxonomy; a recycle is a visible recovery event.
//! - [`resources`]: the S10 tracked resources and the short-run trend rule (BENCH-07).
//! - [`load`]: BENCH-01 at concurrency 1, 8 and 32, then a measured saturation search.
//! - [`switching`]: BENCH-02 A/B/A switches with both S8 switch clocks and the GPU §2.1
//!   switch overhead, and the short repeated-switch BENCH-07 run.
//! - [`corpus`]: the FAST-01 fixtures, fresh-prefill and warm-prefix suites, and the
//!   disclosed cold-test nonce.
//! - [`fast01`]: the corpus served on a fake, with fresh-prefill and warm-prefix attempts
//!   in separate ledgers.
//!
//! Every attempt is a CORE-08 [`RunRecord`](crate::foundation::report::RunRecord) on the
//! fake, time-controlled substrate (S12 G0). Nothing here starts a process, touches a
//! GPU or stands for a real measurement; energy and power are "not measured".

pub mod corpus;
pub mod fast01;
pub mod faults;
pub mod load;
pub mod profile;
pub mod resources;
pub mod rng;
pub mod runner;
pub mod switching;

#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;

use std::fmt;

use crate::foundation::evidence::ModeRefusal;
use crate::foundation::ids::IdError;
use crate::foundation::report::ReportError;
use crate::model_memory::math::bounds::BoundsError;
use crate::model_memory::math::overlap::OverlapError;
use crate::model_memory::math::InputError;

/// Why the bench refused an input or could not finish a run.
#[derive(Clone, Debug, PartialEq)]
pub enum BenchError {
    /// A parameter is out of its range.
    InvalidParameter {
        field: &'static str,
        reason: &'static str,
    },
    /// S12: a model-serving fake keeps a VM-D4–VM-D6 label and is never a VM sandbox.
    ServingCategoryNotLabelled,
    UnknownModel {
        model: String,
    },
    DuplicateModel {
        model: String,
    },
    /// A fake duration beats the GPU §2.2 lower bound for the bytes it moves.
    BelowPhysicalBound {
        model: String,
        operation: &'static str,
        claimed_seconds: f64,
        lower_bound_seconds: f64,
    },
    Bounds(BoundsError),
    Overlap(OverlapError),
    Input(InputError),
    /// A shared identifier, such as a resource name, was refused.
    Id(IdError),
    /// The backend release does not record the mode or the combination (S7; CORE-01).
    Mode(ModeRefusal),
    /// CORE-08 refused a record, ledger or summary.
    Report(ReportError),
    /// A capacity would be exceeded; names the limiting resource.
    Capacity {
        resource: &'static str,
        required_bytes: u64,
        available_bytes: u64,
    },
    /// The operation does not fit the runner's mode or the model's state.
    WrongState {
        operation: &'static str,
        reason: &'static str,
    },
    /// S8: a cold state comes from a fresh fake, never from flushing caches or stopping
    /// an engine.
    ColdStateUnavailable {
        model: String,
    },
    /// S8 names a cold start only as a cold process start, so a cold load inside a
    /// running process has no switch label.
    NoSwitchLabel,
    /// A fault was scheduled before the current time.
    FaultInThePast,
    /// Someone else moved the runner's clock past its next event.
    ClockAhead,
    /// A time or count does not fit in 64 bits.
    Overflow,
    /// A value could not be encoded for a digest.
    Encoding,
    /// FAST-01: a fixture is malformed.
    Fixture {
        id: &'static str,
        reason: &'static str,
    },
    /// FAST-01: a nonce in the prompt must be disclosed.
    UndisclosedNonce,
    /// FAST-01: a nonce that does not change the prompt cannot make a fresh prefill.
    NonceCannotMakeFreshPrefill,
    /// FAST-01: fresh-prefill and warm-prefix tests are kept separate.
    MixedPrefillModes,
    /// FAST-01: the best run is a diagnostic only.
    BestRunIsDiagnostic,
    /// FAST-01: temperature zero alone does not establish token identity.
    TokenIdentityNotEstablished,
    /// S7, BENCH-07: a fake run never backs a no-leak claim, however long its simulated
    /// time.
    NoLeakClaimFromFake {
        simulated_seconds: u64,
        switches: u64,
    },
    /// §2.1: a comparison of these start states is not a cold-load improvement.
    NotColdLoad,
}

impl fmt::Display for BenchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidParameter { field, reason } => write!(f, "{field}: {reason}"),
            Self::ServingCategoryNotLabelled => f.write_str(
                "a model-serving runner keeps its VM-D4–VM-D6 label; it is not a VM sandbox",
            ),
            Self::UnknownModel { model } => write!(f, "no model named {model}"),
            Self::DuplicateModel { model } => write!(f, "{model} is listed twice"),
            Self::BelowPhysicalBound {
                model,
                operation,
                claimed_seconds,
                lower_bound_seconds,
            } => write!(
                f,
                "{operation} of {model} in {claimed_seconds} s beats the physical lower bound of {lower_bound_seconds} s"
            ),
            Self::Bounds(error) => error.fmt(f),
            Self::Overlap(error) => error.fmt(f),
            Self::Input(error) => error.fmt(f),
            Self::Id(error) => error.fmt(f),
            Self::Mode(refusal) => refusal.fmt(f),
            Self::Report(error) => error.fmt(f),
            Self::Capacity {
                resource,
                required_bytes,
                available_bytes,
            } => write!(
                f,
                "{resource} is the limiting resource: {required_bytes} bytes needed, {available_bytes} available"
            ),
            Self::WrongState { operation, reason } => write!(f, "{operation}: {reason}"),
            Self::ColdStateUnavailable { model } => write!(
                f,
                "{model} is not cold here; a cold start needs a fresh fake, not a flushed cache"
            ),
            Self::NoSwitchLabel => {
                f.write_str("a cold load inside a running process has no S8 switch label")
            }
            Self::FaultInThePast => f.write_str("a fault was scheduled before the current time"),
            Self::ClockAhead => f.write_str("the clock moved past the runner's next event"),
            Self::Overflow => f.write_str("a time or count does not fit in 64 bits"),
            Self::Encoding => f.write_str("a value could not be encoded"),
            Self::Fixture { id, reason } => write!(f, "fixture {id}: {reason}"),
            Self::UndisclosedNonce => f.write_str("a cold-test nonce must be disclosed"),
            Self::NonceCannotMakeFreshPrefill => f.write_str(
                "a request-metadata nonce leaves the prompt unchanged and cannot make a fresh prefill",
            ),
            Self::MixedPrefillModes => {
                f.write_str("fresh-prefill and warm-prefix attempts are kept separate")
            }
            Self::BestRunIsDiagnostic => f.write_str("the best run is a diagnostic, not a claim"),
            Self::TokenIdentityNotEstablished => {
                f.write_str("temperature zero alone does not establish token identity")
            }
            Self::NoLeakClaimFromFake {
                simulated_seconds,
                switches,
            } => write!(
                f,
                "{switches} switches over {simulated_seconds} simulated seconds on a fake cannot back a no-leak claim"
            ),
            Self::NotColdLoad => {
                f.write_str("only a cold-versus-cold comparison is a cold-load improvement")
            }
        }
    }
}

impl std::error::Error for BenchError {}

impl From<BoundsError> for BenchError {
    fn from(error: BoundsError) -> Self {
        Self::Bounds(error)
    }
}

impl From<OverlapError> for BenchError {
    fn from(error: OverlapError) -> Self {
        Self::Overlap(error)
    }
}

impl From<InputError> for BenchError {
    fn from(error: InputError) -> Self {
        Self::Input(error)
    }
}

impl From<IdError> for BenchError {
    fn from(error: IdError) -> Self {
        Self::Id(error)
    }
}

impl From<ModeRefusal> for BenchError {
    fn from(refusal: ModeRefusal) -> Self {
        Self::Mode(refusal)
    }
}

impl From<ReportError> for BenchError {
    fn from(error: ReportError) -> Self {
        Self::Report(error)
    }
}
