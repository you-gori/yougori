//! The compute platform a runtime computes on, judged through CORE-01 `ComputePlatform`
//! evidence (GPU part §3.8, CPU/Metal/other row: "CUDA mechanisms are not silently
//! assumed").
//!
//! A runtime is assembled with a declared platform, and the declaration only ever
//! refuses: an enabled CUDA mechanism off a declared CUDA platform is refused at once.
//! Anything that rests on the runtime computing on CUDA needs fresh CORE-01 evidence
//! about exactly that runtime, under its configuration fingerprint, from at least a guest
//! report and within the runtime's platform policy, and that evidence must show the
//! declared platform.

use std::fmt;

use serde::Serialize;

use super::declarations::ComputePlatform;
use crate::foundation::evidence::{self, EvidenceRefusal, Remedy};

impl From<evidence::ComputePlatform> for ComputePlatform {
    fn from(platform: evidence::ComputePlatform) -> Self {
        match platform {
            evidence::ComputePlatform::Cuda => Self::Cuda,
            evidence::ComputePlatform::Metal => Self::Metal,
            evidence::ComputePlatform::Cpu => Self::Cpu,
        }
    }
}

/// Why a runtime's declared platform was not shown by CORE-01 evidence, so nothing that
/// rests on it computing on CUDA is admitted (GPU part §3.8).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum PlatformRefusal {
    /// The runtime has no platform evidence policy (`BackendRuntime::with_platform_policy`),
    /// so its declared platform is never taken as shown.
    NoPolicy,
    /// Admission without the evidence registry cannot judge the platform
    /// (`BackendRuntime::admit_with_evidence` can).
    NotRechecked,
    /// CORE-01 holds no evidence that meets the platform requirement: it is missing, from
    /// a weaker source, observed under another configuration, stale or from another clock
    /// session, or not conclusive.
    Evidence { cause: EvidenceRefusal },
    /// The evidence given is not compute-platform evidence about this runtime, under its
    /// configuration, source and age policy.
    OtherEvidence,
    /// Fresh evidence shows another platform than the one the runtime was declared with.
    Contradicted {
        declared: ComputePlatform,
        observed: ComputePlatform,
    },
}

impl PlatformRefusal {
    /// What the user can do about it.
    pub fn remedy(&self) -> Remedy {
        match self {
            Self::NoPolicy | Self::OtherEvidence => Remedy::RunCheck,
            Self::NotRechecked => Remedy::RunCheckAgain,
            Self::Evidence { cause } => cause.remedy(),
            Self::Contradicted { .. } => Remedy::ChooseSupportedRuntime,
        }
    }
}

impl fmt::Display for PlatformRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let remedy = self.remedy();
        match self {
            Self::NoPolicy => write!(
                f,
                "the runtime's platform is only declared: no policy says what evidence shows \
                 it; {remedy}"
            ),
            Self::NotRechecked => write!(
                f,
                "the runtime's platform is judged only against fresh evidence, which this \
                 admission did not recheck; {remedy}"
            ),
            Self::Evidence { cause } => {
                write!(f, "no fresh evidence shows the runtime's platform: {cause}")
            }
            Self::OtherEvidence => write!(
                f,
                "the evidence given is not compute-platform evidence about this runtime \
                 under its configuration and policy; {remedy}"
            ),
            Self::Contradicted { declared, observed } => write!(
                f,
                "the runtime was declared to compute on {declared}, and evidence shows \
                 {observed}; {remedy}"
            ),
        }
    }
}

impl std::error::Error for PlatformRefusal {}
