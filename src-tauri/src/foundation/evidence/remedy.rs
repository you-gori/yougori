//! What the user can do about a refusal (S2 CORE-01 "refusal reason"; CORE-07
//! "actionable refusal").

use std::fmt;

use super::envelope::SourceClass;

strict_evidence_enum! {
    /// The action a refusal asks of the user (CORE-01, CORE-07).
    ///
    /// None of these is carried out automatically. Yougori never changes global driver
    /// settings, antivirus exclusions or power policy on the user's behalf (S7, consumer
    /// hardware); where such a change would help, the user makes it.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum Remedy tag "action" {
        /// Run the check; no evidence exists yet.
        RunCheck,
        /// Run the check again: the evidence is too old, from another clock or
        /// inconclusive.
        RunCheckAgain,
        /// Run the check again under the current configuration.
        RecheckCurrentConfiguration,
        /// Obtain evidence from at least this source, such as a host probe.
        ObtainStrongerEvidence { required: SourceClass },
        /// Choose a runtime or device that supports the capability.
        ChooseSupportedRuntime,
        /// Turn on hardware virtualization and the platform hypervisor yourself, or use a
        /// remote VM.
        EnableHypervisorYourself,
        /// Choose a runtime whose execution category the request allows (INT-07).
        ChooseAllowedCategory,
        /// Continue with the ordinary authorized loader, or drop the requirement for the
        /// optimization (INT-06).
        UseOrdinaryLoader,
        /// Use one of the conflicting modes at a time (GPU part §1.1).
        UseOneModeAtATime,
        /// Use a backend release whose support for the mode is recorded.
        UseRecordedBackendRelease,
        /// Keep the fallback within the authorized runtime; anything else is a new,
        /// separately authorized request (S3.5).
        KeepWithinAuthorizedRuntime,
        /// Repair or reinstall the host perimeter, which takes one elevated install step
        /// (VM-D3), then run the must-probe again.
        RepairPerimeter,
    }
}

impl fmt::Display for Remedy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RunCheck => f.write_str("run the check"),
            Self::RunCheckAgain => f.write_str("run the check again"),
            Self::RecheckCurrentConfiguration => {
                f.write_str("run the check again under the current configuration")
            }
            Self::ObtainStrongerEvidence { required } => {
                write!(f, "obtain evidence from a {required} or a stronger source")
            }
            Self::ChooseSupportedRuntime => {
                f.write_str("choose a runtime or device that supports it")
            }
            Self::EnableHypervisorYourself => f.write_str(
                "turn on hardware virtualization and the platform hypervisor yourself, or use \
                 a remote VM; Yougori does not change host settings",
            ),
            Self::ChooseAllowedCategory => {
                f.write_str("choose a runtime of a category this request allows")
            }
            Self::UseOrdinaryLoader => f.write_str(
                "continue with the ordinary loader, or remove the requirement for this \
                 optimization",
            ),
            Self::UseOneModeAtATime => f.write_str("use one of these modes at a time"),
            Self::UseRecordedBackendRelease => {
                f.write_str("use a backend release whose support for this mode is recorded")
            }
            Self::KeepWithinAuthorizedRuntime => f.write_str(
                "keep the fallback within the authorized runtime; anything else needs a new, \
                 separately authorized request",
            ),
            Self::RepairPerimeter => f.write_str(
                "repair or reinstall the host perimeter, which takes one elevated install step, \
                 then run the must-probe again",
            ),
        }
    }
}
