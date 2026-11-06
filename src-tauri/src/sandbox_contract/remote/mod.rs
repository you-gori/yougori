//! V12: the remote VM adapter and SSH management contracts, the pure halves of VM-W39 and
//! VM-W41, with the attestation checks of §7.6
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md, VM part §1.2–§1.3, §6.2, §6.3, §7.6;
//! VM-W39, VM-W41; VM-D4–VM-D6, VM-D14; VM-P40–VM-P42; VM-CP-32, VM-CP-33).
//!
//! Tier 0 only (§12.1): pure, synchronous library code. The provider, the SSH transport,
//! the attestation vendor verifier and the nonce source are ports, and the tests drive
//! fakes. Nothing here opens a connection, runs a remote command, calls a provider or an
//! attestation service, or reads any clock but the injected
//! [`Clock`](crate::foundation::ids::Clock). The tests therefore prove the contract and
//! nothing about a real provider, SSH server, TEE, verifier or network. The runtime and
//! cloud integration (`runtime/cloud/`, the NeoCloud provider code, the remote agent) is
//! later work under the VM-W39 and VM-W41 file-ownership rows and is not here.
//!
//! - `offering`: remote offering records (§7.6, VM-D5) and their selection. Only a
//!   dedicated provider VM, or a host (bare metal or not) that launches the per-sandbox
//!   VM, can satisfy a VM-sandbox requirement; a provider container is never a VM
//!   backend and is selected only by an explicit request as the labelled "remote runtime
//!   (provider container), not a sandbox", with credentials held at home. With no VM path
//!   a VM-required request is refused before anything is provisioned (VM-P42).
//! - `adapter`: the remote-VM adapter state machine (VM-W39): spend reservation,
//!   provisioning, runtime-category confirmation through CORE-01, host-key enrollment,
//!   an authenticated control session, delegation the host alone grants (a CORE-04
//!   service lease for a remote VM, the coordinator's labelled-runtime record for a
//!   provider container), termination retried until the provider confirms it, and
//!   billing settled through the V07 spend ledger, where an uncertain outcome counts as
//!   spent; each §6.3 acknowledgment is a CORE-04 revocation milestone.
//! - `ssh`: host-key enrollment through a supported flow with every trust assumption
//!   recorded, refusal of a changed key, the management identity (a type that cannot
//!   carry workload grants) and capability evidence that tells a remote host shell from
//!   a VM workload (VM-W41).
//! - `rejection`: the record of a rejected enrollment (M16E): a host seen presenting
//!   another key, by the control connect or by management SSH, has that enrollment
//!   refused by every check until it is enrolled again under a new generation, and the
//!   run's delegation ends at once.
//! - `argv`: typed remote argv and the one encoder for the remote POSIX shell; secrets
//!   go over stdin through typed operations such as the VM-D14 Jupyter password
//!   replacement.
//! - `control`: the authenticated control session (CORE-05 HMAC-SHA256 and endpoint
//!   identity) bound to the enrolled remote identity.
//! - `lease`: the host-side delegation port over the CORE-04 coordinator: service
//!   leases behind V05's expiry guard, labelled-runtime records (VM-D5), revocation
//!   acknowledgments, and the post-revocation bound of a remote enforcement point.
//! - `attestation`: typed attestation report checks (§7.6 paragraph 4, VM-P41,
//!   VM-CP-32), reported as per-check verdicts, one facet verdict and exact coverage of
//!   CPU, memory, storage and GPU portions, never as a score (§1.3).
//!
//! Claims. The adapter enforces, within this library, the transitions and refusals its
//! tests show: authority the host let expire is never renewed by the remote side or
//! revived by a reconnect; a changed host key, seen at connect or reported by
//! management, is recorded against the enrollment, which every check then refuses, and
//! ends delegation at once, as excessive clock skew does; a stale identity is refused, so
//! delegation runs out at its expiry; provider, region and isolation never change
//! silently. The argv encoder keeps each argument one literal word for a POSIX shell
//! only. The attestation checks judge typed fixtures; parsing real report formats and
//! verifying real vendor chains belong to the verifier port, which is faked here. A
//! verified report says nothing about runtime behaviour or user intent (§1.2), and a
//! confidential VM is not thereby better contained (§1.3).

/// Defines an internally tagged, snake_case enum whose deserialization refuses unknown
/// fields for every variant, unit variants included. serde ignores unknown fields beside
/// the tag of a unit variant even with `deny_unknown_fields`, so reading goes through a
/// twin enum whose unit variants are empty struct variants. The pattern is
/// `strict_policy_enum!` from `sandbox_contract/policy/mod.rs`, kept local.
macro_rules! strict_remote_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident tag $tag:literal {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident $({
                    $(
                        $(#[$field_meta:meta])*
                        $field:ident : $ty:ty
                    ),* $(,)?
                })?
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(serde::Serialize)]
        #[serde(tag = $tag, rename_all = "snake_case")]
        $vis enum $name {
            $(
                $(#[$variant_meta])*
                $variant $({ $($(#[$field_meta])* $field : $ty),* })?
            ),*
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                #[derive(serde::Deserialize)]
                #[serde(tag = $tag, rename_all = "snake_case", deny_unknown_fields)]
                enum Strict {
                    $($variant { $($($field : $ty),*)? }),*
                }
                let record = crate::foundation::strict_serde::read_tagged(deserializer, $tag)?;
                let strict = <Strict as serde::Deserialize>::deserialize(record)
                    .map_err(serde::de::Error::custom)?;
                Ok(match strict {
                    $(Strict::$variant { $($($field),*)? } => Self::$variant $({ $($field),* })?),*
                })
            }
        }
    };
}

/// Declares a name type checked against the ids.rs identifier grammar.
macro_rules! remote_name {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Accepts the ids.rs identifier grammar: 1–128 letters, digits, '.', '_', ':'
            /// or '-', starting with a letter or digit.
            pub fn new(
                value: impl Into<String>,
            ) -> Result<Self, crate::foundation::ids::IdError> {
                let value = value.into();
                crate::foundation::ids::validate_identifier(&value)?;
                Ok(Self(value))
            }

            /// The name as text.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self, D::Error> {
                Self::new(<String as serde::Deserialize>::deserialize(deserializer)?)
                    .map_err(serde::de::Error::custom)
            }
        }
    };
}

mod adapter;
mod argv;
mod attestation;
mod control;
mod lease;
mod offering;
mod peer;
mod rejection;
mod ssh;

#[cfg(test)]
pub(crate) mod fakes;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_host_key;
#[cfg(test)]
mod tests_lifecycle;

pub use adapter::{
    AdapterConfig, AdapterRefusal, AdapterState, AdapterStep, AttemptId, AuthorityEnd,
    BillingOutcome, BillingReport, CleanupFailure, CleanupStatus, ConfidentialLaunch, Delegation,
    FrameOutcome, LookupOutcome, ProviderError, ProviderInstance, ProvisionOutcome,
    ProvisionRequest, RemoteProviderPort, RemoteVmAdapter, Substitution, TerminationOutcome,
    TransitionEntry, UncertainCause,
};
pub use argv::{
    encode_posix, replace_jupyter_password, ArgvRefusal, EncodedCommand, OptionTerminator,
    ProgramPath, RemoteArg, RemoteCommand, RemoteInvocation, RemoteSecret, StdinPayload,
    MAX_ENCODED_COMMAND_BYTES, MAX_PROGRAM_PATH_BYTES, MAX_REMOTE_ARG_BYTES,
    MIN_JUPYTER_PASSWORD_BYTES,
};
pub use attestation::{
    report_data, AttestationBook, AttestationChallenge, AttestationNonce, AttestationPolicy,
    AttestationRecord, AttestationRefusal, AttestationReport, AttestationResult, AttestationUse,
    ChainRejection, CheckName, CheckOutcome, CheckVerdict, CoverageTarget, CpuCoverage,
    FacetVerdict, GpuCoverage, GpuProblem, GpuReport, GpuReportBody, MeasuredImage, MemoryCoverage,
    NonceSource, Portion, ProtectionCoverage, ReportBody, ReportOrigin, StorageCoverage,
    TcbComponent, TcbStatus, TeePlatform, VendorVerdict, VendorVerifier, VolumeName,
    REPORT_DATA_DOMAIN,
};
pub use control::{
    ControlBody, ControlFrame, ControlKey, ControlPeer, ControlRefusal, ControlSession,
    ControlSessionId, FrameTag, GrantRef, LeaseGrant, RemoteIdentity, SealedFrame, SessionState,
    CONTROL_FRAME_DOMAIN,
};
pub use lease::{
    remote_authority_bound, CoordinatorDelegation, HostAuthority, LabelledGrant,
    RemoteAuthorityBound,
};
pub use offering::{
    select_remote, vm_kinds, CredentialPlacement, OfferingKind, OfferingName, OfferingPrice,
    OfferingRefusal, OfferingRefusalReason, OfferingShape, PriceProblem, RegionName,
    RemoteOffering, RemoteRequest, RemoteSelection, RemoteSelectionRefusal, VmPath,
};
pub use peer::{RemoteGrantBound, RemoteGrantRefusal, RemoteGrantWindow};
pub use rejection::{
    HostKeyRejection, PrintedFingerprint, RejectionEvidence, RejectionObserver, RejectionRefusal,
    MAX_PRINTED_FINGERPRINT_BYTES,
};
pub use ssh::{
    EnrollmentEvidence, EnrollmentFlow, EnrollmentGeneration, EnrollmentPolicy, EnrollmentRefusal,
    ExecutionContext, HostEnrollment, HostKey, HostKeyAlgorithm, HostKeyFingerprint,
    HostKeyProblem, HostKeyRefusal, KnownHosts, KnownHostsRestoreRefusal, KnownHostsState,
    ManagementAction, ManagementIdentity, ManagementRefusal, RemoteAccountName, RemoteCapability,
    RemoteCapabilityEvidence, RemoteEvidenceRefusal, RemoteHostId, RemoteShellKind, RemoteVmId,
    TrustAssumption, VmWorkloadEvidence, MAX_HOST_KEY_BYTES,
};
