//! Confidential-computing attestation checks (VM part §7.6 line 2249; VM-P41; VM-CP-32;
//! §1.2: a report does not prove runtime behaviour or intent; §1.3: facets, not a score).
//!
//! A report answers one host challenge: a fresh nonce from a [`NonceSource`], bound with
//! the control session's key and the expected workload into the report data. Checking it
//! covers every item of §7.6: vendor chain (through the [`VendorVerifier`] port), report
//! freshness and nonce, measurement against an allowlist, minimum security versions,
//! debug state, revoked or unsupported TCB, and binding to the session key and the
//! workload. A self-reported measurement or a vTPM quote alone never satisfies the
//! profile, whatever else it says.
//!
//! Each check is reported on its own as a [`CheckVerdict`]. Claims inside a report whose
//! origin or vendor chain did not verify are not evaluated at all. The outcome is one
//! verdict on the operator-confidentiality facet and a [`ProtectionCoverage`] that states
//! exactly which vCPUs, how many memory bytes, which volumes and which GPUs the verified
//! claims cover; a refused report covers nothing. There is no score.
//!
//! Parsing real report formats (SEV-SNP, TDX, GPU) and verifying real certificate chains
//! and revocation collateral belong to the verifier port; the tests use a fake that
//! signs fixtures with HMAC. A challenge is answered once: its nonce is consumed by the
//! first report that names it, accepted or not.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{Digest, DigestBuilder, MonotonicTime};
use crate::sandbox_contract::policy::DeploymentFacet;

remote_name!(
    /// One component of a platform's trusted computing base, such as `snp` or
    /// `microcode`, whose security version is checked.
    TcbComponent
);
remote_name!(
    /// One storage volume of a remote instance.
    VolumeName
);

/// The confidential-computing platform a report comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeePlatform {
    AmdSevSnp,
    IntelTdx,
}

impl TeePlatform {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::AmdSevSnp => "amd_sev_snp",
            Self::IntelTdx => "intel_tdx",
        }
    }
}

/// What produced the report.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportOrigin {
    /// Signed by the platform's hardware root through the vendor chain.
    HardwareSigned,
    /// Stated by software in the guest or by the provider; proves nothing (§7.6).
    SelfReported,
    /// A virtual TPM quote; alone it does not prove protection against the provider.
    VtpmQuote,
}

impl ReportOrigin {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::HardwareSigned => "hardware_signed",
            Self::SelfReported => "self_reported",
            Self::VtpmQuote => "vtpm_quote",
        }
    }
}

/// A challenge nonce, serialized as lowercase hexadecimal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AttestationNonce([u8; 32]);

impl AttestationNonce {
    pub const DOMAIN: &'static str = "yougori/remote/attestation-nonce/v1";

    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The challenge identity: the nonce's digest.
    pub fn id(&self) -> Digest {
        DigestBuilder::new(Self::DOMAIN).bytes(&self.0).finish()
    }
}

impl Serialize for AttestationNonce {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for AttestationNonce {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(text, &mut bytes).map_err(serde::de::Error::custom)?;
        Ok(Self(bytes))
    }
}

/// Where challenge nonces come from: an unpredictable source in production, a seeded
/// generator in tests.
pub trait NonceSource {
    fn next_nonce(&mut self) -> [u8; 32];
}

/// What the attested instance should have, so coverage can be stated against it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageTarget {
    pub vcpus: u32,
    pub memory_bytes: u64,
    pub volumes: BTreeSet<VolumeName>,
    /// GPU device indices.
    pub gpus: BTreeSet<u32>,
}

/// One outstanding challenge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationChallenge {
    pub nonce: AttestationNonce,
    /// The remote identity the report must come from.
    pub identity: Digest,
    /// The control session's key binding.
    pub session_key: Digest,
    /// The workload the report must be bound to.
    pub workload: Digest,
    pub target: CoverageTarget,
    pub clock: ClockSession,
    pub issued_at: MonotonicTime,
}

impl AttestationChallenge {
    pub fn id(&self) -> Digest {
        self.nonce.id()
    }
}

/// Domain of [`report_data`].
pub const REPORT_DATA_DOMAIN: &str = "yougori/remote/attestation-report-data/v1";

/// The report data a guest must place in its report: the nonce, the session key binding
/// and the workload, length-prefixed under [`REPORT_DATA_DOMAIN`].
pub fn report_data(nonce: &AttestationNonce, session_key: &Digest, workload: &Digest) -> Digest {
    DigestBuilder::new(REPORT_DATA_DOMAIN)
        .bytes(nonce.as_bytes())
        .digest(session_key)
        .digest(workload)
        .finish()
}

/// The signed body of a CPU attestation report, as typed fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportBody {
    pub platform: TeePlatform,
    pub origin: ReportOrigin,
    /// The 64 bytes the guest chose, here the [`report_data`] digest.
    pub report_data: Digest,
    pub bound_nonce: AttestationNonce,
    pub bound_session_key: Digest,
    pub bound_workload: Digest,
    /// The launch measurement.
    pub measurement: Digest,
    pub security_versions: BTreeMap<TcbComponent, u64>,
    pub debug_enabled: bool,
    /// The chip or platform identity the TCB status is looked up for.
    pub chip: Digest,
    /// vCPUs whose state the platform protects.
    pub protected_vcpus: u32,
    /// Guest memory encrypted with the VM's key.
    pub private_memory_bytes: u64,
    /// Memory shared with the host for device I/O, which the platform does not protect.
    pub shared_memory_bytes: u64,
}

impl ReportBody {
    pub const DOMAIN: &'static str = "yougori/remote/attestation-report/v1";

    /// Every field under [`ReportBody::DOMAIN`]; the vendor signature covers it.
    pub fn digest(&self) -> Digest {
        let versions = self.security_versions.iter().fold(
            DigestBuilder::new(Self::DOMAIN)
                .str(self.platform.tag())
                .str(self.origin.tag())
                .digest(&self.report_data)
                .bytes(self.bound_nonce.as_bytes())
                .digest(&self.bound_session_key)
                .digest(&self.bound_workload)
                .digest(&self.measurement)
                .u64(u64::try_from(self.security_versions.len()).unwrap_or(u64::MAX)),
            |builder, (component, version)| builder.str(component.as_str()).u64(*version),
        );
        versions
            .u64(u64::from(self.debug_enabled))
            .digest(&self.chip)
            .u64(u64::from(self.protected_vcpus))
            .u64(self.private_memory_bytes)
            .u64(self.shared_memory_bytes)
            .finish()
    }
}

/// The signed body of one GPU's attestation report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpuReportBody {
    pub device: u32,
    pub bound_nonce: AttestationNonce,
    pub bound_session_key: Digest,
    pub confidential_mode: bool,
    pub debug_enabled: bool,
    pub measurement: Digest,
    pub chip: Digest,
}

impl GpuReportBody {
    pub const DOMAIN: &'static str = "yougori/remote/gpu-attestation-report/v1";

    pub fn digest(&self) -> Digest {
        DigestBuilder::new(Self::DOMAIN)
            .u64(u64::from(self.device))
            .bytes(self.bound_nonce.as_bytes())
            .digest(&self.bound_session_key)
            .u64(u64::from(self.confidential_mode))
            .u64(u64::from(self.debug_enabled))
            .digest(&self.measurement)
            .digest(&self.chip)
            .finish()
    }
}

/// One GPU report with its chain and signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpuReport {
    pub body: GpuReportBody,
    /// Certificate digests, leaf first, root last.
    pub chain: Vec<Digest>,
    pub signature: Vec<u8>,
}

/// A typed attestation report as the remote returned it; untrusted until checked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationReport {
    pub body: ReportBody,
    /// Certificate digests, leaf first, root last.
    pub chain: Vec<Digest>,
    pub signature: Vec<u8>,
    pub gpus: Vec<GpuReport>,
}

impl AttestationReport {
    pub const DOMAIN: &'static str = "yougori/remote/attestation-record/v1";

    /// The CPU body and every GPU body, for records.
    pub fn digest(&self) -> Digest {
        self.gpus
            .iter()
            .fold(
                DigestBuilder::new(Self::DOMAIN)
                    .digest(&self.body.digest())
                    .u64(u64::try_from(self.gpus.len()).unwrap_or(u64::MAX)),
                |builder, gpu| builder.digest(&gpu.body.digest()),
            )
            .finish()
    }
}

/// The vendor's TCB status for a chip, from its collateral.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TcbStatus {
    UpToDate,
    /// A newer TCB is available.
    OutOfDate,
    Revoked,
    Unsupported,
}

/// Why the vendor chain was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainRejection {
    EmptyChain,
    UnknownRoot,
    BadSignature,
    CertificateRevoked,
}

strict_remote_enum! {
    /// What the vendor verifier found.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum VendorVerdict tag "verdict" {
        /// The chain leads to a trusted vendor root and the signature covers the body.
        Verified { tcb: TcbStatus },
        Rejected { reason: ChainRejection },
        /// The verifier or its collateral could not be reached; nothing is assumed.
        Unavailable,
    }
}

/// The vendor verifier port: certificate chains, signatures and TCB collateral.
pub trait VendorVerifier {
    fn verify_cpu(&self, report: &AttestationReport) -> VendorVerdict;
    fn verify_gpu(&self, report: &GpuReport) -> VendorVerdict;
}

/// What a reviewed, allowlisted image protects, known from its review rather than from
/// the report: the volumes it encrypts with a key released only after attestation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasuredImage {
    pub encrypted_volumes: BTreeSet<VolumeName>,
}

/// A portion of the instance that coverage is stated for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Portion {
    Cpu,
    Memory,
    Storage,
    Gpu,
}

/// What a confidential profile requires of a report (VM-P41).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationPolicy {
    pub platform: TeePlatform,
    /// Allowed launch measurements and what each image protects.
    pub measurements: BTreeMap<Digest, MeasuredImage>,
    pub min_security_versions: BTreeMap<TcbComponent, u64>,
    /// How long after the challenge a report may arrive.
    pub max_report_age_seconds: u64,
    /// Whether a TCB the vendor calls out of date is accepted; revoked and unsupported
    /// ones never are.
    pub allow_out_of_date_tcb: bool,
    pub gpu_measurements: BTreeSet<Digest>,
    /// The most memory the instance may share with the host for device I/O.
    pub max_shared_memory_bytes: u64,
    /// The portions that must be fully covered.
    pub required: BTreeSet<Portion>,
}

/// The checks of §7.6, each reported on its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckName {
    ReportOrigin,
    VendorChain,
    TcbStatus,
    Platform,
    Freshness,
    Nonce,
    ReportData,
    SessionKeyBinding,
    WorkloadBinding,
    Measurement,
    SecurityVersion,
    DebugState,
    GpuEvidence,
    Coverage,
}

impl CheckName {
    pub const ALL: [Self; 14] = [
        Self::ReportOrigin,
        Self::VendorChain,
        Self::TcbStatus,
        Self::Platform,
        Self::Freshness,
        Self::Nonce,
        Self::ReportData,
        Self::SessionKeyBinding,
        Self::WorkloadBinding,
        Self::Measurement,
        Self::SecurityVersion,
        Self::DebugState,
        Self::GpuEvidence,
        Self::Coverage,
    ];
}

strict_remote_enum! {
    /// Why one GPU report was refused.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum GpuProblem tag "problem" {
        ChainRejected { reason: ChainRejection },
        VerifierUnavailable,
        TcbRevoked,
        TcbUnsupported,
        TcbOutOfDate,
        StaleNonce,
        UnboundSessionKey,
        NotConfidentialMode,
        DebugEnabled,
        MeasurementNotAllowed,
        /// The device is not one of the instance's GPUs, or is reported twice.
        UnexpectedDevice,
    }
}

strict_remote_enum! {
    /// Why an attestation check failed (VM-P41).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum AttestationRefusal tag "refusal" {
        /// A self-reported measurement never satisfies the profile (§7.6).
        SelfReportedMeasurement,
        /// A vTPM alone does not prove protection against the provider (§7.6).
        VtpmAlone,
        ChainRejected { reason: ChainRejection },
        VerifierUnavailable,
        TcbRevoked,
        TcbUnsupported,
        TcbOutOfDate,
        PlatformMismatch { expected: TeePlatform, found: TeePlatform },
        StaleReport { age_nanos: u64, max_nanos: u64 },
        /// The challenge was issued on another clock session, such as before a restart.
        OtherClock,
        /// The nonce answers no outstanding challenge: already answered, or never issued.
        StaleNonce,
        /// The nonce source returned a nonce already used.
        NonceReused,
        /// The report data is not the binding of the claimed nonce, key and workload.
        ReportDataMismatch,
        UnboundSessionKey,
        UnboundWorkload,
        MeasurementNotAllowed { measurement: Digest },
        SecurityVersionBelowMinimum {
            component: TcbComponent,
            found: Option<u64>,
            minimum: u64,
        },
        DebugEnabled,
        GpuReportRefused { device: u32, problem: GpuProblem },
        PortionNotCovered { portion: Portion },
    }
}

impl fmt::Display for AttestationRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SelfReportedMeasurement => {
                f.write_str("a self-reported measurement does not prove protection")
            }
            Self::VtpmAlone => {
                f.write_str("a vTPM alone does not prove protection against the provider")
            }
            Self::ChainRejected { reason } => {
                write!(f, "the vendor chain was rejected: {reason:?}")
            }
            Self::VerifierUnavailable => f.write_str("the vendor verifier was unavailable"),
            Self::TcbRevoked => f.write_str("the platform's TCB is revoked"),
            Self::TcbUnsupported => f.write_str("the platform's TCB is unsupported"),
            Self::TcbOutOfDate => f.write_str("the platform's TCB is out of date"),
            Self::PlatformMismatch { expected, found } => {
                write!(f, "the report is from {found:?}, not {expected:?}")
            }
            Self::StaleReport { .. } => {
                f.write_str("the report arrived too long after the challenge")
            }
            Self::OtherClock => f.write_str("the challenge is from another clock session"),
            Self::StaleNonce => f.write_str("the nonce answers no outstanding challenge"),
            Self::NonceReused => f.write_str("the nonce source repeated a nonce"),
            Self::ReportDataMismatch => {
                f.write_str("the report data does not bind the claimed nonce, key and workload")
            }
            Self::UnboundSessionKey => {
                f.write_str("the report is not bound to this control session's key")
            }
            Self::UnboundWorkload => f.write_str("the report is not bound to this workload"),
            Self::MeasurementNotAllowed { measurement } => {
                write!(f, "measurement {measurement} is not allowed")
            }
            Self::SecurityVersionBelowMinimum {
                component,
                found,
                minimum,
            } => match found {
                Some(found) => write!(
                    f,
                    "{component} is at security version {found}, below {minimum}"
                ),
                None => write!(
                    f,
                    "{component} reports no security version; {minimum} needed"
                ),
            },
            Self::DebugEnabled => f.write_str("the platform's debug mode is enabled"),
            Self::GpuReportRefused { device, problem } => {
                write!(f, "GPU {device}'s report was refused: {problem:?}")
            }
            Self::PortionNotCovered { portion } => write!(f, "{portion:?} is not fully covered"),
        }
    }
}

impl std::error::Error for AttestationRefusal {}

strict_remote_enum! {
    /// How one check came out.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum CheckOutcome tag "outcome" {
        Passed,
        Failed { refusals: Vec<AttestationRefusal> },
        /// The check judges claims that did not verify, so it was not evaluated.
        NotEvaluated { because: CheckName },
        /// Nothing to check, such as GPU evidence on an instance without GPUs.
        NotApplicable,
    }
}

/// One check and its outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckVerdict {
    pub check: CheckName,
    pub outcome: CheckOutcome,
}

/// The vCPUs whose state the platform protects, of the instance's total.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CpuCoverage {
    pub protected_vcpus: u32,
    pub total_vcpus: u32,
}

impl CpuCoverage {
    /// Every vCPU of the instance is protected.
    pub fn is_full(&self) -> bool {
        self.total_vcpus > 0 && self.protected_vcpus == self.total_vcpus
    }
}

/// Guest memory encrypted with the VM's key, memory shared with the host (never
/// covered), and the instance's total.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryCoverage {
    pub private_bytes: u64,
    pub shared_bytes: u64,
    pub total_bytes: u64,
}

impl MemoryCoverage {
    /// Every byte is accounted for, and no more than `max_shared_bytes` is shared.
    pub fn is_full(&self, max_shared_bytes: u64) -> bool {
        self.private_bytes > 0
            && self.private_bytes.checked_add(self.shared_bytes) == Some(self.total_bytes)
            && self.shared_bytes <= max_shared_bytes
    }
}

/// The instance's volumes, split into those the measured image encrypts and the rest.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageCoverage {
    pub encrypted: BTreeSet<VolumeName>,
    pub not_covered: BTreeSet<VolumeName>,
}

/// The instance's GPUs, split into those with a verified confidential-mode report and
/// the rest.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpuCoverage {
    pub attested: BTreeSet<u32>,
    pub not_covered: BTreeSet<u32>,
}

/// Exactly what the verified claims cover (§7.6: "Report exactly what CPU, memory,
/// storage and GPU portions are covered").
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectionCoverage {
    pub cpu: CpuCoverage,
    pub memory: MemoryCoverage,
    pub storage: StorageCoverage,
    pub gpu: GpuCoverage,
}

impl ProtectionCoverage {
    /// Nothing covered: what a report that did not verify gets.
    pub fn none(target: &CoverageTarget) -> Self {
        Self {
            cpu: CpuCoverage {
                protected_vcpus: 0,
                total_vcpus: target.vcpus,
            },
            memory: MemoryCoverage {
                private_bytes: 0,
                shared_bytes: 0,
                total_bytes: target.memory_bytes,
            },
            storage: StorageCoverage {
                encrypted: BTreeSet::new(),
                not_covered: target.volumes.clone(),
            },
            gpu: GpuCoverage {
                attested: BTreeSet::new(),
                not_covered: target.gpus.clone(),
            },
        }
    }

    /// Whether `portion` is fully covered.
    pub fn covers(&self, portion: Portion, max_shared_memory_bytes: u64) -> bool {
        match portion {
            Portion::Cpu => self.cpu.is_full(),
            Portion::Memory => self.memory.is_full(max_shared_memory_bytes),
            Portion::Storage => self.storage.not_covered.is_empty(),
            Portion::Gpu => self.gpu.not_covered.is_empty(),
        }
    }
}

strict_remote_enum! {
    /// The verdict on the operator-confidentiality facet (§1.3).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum FacetVerdict tag "verdict" {
        /// Every check passed; the coverage says what it covers.
        Verified,
        Refused { refusals: Vec<AttestationRefusal> },
    }
}

/// The result of checking one report: per-check verdicts, exact coverage and one facet
/// verdict. Never a score.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationResult {
    /// The challenge answered, if the report's nonce named an outstanding one.
    pub challenge: Option<Digest>,
    pub identity: Option<Digest>,
    pub session_key: Option<Digest>,
    pub workload: Option<Digest>,
    pub platform: TeePlatform,
    pub checks: Vec<CheckVerdict>,
    pub coverage: ProtectionCoverage,
    pub facet: DeploymentFacet,
    pub verdict: FacetVerdict,
    pub clock: ClockSession,
    pub verified_at: MonotonicTime,
}

impl AttestationResult {
    /// Whether the facet verdict is verified.
    pub fn is_accepted(&self) -> bool {
        self.verdict == FacetVerdict::Verified
    }

    /// The outcome of `check`.
    pub fn outcome(&self, check: CheckName) -> Option<&CheckOutcome> {
        self.checks
            .iter()
            .find(|verdict| verdict.check == check)
            .map(|verdict| &verdict.outcome)
    }
}

strict_remote_enum! {
    /// Why a recorded result cannot back a launch.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum AttestationUse tag "reason" {
        NotAccepted,
        OtherIdentity,
        OtherSessionKey,
        OtherWorkload,
        OtherClock,
        Stale { age_nanos: u64, max_nanos: u64 },
    }
}

impl fmt::Display for AttestationUse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotAccepted => "the attestation was refused",
            Self::OtherIdentity => "the attestation is for another remote identity",
            Self::OtherSessionKey => "the attestation is bound to another control session",
            Self::OtherWorkload => "the attestation is bound to another workload",
            Self::OtherClock => "the attestation is from another clock session",
            Self::Stale { .. } => "the attestation is too old",
        })
    }
}

impl std::error::Error for AttestationUse {}

/// One checked report as recorded (VM-CP-32: "a valid fixture report is accepted and
/// recorded").
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationRecord {
    pub report: Digest,
    pub result: AttestationResult,
}

fn nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

impl AttestationRecord {
    /// Whether the record can back a launch of `workload` for `identity` on the control
    /// session bound to `session_key`, at `now` on `clock`.
    pub fn usable_for(
        &self,
        identity: Digest,
        session_key: Digest,
        workload: Digest,
        clock: ClockSession,
        now: MonotonicTime,
        max_age: Duration,
    ) -> Result<(), AttestationUse> {
        let result = &self.result;
        if !result.is_accepted() {
            return Err(AttestationUse::NotAccepted);
        }
        if result.identity != Some(identity) {
            return Err(AttestationUse::OtherIdentity);
        }
        if result.session_key != Some(session_key) {
            return Err(AttestationUse::OtherSessionKey);
        }
        if result.workload != Some(workload) {
            return Err(AttestationUse::OtherWorkload);
        }
        if result.clock != clock {
            return Err(AttestationUse::OtherClock);
        }
        let age = now
            .checked_duration_since(result.verified_at)
            .ok_or(AttestationUse::OtherClock)?;
        if age > max_age {
            return Err(AttestationUse::Stale {
                age_nanos: nanos(age),
                max_nanos: nanos(max_age),
            });
        }
        Ok(())
    }
}

/// Outstanding challenges, answered nonces and every recorded result.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AttestationBook {
    outstanding: BTreeMap<Digest, AttestationChallenge>,
    used: BTreeSet<Digest>,
    records: Vec<AttestationRecord>,
}

struct Checks {
    verdicts: Vec<CheckVerdict>,
}

impl Checks {
    fn push(&mut self, check: CheckName, outcome: CheckOutcome) {
        self.verdicts.push(CheckVerdict { check, outcome });
    }

    fn judge(&mut self, check: CheckName, refusals: Vec<AttestationRefusal>) {
        let outcome = if refusals.is_empty() {
            CheckOutcome::Passed
        } else {
            CheckOutcome::Failed { refusals }
        };
        self.push(check, outcome);
    }

    fn passed(&self, check: CheckName) -> bool {
        self.verdicts
            .iter()
            .any(|verdict| verdict.check == check && verdict.outcome == CheckOutcome::Passed)
    }
}

fn tcb_refusal(status: TcbStatus, allow_out_of_date: bool) -> Option<AttestationRefusal> {
    match status {
        TcbStatus::UpToDate => None,
        TcbStatus::OutOfDate if allow_out_of_date => None,
        TcbStatus::OutOfDate => Some(AttestationRefusal::TcbOutOfDate),
        TcbStatus::Revoked => Some(AttestationRefusal::TcbRevoked),
        TcbStatus::Unsupported => Some(AttestationRefusal::TcbUnsupported),
    }
}

impl AttestationBook {
    pub fn new() -> Self {
        Self::default()
    }

    /// Issues a challenge for a report from `identity`, bound to the control session's
    /// `session_key` and to `workload`.
    #[allow(clippy::too_many_arguments)]
    pub fn challenge(
        &mut self,
        nonces: &mut dyn NonceSource,
        identity: Digest,
        session_key: Digest,
        workload: Digest,
        target: CoverageTarget,
        clock: ClockSession,
        now: MonotonicTime,
    ) -> Result<AttestationChallenge, AttestationRefusal> {
        let nonce = AttestationNonce::new(nonces.next_nonce());
        let id = nonce.id();
        if self.used.contains(&id) || self.outstanding.contains_key(&id) {
            return Err(AttestationRefusal::NonceReused);
        }
        let challenge = AttestationChallenge {
            nonce,
            identity,
            session_key,
            workload,
            target,
            clock,
            issued_at: now,
        };
        self.outstanding.insert(id, challenge.clone());
        Ok(challenge)
    }

    /// Every recorded result, in order.
    pub fn records(&self) -> &[AttestationRecord] {
        &self.records
    }

    /// Checks `report` against `policy` at `now` on `clock`, consumes the challenge its
    /// nonce names, and records the result.
    pub fn verify(
        &mut self,
        report: &AttestationReport,
        policy: &AttestationPolicy,
        verifier: &dyn VendorVerifier,
        clock: ClockSession,
        now: MonotonicTime,
    ) -> AttestationRecord {
        let body = &report.body;
        let nonce_id = body.bound_nonce.id();
        let challenge = self.outstanding.remove(&nonce_id);
        self.used.insert(nonce_id);
        let mut checks = Checks {
            verdicts: Vec::new(),
        };

        let origin = match body.origin {
            ReportOrigin::HardwareSigned => Vec::new(),
            ReportOrigin::SelfReported => vec![AttestationRefusal::SelfReportedMeasurement],
            ReportOrigin::VtpmQuote => vec![AttestationRefusal::VtpmAlone],
        };
        checks.judge(CheckName::ReportOrigin, origin);
        let vendor = verifier.verify_cpu(report);
        checks.judge(
            CheckName::VendorChain,
            match vendor {
                VendorVerdict::Verified { .. } => Vec::new(),
                VendorVerdict::Rejected { reason } => {
                    vec![AttestationRefusal::ChainRejected { reason }]
                }
                VendorVerdict::Unavailable => vec![AttestationRefusal::VerifierUnavailable],
            },
        );
        let claims_verified =
            checks.passed(CheckName::ReportOrigin) && checks.passed(CheckName::VendorChain);
        let unverified_because = if checks.passed(CheckName::ReportOrigin) {
            CheckName::VendorChain
        } else {
            CheckName::ReportOrigin
        };

        match &challenge {
            None => {
                checks.push(
                    CheckName::Freshness,
                    CheckOutcome::NotEvaluated {
                        because: CheckName::Nonce,
                    },
                );
            }
            Some(challenge) if challenge.clock != clock => {
                checks.judge(CheckName::Freshness, vec![AttestationRefusal::OtherClock]);
            }
            Some(challenge) => {
                let age = now.saturating_duration_since(challenge.issued_at);
                let max_age = Duration::from_secs(policy.max_report_age_seconds);
                let refusals = if age > max_age {
                    vec![AttestationRefusal::StaleReport {
                        age_nanos: nanos(age),
                        max_nanos: nanos(max_age),
                    }]
                } else {
                    Vec::new()
                };
                checks.judge(CheckName::Freshness, refusals);
            }
        }

        let mut gpu_attested = BTreeSet::new();
        if claims_verified {
            let tcb = match vendor {
                VendorVerdict::Verified { tcb } => tcb_refusal(tcb, policy.allow_out_of_date_tcb),
                VendorVerdict::Rejected { .. } | VendorVerdict::Unavailable => None,
            };
            checks.judge(CheckName::TcbStatus, tcb.into_iter().collect());
            checks.judge(
                CheckName::Platform,
                if body.platform == policy.platform {
                    Vec::new()
                } else {
                    vec![AttestationRefusal::PlatformMismatch {
                        expected: policy.platform,
                        found: body.platform,
                    }]
                },
            );
            match &challenge {
                None => {
                    checks.judge(CheckName::Nonce, vec![AttestationRefusal::StaleNonce]);
                    for check in [CheckName::SessionKeyBinding, CheckName::WorkloadBinding] {
                        checks.push(
                            check,
                            CheckOutcome::NotEvaluated {
                                because: CheckName::Nonce,
                            },
                        );
                    }
                }
                Some(challenge) => {
                    checks.judge(CheckName::Nonce, Vec::new());
                    checks.judge(
                        CheckName::SessionKeyBinding,
                        if body.bound_session_key == challenge.session_key {
                            Vec::new()
                        } else {
                            vec![AttestationRefusal::UnboundSessionKey]
                        },
                    );
                    checks.judge(
                        CheckName::WorkloadBinding,
                        if body.bound_workload == challenge.workload {
                            Vec::new()
                        } else {
                            vec![AttestationRefusal::UnboundWorkload]
                        },
                    );
                }
            }
            let expected_data = report_data(
                &body.bound_nonce,
                &body.bound_session_key,
                &body.bound_workload,
            );
            checks.judge(
                CheckName::ReportData,
                if body.report_data == expected_data {
                    Vec::new()
                } else {
                    vec![AttestationRefusal::ReportDataMismatch]
                },
            );
            checks.judge(
                CheckName::Measurement,
                if policy.measurements.contains_key(&body.measurement) {
                    Vec::new()
                } else {
                    vec![AttestationRefusal::MeasurementNotAllowed {
                        measurement: body.measurement,
                    }]
                },
            );
            let versions = policy
                .min_security_versions
                .iter()
                .filter_map(|(component, minimum)| {
                    let found = body.security_versions.get(component).copied();
                    match found {
                        Some(found) if found >= *minimum => None,
                        _ => Some(AttestationRefusal::SecurityVersionBelowMinimum {
                            component: component.clone(),
                            found,
                            minimum: *minimum,
                        }),
                    }
                })
                .collect();
            checks.judge(CheckName::SecurityVersion, versions);
            checks.judge(
                CheckName::DebugState,
                if body.debug_enabled {
                    vec![AttestationRefusal::DebugEnabled]
                } else {
                    Vec::new()
                },
            );
            if report.gpus.is_empty() {
                checks.push(CheckName::GpuEvidence, CheckOutcome::NotApplicable);
            } else {
                let refusals = check_gpus(
                    report,
                    policy,
                    verifier,
                    challenge.as_ref(),
                    &mut gpu_attested,
                );
                checks.judge(CheckName::GpuEvidence, refusals);
            }
        } else {
            for check in [
                CheckName::TcbStatus,
                CheckName::Platform,
                CheckName::Nonce,
                CheckName::SessionKeyBinding,
                CheckName::WorkloadBinding,
                CheckName::ReportData,
                CheckName::Measurement,
                CheckName::SecurityVersion,
                CheckName::DebugState,
                CheckName::GpuEvidence,
            ] {
                checks.push(
                    check,
                    CheckOutcome::NotEvaluated {
                        because: unverified_because,
                    },
                );
            }
        }

        let target = challenge
            .as_ref()
            .map(|challenge| challenge.target.clone())
            .unwrap_or_default();
        let cpu_checks_passed = checks.verdicts.iter().all(|verdict| {
            matches!(
                verdict.outcome,
                CheckOutcome::Passed | CheckOutcome::NotApplicable
            ) || verdict.check == CheckName::GpuEvidence
        });
        let coverage = if cpu_checks_passed {
            let encrypted: BTreeSet<VolumeName> = policy
                .measurements
                .get(&body.measurement)
                .map(|image| {
                    image
                        .encrypted_volumes
                        .intersection(&target.volumes)
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();
            let attested: BTreeSet<u32> =
                gpu_attested.intersection(&target.gpus).copied().collect();
            ProtectionCoverage {
                cpu: CpuCoverage {
                    protected_vcpus: body.protected_vcpus,
                    total_vcpus: target.vcpus,
                },
                memory: MemoryCoverage {
                    private_bytes: body.private_memory_bytes,
                    shared_bytes: body.shared_memory_bytes,
                    total_bytes: target.memory_bytes,
                },
                storage: StorageCoverage {
                    not_covered: target.volumes.difference(&encrypted).cloned().collect(),
                    encrypted,
                },
                gpu: GpuCoverage {
                    not_covered: target.gpus.difference(&attested).copied().collect(),
                    attested,
                },
            }
        } else {
            ProtectionCoverage::none(&target)
        };
        let uncovered = policy
            .required
            .iter()
            .filter(|portion| !coverage.covers(**portion, policy.max_shared_memory_bytes))
            .map(|portion| AttestationRefusal::PortionNotCovered { portion: *portion })
            .collect();
        checks.judge(CheckName::Coverage, uncovered);

        let refusals: Vec<AttestationRefusal> = checks
            .verdicts
            .iter()
            .flat_map(|verdict| match &verdict.outcome {
                CheckOutcome::Failed { refusals } => refusals.clone(),
                CheckOutcome::Passed
                | CheckOutcome::NotEvaluated { .. }
                | CheckOutcome::NotApplicable => Vec::new(),
            })
            .collect();
        let all_evaluated = checks
            .verdicts
            .iter()
            .all(|verdict| !matches!(verdict.outcome, CheckOutcome::NotEvaluated { .. }));
        let verdict = if refusals.is_empty() && all_evaluated {
            FacetVerdict::Verified
        } else {
            FacetVerdict::Refused { refusals }
        };
        let mut verdicts = checks.verdicts;
        verdicts.sort_by_key(|verdict| verdict.check);
        let record = AttestationRecord {
            report: report.digest(),
            result: AttestationResult {
                challenge: challenge.as_ref().map(AttestationChallenge::id),
                identity: challenge.as_ref().map(|challenge| challenge.identity),
                session_key: challenge.as_ref().map(|challenge| challenge.session_key),
                workload: challenge.as_ref().map(|challenge| challenge.workload),
                platform: body.platform,
                checks: verdicts,
                coverage,
                facet: DeploymentFacet::OperatorConfidentiality,
                verdict,
                clock,
                verified_at: now,
            },
        };
        self.records.push(record.clone());
        record
    }
}

fn check_gpus(
    report: &AttestationReport,
    policy: &AttestationPolicy,
    verifier: &dyn VendorVerifier,
    challenge: Option<&AttestationChallenge>,
    attested: &mut BTreeSet<u32>,
) -> Vec<AttestationRefusal> {
    let mut refusals = Vec::new();
    let mut seen = BTreeSet::new();
    for gpu in &report.gpus {
        let device = gpu.body.device;
        let problem = gpu_problem(gpu, policy, verifier, challenge, &mut seen);
        match problem {
            None => {
                attested.insert(device);
            }
            Some(problem) => {
                refusals.push(AttestationRefusal::GpuReportRefused { device, problem })
            }
        }
    }
    refusals
}

fn gpu_problem(
    gpu: &GpuReport,
    policy: &AttestationPolicy,
    verifier: &dyn VendorVerifier,
    challenge: Option<&AttestationChallenge>,
    seen: &mut BTreeSet<u32>,
) -> Option<GpuProblem> {
    let device = gpu.body.device;
    let Some(challenge) = challenge else {
        return Some(GpuProblem::StaleNonce);
    };
    if !challenge.target.gpus.contains(&device) || !seen.insert(device) {
        return Some(GpuProblem::UnexpectedDevice);
    }
    match verifier.verify_gpu(gpu) {
        VendorVerdict::Verified { tcb } => match tcb {
            TcbStatus::UpToDate => {}
            TcbStatus::OutOfDate if policy.allow_out_of_date_tcb => {}
            TcbStatus::OutOfDate => return Some(GpuProblem::TcbOutOfDate),
            TcbStatus::Revoked => return Some(GpuProblem::TcbRevoked),
            TcbStatus::Unsupported => return Some(GpuProblem::TcbUnsupported),
        },
        VendorVerdict::Rejected { reason } => return Some(GpuProblem::ChainRejected { reason }),
        VendorVerdict::Unavailable => return Some(GpuProblem::VerifierUnavailable),
    }
    if gpu.body.bound_nonce != challenge.nonce {
        return Some(GpuProblem::StaleNonce);
    }
    if gpu.body.bound_session_key != challenge.session_key {
        return Some(GpuProblem::UnboundSessionKey);
    }
    if !gpu.body.confidential_mode {
        return Some(GpuProblem::NotConfidentialMode);
    }
    if gpu.body.debug_enabled {
        return Some(GpuProblem::DebugEnabled);
    }
    if !policy.gpu_measurements.contains(&gpu.body.measurement) {
        return Some(GpuProblem::MeasurementNotAllowed);
    }
    None
}
