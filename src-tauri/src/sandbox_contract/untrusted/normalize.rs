//! The content normalization contract (VM-W58: "content normalization and preview
//! processing inside restricted VMs; track provenance and preserve raw source separately
//! when needed"; §5.2 line 2073: "treat archive extraction, image decoding, document
//! parsing and HTML sanitization as attack surfaces"; §1.2; the "sanitized content"
//! residual risk; VM-R109).
//!
//! The host side here only hashes and compares. [`route_raw`] names raw bytes by their
//! content key and size without looking inside them; a [`NormalizationJob`] is planned
//! only for a restricted VM execution with no credential grants, no host paths, no
//! clipboard and no network unless explicitly granted; and
//! [`NormalizationJob::accept`] validates the job's typed [`NormalizationReport`]
//! against the plan and the received output bytes. HTML, PDF, archive and image
//! parsing happens in the VM, never here. Preview rendering (for example a document page
//! to PNG) is a normalization job like any other.
//!
//! A [`NormalizedArtifact`] is labelled [`NORMALIZATION_LABEL`]: normalization changes
//! the format, and semantic prompt injection can survive it. Nothing here runs a
//! normalizer, and nothing here claims normalized content is safe.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::foundation::ids::{
    validate_identifier, ContentKey, Digest, DigestBuilder, ExecutionCategory, ExecutionId,
    IdError, OperationId, SandboxBootGeneration, TrustScope,
};
use crate::sandbox_contract::destinations::RouteId;
use crate::sandbox_contract::files::{
    check_inspection, ArtifactOrigin, ImportInspection, InspectionMethod, InspectionRefusal,
    Provenance,
};

/// The only label a normalized result carries (VM-W58 acceptance: "normalization is not
/// described as eliminating prompt injection"; §1.2).
pub const NORMALIZATION_LABEL: &str = "format normalized; prompt injection may survive";

const JOB_DOMAIN: &str = "yougori/sandbox/untrusted/normalization-job/v1";
const OBJECT_DOMAIN: &str = "yougori/sandbox/untrusted/normalization-object/v1";

/// The format a requester says raw bytes have (VM-W58). It is a claim used to pick a
/// normalizer; the host never checks it by looking at the bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeclaredFormat {
    Html,
    Pdf,
    Archive,
    Image,
    OfficeDocument,
    PlainText,
    Unknown,
}

impl DeclaredFormat {
    const fn tag(self) -> &'static str {
        match self {
            Self::Html => "html",
            Self::Pdf => "pdf",
            Self::Archive => "archive",
            Self::Image => "image",
            Self::OfficeDocument => "office_document",
            Self::PlainText => "plain_text",
            Self::Unknown => "unknown",
        }
    }
}

/// The format a normalizer produces (VM-W58; a PNG is a preview rendering).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputFormat {
    /// UTF-8 text.
    PlainText,
    /// UTF-8 Markdown.
    Markdown,
    /// A raster image, for previews.
    Png,
}

impl OutputFormat {
    const fn tag(self) -> &'static str {
        match self {
            Self::PlainText => "plain_text",
            Self::Markdown => "markdown",
            Self::Png => "png",
        }
    }

    const fn is_text(self) -> bool {
        matches!(self, Self::PlainText | Self::Markdown)
    }
}

/// Raw bytes as the host routes them (§5.2 line 2073; VM-W58): content key, size, the
/// declared format and who produced them. It holds no part of the content.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RawArtifact {
    content: ContentKey,
    size_bytes: u64,
    declared: DeclaredFormat,
    provenance: Provenance,
    origin: ArtifactOrigin,
}

impl RawArtifact {
    pub const fn content(&self) -> ContentKey {
        self.content
    }

    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    pub const fn declared(&self) -> DeclaredFormat {
        self.declared
    }

    pub fn provenance(&self) -> &Provenance {
        &self.provenance
    }

    pub const fn origin(&self) -> ArtifactOrigin {
        self.origin
    }
}

/// Names raw bytes for a normalization job by hashing them; nothing else is read from
/// them (§5.2 line 2073; VM-W58).
pub fn route_raw(
    bytes: &[u8],
    declared: DeclaredFormat,
    provenance: Provenance,
    origin: ArtifactOrigin,
) -> RawArtifact {
    RawArtifact {
        content: ContentKey::of(bytes),
        size_bytes: byte_len(bytes),
        declared,
        provenance,
        origin,
    }
}

fn byte_len(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).unwrap_or(u64::MAX)
}

/// The normalizer: its name, version and the digest of its VM recipe (VM-W58
/// provenance: "normalizer identity and version").
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "IdentityWire")]
pub struct NormalizerIdentity {
    name: String,
    version: String,
    recipe: Digest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityWire {
    name: String,
    version: String,
    recipe: Digest,
}

impl TryFrom<IdentityWire> for NormalizerIdentity {
    type Error = IdError;

    fn try_from(wire: IdentityWire) -> Result<Self, Self::Error> {
        Self::new(wire.name, wire.version, wire.recipe)
    }
}

impl NormalizerIdentity {
    /// Name and version follow the ids.rs identifier grammar.
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        recipe: Digest,
    ) -> Result<Self, IdError> {
        let name = name.into();
        let version = version.into();
        validate_identifier(&name)?;
        validate_identifier(&version)?;
        Ok(Self {
            name,
            version,
            recipe,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub const fn recipe(&self) -> Digest {
        self.recipe
    }
}

/// Where the job runs (VM-W58 "inside restricted VMs"; VM-D4–VM-D6 labels).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizerExecution {
    pub execution: ExecutionId,
    /// Must be [`ExecutionCategory::VmSandbox`].
    pub category: ExecutionCategory,
    /// The VM generation bound into the result's provenance.
    pub boot: SandboxBootGeneration,
    pub scope: TrustScope,
}

strict_untrusted_enum! {
    /// A credential a job could be given. Every one is refused: a normalization job
    /// never holds credentials (VM-W58 acceptance: fixtures "cannot ... inherit website
    /// credentials").
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum CredentialGrant tag "credential" {
        WebsiteCookies { site: String },
        WebsiteSession { site: String },
        /// A browser profile, with whatever sessions it holds.
        BrowserProfile,
        ProviderKey { provider: String },
        /// The host application's own session.
        HostApplicationSession,
        RepositoryToken { repository: String },
    }
}

strict_untrusted_enum! {
    /// Network access of a job: none unless routes are granted explicitly (VM-W58).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum NetworkGrant tag "network" {
        None,
        /// The named routes only; an empty set is refused rather than read as none.
        ExplicitRoutes { routes: BTreeSet<RouteId> },
    }
}

/// What a job is given beyond its input bytes (VM-W58; VM-P03).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobGrants {
    /// Must be empty.
    pub credentials: Vec<CredentialGrant>,
    pub network: NetworkGrant,
    /// Host paths mounted into the job; must be empty, input arrives as bytes.
    pub host_paths: Vec<String>,
    /// Clipboard access; must be false (VM-P03).
    pub clipboard: bool,
}

impl JobGrants {
    /// No credentials, no network, no host paths, no clipboard.
    pub fn none() -> Self {
        Self {
            credentials: Vec::new(),
            network: NetworkGrant::None,
            host_paths: Vec::new(),
            clipboard: false,
        }
    }
}

/// Whether the raw source is kept as its own object beside the output (VM-W58 "preserve
/// raw source separately when needed").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawRetention {
    KeepSeparately,
    Discard,
}

impl RawRetention {
    const fn tag(self) -> &'static str {
        match self {
            Self::KeepSeparately => "keep_separately",
            Self::Discard => "discard",
        }
    }
}

/// A request for one normalization job (VM-W58).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NormalizationRequest {
    pub raw: RawArtifact,
    pub target: OutputFormat,
    pub retention: RawRetention,
    pub normalizer: NormalizerIdentity,
    pub execution: NormalizerExecution,
    pub grants: JobGrants,
    /// Where the content is parsed; must be [`InspectionMethod::SeparateVm`].
    pub inspection: InspectionMethod,
    pub max_output_bytes: u64,
}

/// One reason a job was refused (VM-W58; §5.2 lines 2071–2073; VM-P03).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobViolation {
    /// A host process or labelled non-VM runtime (VM-D4–VM-D6) was named.
    NotVm {
        category: ExecutionCategory,
        label: &'static str,
        decision: Option<&'static str>,
    },
    /// V05 refuses host mounting and host-process parsing (§5.2 line 2073).
    Inspection(InspectionRefusal),
    /// A constrained helper passes V05's check but is not a restricted VM.
    InspectionNotVm {
        method: InspectionMethod,
    },
    CredentialGranted {
        grant: CredentialGrant,
    },
    EmptyNetworkGrant,
    HostPathsGranted {
        paths: usize,
    },
    ClipboardGranted,
    /// The job would run in the VM that produced the raw bytes, not a separate one
    /// (§5.2 line 2071).
    SameVmAsProducer,
    ZeroOutputBound,
}

impl fmt::Display for JobViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotVm {
                label, decision, ..
            } => match decision {
                Some(decision) => write!(
                    f,
                    "normalization runs only in a VM sandbox, not a {label} ({decision})"
                ),
                None => write!(f, "normalization runs only in a VM sandbox, not a {label}"),
            },
            Self::Inspection(refusal) => fmt::Display::fmt(refusal, f),
            Self::InspectionNotVm { method } => {
                write!(f, "content is parsed in a restricted VM, not {method:?}")
            }
            Self::CredentialGranted { grant } => {
                write!(f, "a normalization job holds no credentials: {grant:?}")
            }
            Self::EmptyNetworkGrant => f.write_str("a network grant must name its routes"),
            Self::HostPathsGranted { paths } => {
                write!(
                    f,
                    "a normalization job mounts no host paths ({paths} named)"
                )
            }
            Self::ClipboardGranted => f.write_str("a normalization job has no clipboard"),
            Self::SameVmAsProducer => {
                f.write_str("normalization runs in a VM separate from the producer")
            }
            Self::ZeroOutputBound => f.write_str("the output bound must be greater than zero"),
        }
    }
}

/// Every reason a job was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobRefusal {
    pub violations: Vec<JobViolation>,
}

impl fmt::Display for JobRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reasons: Vec<String> = self.violations.iter().map(ToString::to_string).collect();
        write!(f, "normalization job refused: {}", reasons.join("; "))
    }
}

impl std::error::Error for JobRefusal {}

/// A planned normalization job (VM-W58). Its digest binds the raw identity, the target,
/// the retention, the normalizer, the execution and the grants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizationJob {
    request: NormalizationRequest,
    digest: Digest,
}

impl NormalizationJob {
    /// Plans a job, refusing every violation at once.
    pub fn plan(request: NormalizationRequest) -> Result<Self, JobRefusal> {
        let mut violations = Vec::new();
        let category = request.execution.category;
        if !category.is_vm_sandbox() {
            violations.push(JobViolation::NotVm {
                category,
                label: category.label(),
                decision: category.decision(),
            });
        }
        let inspection = ImportInspection {
            origin: request.raw.origin,
            filesystem_image: false,
            method: request.inspection,
        };
        if let Err(refusal) = check_inspection(&inspection) {
            violations.push(JobViolation::Inspection(refusal));
        } else if request.inspection != InspectionMethod::SeparateVm {
            violations.push(JobViolation::InspectionNotVm {
                method: request.inspection,
            });
        }
        for grant in &request.grants.credentials {
            violations.push(JobViolation::CredentialGranted {
                grant: grant.clone(),
            });
        }
        if let NetworkGrant::ExplicitRoutes { routes } = &request.grants.network {
            if routes.is_empty() {
                violations.push(JobViolation::EmptyNetworkGrant);
            }
        }
        if !request.grants.host_paths.is_empty() {
            violations.push(JobViolation::HostPathsGranted {
                paths: request.grants.host_paths.len(),
            });
        }
        if request.grants.clipboard {
            violations.push(JobViolation::ClipboardGranted);
        }
        if request.execution.execution == request.raw.provenance.execution {
            violations.push(JobViolation::SameVmAsProducer);
        }
        if request.max_output_bytes == 0 {
            violations.push(JobViolation::ZeroOutputBound);
        }
        if !violations.is_empty() {
            return Err(JobRefusal { violations });
        }
        let digest = job_digest(&request);
        Ok(Self { request, digest })
    }

    pub const fn digest(&self) -> Digest {
        self.digest
    }

    pub fn request(&self) -> &NormalizationRequest {
        &self.request
    }

    /// Checks that bytes about to be routed to the job are the planned raw bytes, by
    /// size and content key only.
    pub fn check_input(&self, bytes: &[u8]) -> Result<(), ResultRefusal> {
        let raw = &self.request.raw;
        if byte_len(bytes) != raw.size_bytes {
            return Err(ResultRefusal::InputSizeMismatch {
                expected_bytes: raw.size_bytes,
                found_bytes: byte_len(bytes),
            });
        }
        if ContentKey::of(bytes) != raw.content {
            return Err(ResultRefusal::InputMismatch);
        }
        Ok(())
    }

    /// Validates the job's typed report and the output bytes the host received. The host
    /// compares identities, sizes and content keys, and checks that text output is UTF-8;
    /// it parses no document, archive or image.
    pub fn accept(
        &self,
        report: NormalizationReport,
        output: &[u8],
    ) -> Result<NormalizedArtifact, ResultRefusal> {
        let request = &self.request;
        if report.job != self.digest {
            return Err(ResultRefusal::JobMismatch);
        }
        if report.raw != request.raw.content {
            return Err(ResultRefusal::RawMismatch);
        }
        if report.normalizer != request.normalizer {
            return Err(ResultRefusal::NormalizerMismatch);
        }
        if report.execution != request.execution.execution {
            return Err(ResultRefusal::ExecutionMismatch);
        }
        if report.boot != request.execution.boot {
            return Err(ResultRefusal::GenerationMismatch {
                expected: request.execution.boot,
                found: report.boot,
            });
        }
        let reported = match report.outcome {
            NormalizationOutcome::Normalized { output } => output,
            NormalizationOutcome::Failed { failure } => {
                return Err(ResultRefusal::NormalizerFailed { failure })
            }
        };
        if reported.format != request.target {
            return Err(ResultRefusal::FormatNotRequested {
                requested: request.target,
                found: reported.format,
            });
        }
        if reported.size_bytes > request.max_output_bytes {
            return Err(ResultRefusal::OutputTooLarge {
                size_bytes: reported.size_bytes,
                limit_bytes: request.max_output_bytes,
            });
        }
        if reported.size_bytes != byte_len(output) {
            return Err(ResultRefusal::SizeMismatch {
                reported_bytes: reported.size_bytes,
                received_bytes: byte_len(output),
            });
        }
        if ContentKey::of(output) != reported.content {
            return Err(ResultRefusal::ContentMismatch);
        }
        if reported.format.is_text() {
            if let Err(error) = std::str::from_utf8(output) {
                return Err(ResultRefusal::TextNotUtf8 {
                    valid_up_to_bytes: byte_len(output.get(..error.valid_up_to()).unwrap_or(&[])),
                });
            }
        }
        let output_object = StoredObject::new(
            StoredRole::NormalizedOutput,
            reported.content,
            reported.size_bytes,
            self.digest,
        );
        let raw = match request.retention {
            RawRetention::KeepSeparately => RawDisposition::KeptSeparately {
                object: StoredObject::new(
                    StoredRole::RawSource,
                    request.raw.content,
                    request.raw.size_bytes,
                    self.digest,
                ),
            },
            RawRetention::Discard => RawDisposition::Discarded {
                content: request.raw.content,
            },
        };
        Ok(NormalizedArtifact {
            output: output_object,
            format: reported.format,
            raw,
            provenance: NormalizationProvenance {
                raw: request.raw.content,
                raw_provenance: request.raw.provenance.clone(),
                normalizer: request.normalizer.clone(),
                execution: request.execution.execution.clone(),
                boot: request.execution.boot,
                scope: request.execution.scope,
                job: self.digest,
            },
            label: NORMALIZATION_LABEL,
        })
    }
}

fn category_tag(category: ExecutionCategory) -> &'static str {
    match category {
        ExecutionCategory::VmSandbox => "vm_sandbox",
        ExecutionCategory::SharedKernelGpuRuntime => "shared_kernel_gpu_runtime",
        ExecutionCategory::ProviderContainerRuntime => "provider_container_runtime",
        ExecutionCategory::HostProcessModelRuntime => "host_process_model_runtime",
    }
}

fn bind_scope(builder: DigestBuilder, scope: &TrustScope) -> DigestBuilder {
    builder
        .str(category_tag(scope.category))
        .digest(&scope.domain)
}

fn job_digest(request: &NormalizationRequest) -> Digest {
    let raw = &request.raw;
    let mut builder = DigestBuilder::new(JOB_DOMAIN)
        .digest(raw.content.digest())
        .u64(raw.size_bytes)
        .str(raw.declared.tag())
        .str(raw.provenance.execution.as_str())
        .u64(raw.provenance.boot.get())
        .str(raw.provenance.operation.as_str());
    builder = bind_scope(builder, &raw.provenance.scope)
        .str(request.target.tag())
        .str(request.retention.tag())
        .str(request.normalizer.name())
        .str(request.normalizer.version())
        .digest(&request.normalizer.recipe())
        .str(request.execution.execution.as_str())
        .str(category_tag(request.execution.category))
        .u64(request.execution.boot.get());
    builder = bind_scope(builder, &request.execution.scope);
    builder = match &request.grants.network {
        NetworkGrant::None => builder.str("network:none"),
        NetworkGrant::ExplicitRoutes { routes } => {
            let mut builder = builder
                .str("network:routes")
                .u64(u64::try_from(routes.len()).unwrap_or(u64::MAX));
            for route in routes {
                builder = builder.str(route.as_str());
            }
            builder
        }
    };
    builder.u64(request.max_output_bytes).finish()
}

/// The job's report, read from the VM (VM-W58). Unknown fields are refused, so a report
/// cannot smuggle a claim such as "safe" or "sanitized".
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizationReport {
    pub job: Digest,
    pub raw: ContentKey,
    pub normalizer: NormalizerIdentity,
    pub execution: ExecutionId,
    pub boot: SandboxBootGeneration,
    pub outcome: NormalizationOutcome,
}

strict_untrusted_enum! {
    /// What the job reports it did.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum NormalizationOutcome tag "outcome" {
        Normalized { output: ReportedOutput },
        Failed { failure: NormalizerFailure },
    }
}

/// The output a job reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportedOutput {
    pub format: OutputFormat,
    pub content: ContentKey,
    pub size_bytes: u64,
}

/// Why a normalizer gave up.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NormalizerFailure {
    UnsupportedFormat,
    MalformedInput,
    InputTooLarge,
    ResourceLimit,
    Timeout,
}

/// Why input bytes or a job's result were refused (VM-W58).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResultRefusal {
    InputSizeMismatch {
        expected_bytes: u64,
        found_bytes: u64,
    },
    InputMismatch,
    JobMismatch,
    RawMismatch,
    NormalizerMismatch,
    ExecutionMismatch,
    GenerationMismatch {
        expected: SandboxBootGeneration,
        found: SandboxBootGeneration,
    },
    NormalizerFailed {
        failure: NormalizerFailure,
    },
    FormatNotRequested {
        requested: OutputFormat,
        found: OutputFormat,
    },
    OutputTooLarge {
        size_bytes: u64,
        limit_bytes: u64,
    },
    SizeMismatch {
        reported_bytes: u64,
        received_bytes: u64,
    },
    ContentMismatch,
    TextNotUtf8 {
        valid_up_to_bytes: u64,
    },
}

impl fmt::Display for ResultRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputSizeMismatch {
                expected_bytes,
                found_bytes,
            } => write!(
                f,
                "input has {found_bytes} bytes; the job was planned for {expected_bytes}"
            ),
            Self::InputMismatch => f.write_str("input bytes are not the planned raw artifact"),
            Self::JobMismatch => f.write_str("the report names another job"),
            Self::RawMismatch => f.write_str("the report names another raw artifact"),
            Self::NormalizerMismatch => f.write_str("the report names another normalizer"),
            Self::ExecutionMismatch => f.write_str("the report names another execution"),
            Self::GenerationMismatch { expected, found } => write!(
                f,
                "the report comes from VM generation {found}; the job ran in {expected}"
            ),
            Self::NormalizerFailed { failure } => write!(f, "the normalizer failed: {failure:?}"),
            Self::FormatNotRequested { requested, found } => {
                write!(f, "the job produced {found:?}; {requested:?} was requested")
            }
            Self::OutputTooLarge {
                size_bytes,
                limit_bytes,
            } => write!(
                f,
                "the output has {size_bytes} bytes; at most {limit_bytes} are accepted"
            ),
            Self::SizeMismatch {
                reported_bytes,
                received_bytes,
            } => write!(
                f,
                "the report says {reported_bytes} bytes; {received_bytes} were received"
            ),
            Self::ContentMismatch => f.write_str("the output bytes do not match the report"),
            Self::TextNotUtf8 { valid_up_to_bytes } => {
                write!(f, "text output is not UTF-8 after byte {valid_up_to_bytes}")
            }
        }
    }
}

impl std::error::Error for ResultRefusal {}

/// The role of a stored object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StoredRole {
    RawSource,
    NormalizedOutput,
}

impl StoredRole {
    const fn tag(self) -> &'static str {
        match self {
            Self::RawSource => "raw_source",
            Self::NormalizedOutput => "normalized_output",
        }
    }
}

/// An object a normalization result refers to. Its identity binds the role and the job,
/// so a kept raw source is a separate object from the output even when the bytes are
/// equal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct StoredObject {
    pub role: StoredRole,
    pub identity: Digest,
    pub content: ContentKey,
    pub size_bytes: u64,
}

impl StoredObject {
    fn new(role: StoredRole, content: ContentKey, size_bytes: u64, job: Digest) -> Self {
        let identity = DigestBuilder::new(OBJECT_DOMAIN)
            .str(role.tag())
            .digest(content.digest())
            .u64(size_bytes)
            .digest(&job)
            .finish();
        Self {
            role,
            identity,
            content,
            size_bytes,
        }
    }
}

/// What happened to the raw source (VM-W58 "preserve raw source separately").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "raw", rename_all = "snake_case")]
pub enum RawDisposition {
    KeptSeparately {
        object: StoredObject,
    },
    /// Not kept; only its content key stays in the provenance.
    Discarded {
        content: ContentKey,
    },
}

/// The provenance chain of a normalized result (VM-W58 "track provenance").
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NormalizationProvenance {
    pub raw: ContentKey,
    /// Who produced the raw bytes.
    pub raw_provenance: Provenance,
    pub normalizer: NormalizerIdentity,
    /// The normalizer VM and its generation.
    pub execution: ExecutionId,
    pub boot: SandboxBootGeneration,
    pub scope: TrustScope,
    pub job: Digest,
}

/// A validated normalized result (VM-W58). It is guest-derived content with a new
/// format, labelled [`NORMALIZATION_LABEL`]; nothing about it is trusted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NormalizedArtifact {
    output: StoredObject,
    format: OutputFormat,
    raw: RawDisposition,
    provenance: NormalizationProvenance,
    label: &'static str,
}

impl NormalizedArtifact {
    pub const fn output(&self) -> &StoredObject {
        &self.output
    }

    pub const fn format(&self) -> OutputFormat {
        self.format
    }

    pub const fn raw(&self) -> &RawDisposition {
        &self.raw
    }

    pub fn provenance(&self) -> &NormalizationProvenance {
        &self.provenance
    }

    /// Always [`NORMALIZATION_LABEL`].
    pub const fn label(&self) -> &'static str {
        self.label
    }

    /// The provenance for promoting the output through V05's transaction (§5.2): the
    /// normalizer VM is its producer.
    pub fn promotion_provenance(&self, operation: OperationId) -> Provenance {
        Provenance {
            execution: self.provenance.execution.clone(),
            boot: self.provenance.boot,
            operation,
            scope: self.provenance.scope,
        }
    }
}

impl fmt::Display for NormalizedArtifact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} output {} ({} bytes) from raw {} by {} {}: {}",
            self.format.tag(),
            self.output.content,
            self.output.size_bytes,
            self.provenance.raw,
            self.provenance.normalizer.name(),
            self.provenance.normalizer.version(),
            self.label
        )
    }
}
