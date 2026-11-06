//! The stored view (VM-W04 acceptance: "Tampering detected; stale evidence not presented
//! as current; record does not claim a security score"; §8.1: a launch record is an
//! evidence record, not a security certificate, and a digest establishes the integrity of
//! a record, not the truth of what it reports).
//!
//! A [`SandboxView`] is a [`ViewBody`] sealed under a domain-separated digest
//! ([`VIEW_DOMAIN`]) of its serialized form, so a change to anything it shows changes the
//! digest. The body binds the launch record by its identity digest and the contract by
//! its identity. Reading a view back is strict: unknown fields, another view version or
//! notice text, a digest that does not match the content, or a fact on a basis that does
//! not fit its value are refused. A digest alone cannot stop someone who re-seals an
//! edited body, so [`SandboxView::check_against`] compares the view with what its launch
//! record yields, and [`SandboxView::check_contract`] with the contract.

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::facts::{FactValue, ViewFact};
use super::sections::{contract_facts, preview_matches, record_facts, ViewInputs};
use crate::foundation::coordination::{SandboxGenerations, SnapshotId, VmInstanceId};
use crate::foundation::evidence::{ClockSession, ConfigurationFingerprint};
use crate::foundation::ids::{digest, Digest, ExecutionId, MonotonicTime, TenantId};
use crate::sandbox::backend::LaunchRecord;
use crate::sandbox_contract::declarations::{ContractLine, ContractMeaning};
use crate::sandbox_contract::policy::{ContractIdentity, PermissionTuple, ResolvedPolicy};

/// The digest domain of a view.
pub const VIEW_DOMAIN: &str = "yougori/sandbox/view/v1";

/// The view schema version this build writes and reads.
pub const VIEW_VERSION: u32 = 1;

/// The pinned view version; any other is refused when read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct ViewVersion(u32);

impl ViewVersion {
    pub const CURRENT: Self = Self(VIEW_VERSION);

    pub const fn get(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for ViewVersion {
    type Error = String;

    fn try_from(found: u32) -> Result<Self, Self::Error> {
        if found == VIEW_VERSION {
            Ok(Self(found))
        } else {
            Err(format!(
                "view version {found} is not supported; this build reads only version \
                 {VIEW_VERSION}"
            ))
        }
    }
}

impl From<ViewVersion> for u32 {
    fn from(version: ViewVersion) -> Self {
        version.0
    }
}

/// The view's standing notice (§8.1). Written as its one fixed sentence and read only if
/// it is exactly that sentence, so a stored view cannot be edited into a certificate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ViewNotice;

impl ViewNotice {
    pub const TEXT: &'static str = "This view is an evidence record, not a certificate. \
         Observed and verified facts hold only while current under the configuration in \
         force; guest, launch request, declaration and contract statements are assertions; \
         a contract states what is granted, not that anything enforces it.";
}

impl fmt::Display for ViewNotice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(Self::TEXT)
    }
}

impl Serialize for ViewNotice {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(Self::TEXT)
    }
}

impl<'de> Deserialize<'de> for ViewNotice {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if String::deserialize(deserializer)? == Self::TEXT {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(
                "the notice field holds only its fixed text",
            ))
        }
    }
}

/// Everything a view shows; the view's digest covers all of it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ViewBody {
    pub view_version: ViewVersion,
    /// The launch record this view shows, by its identity digest.
    pub launch_record: Digest,
    /// The contract's identity, labelled as identification only (§2.4 line 1804).
    pub contract: ContractLine,
    pub execution: ExecutionId,
    pub tenant: TenantId,
    pub generations: SandboxGenerations,
    pub vm: VmInstanceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restored_from: Option<SnapshotId>,
    /// The host configuration the launch was decided under.
    pub configuration: ConfigurationFingerprint,
    /// The evidence clock session the launch was recorded on.
    pub clock: ClockSession,
    pub recorded_at: MonotonicTime,
    /// The oldest a host observation may be to be shown as current: the launch's
    /// evidence requirement.
    pub max_age: Duration,
    /// Every fact, launch-record facts first; each is shown in its value's section.
    pub facts: Vec<ViewFact>,
    pub notice: ViewNotice,
}

/// Why a view could not be built.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ViewError {
    /// The contract is not the one the launch record names.
    ContractMismatch {
        record: Digest,
        contract: ContractIdentity,
    },
    /// The preview is of another contract.
    PreviewForAnotherContract {
        preview: Digest,
        contract: ContractIdentity,
    },
    /// The preview's lines are not the contract's permitted and removed tuples, or it
    /// carries a refusal planning does not make.
    PreviewDoesNotMatchContract,
    /// The view could not be serialized for its digest.
    Unserializable { detail: String },
}

impl fmt::Display for ViewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContractMismatch { record, contract } => write!(
                f,
                "the launch record names contract {record}, not the contract {contract} given"
            ),
            Self::PreviewForAnotherContract { preview, contract } => write!(
                f,
                "the preview is of contract {preview}, not the contract {contract}"
            ),
            Self::PreviewDoesNotMatchContract => f.write_str(
                "the preview's lines are not the contract's permitted and removed tuples",
            ),
            Self::Unserializable { detail } => {
                write!(f, "the view could not be serialized: {detail}")
            }
        }
    }
}

impl std::error::Error for ViewError {}

/// A part of a view that its launch record determines.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecordPart {
    Contract,
    Sandbox,
    Vm,
    Configuration,
    Clock,
    MaxAge,
    Facts,
}

impl fmt::Display for RecordPart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Contract => "contract",
            Self::Sandbox => "sandbox and generations",
            Self::Vm => "VM handle",
            Self::Configuration => "host configuration",
            Self::Clock => "evidence clock and record time",
            Self::MaxAge => "evidence freshness bound",
            Self::Facts => "launch record facts",
        })
    }
}

/// Why a view was refused when read or checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ViewRefusal {
    /// Not a well-formed view: unknown fields, another version or notice, bad values.
    Malformed { detail: String },
    /// The stored digest is not the digest of the content.
    DigestMismatch { stored: Digest, computed: Digest },
    /// The fact at `index` stands on a basis its value may not have.
    BasisDoesNotFit { index: usize },
    /// The view is of another launch record.
    OtherLaunchRecord { view: Digest, record: Digest },
    /// The view differs from what its launch record yields.
    DiffersFromRecord { part: RecordPart },
    /// The view is of another contract.
    OtherContract {
        view: Digest,
        contract: ContractIdentity,
    },
    /// The view's contract lines are not the contract's permitted and removed tuples.
    DiffersFromContract,
}

impl fmt::Display for ViewRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed { detail } => write!(f, "the view is malformed: {detail}"),
            Self::DigestMismatch { stored, computed } => write!(
                f,
                "the view's digest {stored} is not the digest {computed} of its content; it was \
                 changed after it was sealed"
            ),
            Self::BasisDoesNotFit { index } => write!(
                f,
                "fact {index} of the view stands on a basis its value may not have"
            ),
            Self::OtherLaunchRecord { view, record } => write!(
                f,
                "the view is of launch record {view}, not launch record {record}"
            ),
            Self::DiffersFromRecord { part } => {
                write!(f, "the view's {part} differs from its launch record")
            }
            Self::OtherContract { view, contract } => {
                write!(f, "the view is of contract {view}, not contract {contract}")
            }
            Self::DiffersFromContract => {
                f.write_str("the view's contract lines differ from the contract")
            }
        }
    }
}

impl std::error::Error for ViewRefusal {}

/// A sealed view of one launched sandbox (VM-W04, VM-W53). Only [`SandboxView::build`]
/// seals one; reading one back checks its digest and its fact bases.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ViewWire")]
pub struct SandboxView {
    digest: Digest,
    body: ViewBody,
}

/// A view as read, before its digest and bases are checked.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ViewWire {
    digest: Digest,
    body: ViewBody,
}

impl TryFrom<ViewWire> for SandboxView {
    type Error = ViewRefusal;

    fn try_from(wire: ViewWire) -> Result<Self, Self::Error> {
        let computed = body_digest(&wire.body).map_err(|detail| ViewRefusal::Malformed {
            detail: detail.to_string(),
        })?;
        if computed != wire.digest {
            return Err(ViewRefusal::DigestMismatch {
                stored: wire.digest,
                computed,
            });
        }
        if let Some(index) = wire.body.facts.iter().position(|fact| !fact.fits()) {
            return Err(ViewRefusal::BasisDoesNotFit { index });
        }
        Ok(Self {
            digest: wire.digest,
            body: wire.body,
        })
    }
}

fn body_digest(body: &ViewBody) -> Result<Digest, serde_json::Error> {
    let bytes = serde_json::to_vec(body)?;
    Ok(digest(VIEW_DOMAIN, &[&bytes]))
}

/// The tuples of a fact list's contract lines and removed capabilities.
fn contract_tuples(facts: &[ViewFact]) -> (Vec<&PermissionTuple>, Vec<&PermissionTuple>) {
    let mut lines = Vec::new();
    let mut removed = Vec::new();
    for fact in facts {
        match &fact.value {
            FactValue::Access { access } => lines.push(&access.tuple),
            FactValue::Credential { credential } => lines.push(&credential.access.tuple),
            FactValue::Requested { tuple, .. } => removed.push(tuple),
            _ => {}
        }
    }
    lines.sort();
    removed.sort();
    (lines, removed)
}

impl SandboxView {
    /// Builds and seals the view of a launched sandbox from its launch record, the V01
    /// contract it ran under and V08's preview of that contract.
    pub fn build(inputs: &ViewInputs<'_>) -> Result<Self, ViewError> {
        let record = inputs.record;
        let contract = inputs.contract.identity();
        if record.contract() != contract.digest() {
            return Err(ViewError::ContractMismatch {
                record: record.contract(),
                contract,
            });
        }
        if inputs.preview.contract.digest != contract.digest() {
            return Err(ViewError::PreviewForAnotherContract {
                preview: inputs.preview.contract.digest,
                contract,
            });
        }
        if !preview_matches(inputs.contract, inputs.preview) {
            return Err(ViewError::PreviewDoesNotMatchContract);
        }
        let mut facts = record_facts(record);
        facts.extend(contract_facts(
            inputs.contract,
            inputs.preview,
            inputs.network_mode,
        ));
        let sandbox = record.sandbox();
        Self::seal(ViewBody {
            view_version: ViewVersion::CURRENT,
            launch_record: record.identity(),
            contract: ContractLine {
                digest: contract.digest(),
                meaning: ContractMeaning,
            },
            execution: sandbox.execution.clone(),
            tenant: sandbox.tenant.clone(),
            generations: sandbox.generations,
            vm: record.vm(),
            restored_from: record.restored_from(),
            configuration: record.configuration(),
            clock: record.clock(),
            recorded_at: record.recorded_at(),
            max_age: record.required().evidence.max_age,
            facts,
            notice: ViewNotice,
        })
    }

    /// Seals `body` under the digest of its serialized form.
    pub(super) fn seal(body: ViewBody) -> Result<Self, ViewError> {
        let digest = body_digest(&body).map_err(|error| ViewError::Unserializable {
            detail: error.to_string(),
        })?;
        Ok(Self { digest, body })
    }

    /// The view's own digest.
    pub fn digest(&self) -> Digest {
        self.digest
    }

    pub fn body(&self) -> &ViewBody {
        &self.body
    }

    /// The identity digest of the launch record the view shows.
    pub fn launch_record(&self) -> Digest {
        self.body.launch_record
    }

    pub fn facts(&self) -> &[ViewFact] {
        &self.body.facts
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Reads a view strictly; see the module notes for what is refused.
    pub fn from_json(text: &str) -> Result<Self, ViewRefusal> {
        let wire: ViewWire =
            serde_json::from_str(text).map_err(|error| ViewRefusal::Malformed {
                detail: error.to_string(),
            })?;
        Self::try_from(wire)
    }

    /// Refuses unless the view is exactly what `record` yields: the same launch record
    /// identity, contract, sandbox and generations, VM handle, configuration, evidence
    /// clock, freshness bound and launch-record facts, fact for fact and basis for basis.
    pub fn check_against(&self, record: &LaunchRecord) -> Result<(), ViewRefusal> {
        let body = &self.body;
        if body.launch_record != record.identity() {
            return Err(ViewRefusal::OtherLaunchRecord {
                view: body.launch_record,
                record: record.identity(),
            });
        }
        let sandbox = record.sandbox();
        let differs = |part| Err(ViewRefusal::DiffersFromRecord { part });
        if body.contract.digest != record.contract() {
            return differs(RecordPart::Contract);
        }
        if body.execution != sandbox.execution
            || body.tenant != sandbox.tenant
            || body.generations != sandbox.generations
        {
            return differs(RecordPart::Sandbox);
        }
        if body.vm != record.vm() || body.restored_from != record.restored_from() {
            return differs(RecordPart::Vm);
        }
        if body.configuration != record.configuration() {
            return differs(RecordPart::Configuration);
        }
        if body.clock != record.clock() || body.recorded_at != record.recorded_at() {
            return differs(RecordPart::Clock);
        }
        if body.max_age != record.required().evidence.max_age {
            return differs(RecordPart::MaxAge);
        }
        let shown: Vec<&ViewFact> = body
            .facts
            .iter()
            .filter(|fact| fact.from_launch_record())
            .collect();
        let expected = record_facts(record);
        if shown.len() != expected.len() || shown.iter().zip(&expected).any(|(a, b)| *a != b) {
            return differs(RecordPart::Facts);
        }
        Ok(())
    }

    /// Refuses unless the view is of `contract` and its contract lines and removed
    /// capabilities are exactly the contract's permitted and removed tuples.
    pub fn check_contract(&self, contract: &ResolvedPolicy) -> Result<(), ViewRefusal> {
        let identity = contract.identity();
        if self.body.contract.digest != identity.digest() {
            return Err(ViewRefusal::OtherContract {
                view: self.body.contract.digest,
                contract: identity,
            });
        }
        let (lines, removed) = contract_tuples(&self.body.facts);
        let mut permitted = contract.permitted().tuples();
        permitted.sort();
        let mut expected_removed: Vec<&PermissionTuple> =
            contract.removed().iter().map(|line| &line.tuple).collect();
        expected_removed.sort();
        if lines.len() != permitted.len()
            || lines.iter().zip(&permitted).any(|(a, b)| *a != b)
            || removed != expected_removed
        {
            return Err(ViewRefusal::DiffersFromContract);
        }
        Ok(())
    }
}
