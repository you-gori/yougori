//! Stable refusal codes shared by the declaration reader, V01 validation, launch
//! planning and non-interactive runs (VM-W54: "stable JSON/text errors; error codes and
//! examples match").
//!
//! The set is closed and versioned ([`REFUSAL_SCHEMA_VERSION`]). Each [`RefusalCode`]
//! has a stable snake_case string, a stage and a one-line help text; each
//! [`RefusalDetail`] carries the structured detail and produces the one-line message.
//! Validation and launch details mirror V01's [`ValidationIssue`] and
//! [`LaunchRefusalReason`] field for field, and their messages are V01's own wording.
//! A [`Refusal`] is the same value in text (`[code] message`) and JSON; reading JSON
//! back refuses a code or message that does not match its detail.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::schema::ExtensionName;
use crate::foundation::ids::ExecutionCategory;
use crate::foundation::text::is_hazardous;
use crate::sandbox_contract::policy::{
    ApprovalRule, BudgetKey, LaunchRefusal, LaunchRefusalReason, MigrationRefusal, PermissionTuple,
    PolicyLayer, PredicateOutcome, ResourceName, RoleName, SecurityPredicate, ValidationIssue,
    ValidationRefusal,
};

/// The refusal schema version this build writes and reads.
pub const REFUSAL_SCHEMA_VERSION: u32 = 1;

/// Longest untrusted fragment copied into a refusal, in characters.
pub(super) const MAX_UNTRUSTED_CHARS: usize = 160;

/// The pinned refusal schema version; any other is refused when read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct RefusalSchemaVersion(u32);

impl RefusalSchemaVersion {
    pub const CURRENT: Self = Self(REFUSAL_SCHEMA_VERSION);

    pub const fn get(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for RefusalSchemaVersion {
    type Error = String;

    fn try_from(found: u32) -> Result<Self, Self::Error> {
        if found == REFUSAL_SCHEMA_VERSION {
            Ok(Self(found))
        } else {
            Err(format!(
                "refusal schema version {found} is not supported; this build reads only \
                 version {REFUSAL_SCHEMA_VERSION}"
            ))
        }
    }
}

impl From<RefusalSchemaVersion> for u32 {
    fn from(version: RefusalSchemaVersion) -> Self {
        version.0
    }
}

/// Where a refusal arises.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalStage {
    /// Reading or compiling a declaration (VM-W37).
    Declaration,
    /// V01 static validation (§2.4 line 1804).
    Validation,
    /// V01 launch planning (§2.4 lines 1797–1800).
    Launch,
    /// A non-interactive run that cannot ask (VM-W54).
    NonInteractive,
}

macro_rules! refusal_codes {
    ($( $(#[$doc:meta])* $variant:ident = $code:literal, $stage:ident, $help:literal; )*) => {
        /// A stable refusal code (VM-W54). The string form never changes within a
        /// refusal schema version.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum RefusalCode {
            $( $(#[$doc])* $variant, )*
        }

        impl RefusalCode {
            /// Every code of this schema version.
            pub const ALL: &'static [Self] = &[$(Self::$variant,)*];

            /// The stable snake_case string.
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $code,)* }
            }

            pub const fn stage(self) -> RefusalStage {
                match self { $(Self::$variant => RefusalStage::$stage,)* }
            }

            /// One line on what to do about it.
            pub const fn help(self) -> &'static str {
                match self { $(Self::$variant => $help,)* }
            }
        }
    };
}

refusal_codes! {
    DeclarationNotJson = "declaration_not_json", Declaration,
        "Write the declaration as one JSON document.";
    DeclarationNotObject = "declaration_not_object", Declaration,
        "Write the declaration as a JSON object.";
    DeclarationVersionMissing = "declaration_version_missing", Declaration,
        "State declaration_version; this build reads version 1.";
    UnsupportedDeclarationVersion = "unsupported_declaration_version", Declaration,
        "Use declaration version 1, or a build that reads the newer version.";
    AuthorityField = "authority_field", Declaration,
        "Remove the field: ceilings, delegations, approvals, evidence and trust come from the host, never a declaration.";
    UnknownCapability = "unknown_capability", Declaration,
        "Use a capability kind this version defines; unknown capabilities are never ignored.";
    UnknownExtensionRuntime = "unknown_extension_runtime", Declaration,
        "Use wasm, native_plugin or script.";
    UnknownField = "unknown_field", Declaration,
        "Remove the field; this version defines a closed set of fields.";
    InvalidDeclaration = "invalid_declaration", Declaration,
        "Correct the value the message names.";
    NoSandbox = "no_sandbox", Declaration,
        "Declare at least one sandbox role.";
    DuplicateSandboxRole = "duplicate_sandbox_role", Declaration,
        "Declare each sandbox role once.";
    UndeclaredSandboxRole = "undeclared_sandbox_role", Declaration,
        "Declare the sandbox role before giving it capabilities or extensions.";
    DuplicateCapability = "duplicate_capability", Declaration,
        "List each capability once, with one need.";
    DuplicateExtension = "duplicate_extension", Declaration,
        "Name each extension executor once.";
    WildcardDestination = "wildcard_destination", Declaration,
        "Name exact destinations; a wildcard needs host-verified zone ownership and is granted by host policy.";
    DestinationNotAName = "destination_not_a_name", Declaration,
        "Name the destination by DNS name; address endpoints are granted by host policy.";
    InvalidDestination = "invalid_destination", Declaration,
        "Write the destination as a canonical host or host:port.";
    LabelledRuntime = "labelled_runtime", Declaration,
        "Remove the labelled runtime; sandboxes and extensions run only in a VM sandbox.";
    CredentialNeverDelivered = "credential_never_delivered", Declaration,
        "Declare a typed provider_operation instead; the executor keeps the credential.";
    CanaryNotRequestable = "canary_not_requestable", Declaration,
        "Remove it; the host places canaries.";
    VolumeOnEphemeralSandbox = "volume_on_ephemeral_sandbox", Declaration,
        "Declare persistence declared_volumes for the sandbox, or drop the volume write.";
    ApprovalWithoutOperation = "approval_without_operation", Declaration,
        "Remove the approval; the capability performs no host operation to approve.";
    RequestMalformed = "request_malformed", Validation,
        "Correct the request document.";
    UnsupportedContractSchema = "unsupported_contract_schema", Validation,
        "Use the contract schema version this build reads.";
    UnknownRequirement = "unknown_requirement", Validation,
        "Require only predicates this build defines; unknown requirements are never ignored.";
    LegacyTierRefused = "legacy_tier_refused", Validation,
        "Replace the old tier with explicit requirements.";
    GenerationBoundInLayer = "generation_bound_in_layer", Validation,
        "Only a delegation may bind an authorization epoch.";
    OperationOnWrongResource = "operation_on_wrong_resource", Validation,
        "Pair each operation with the resource kind it applies to.";
    ApprovalDoesNotFit = "approval_does_not_fit", Validation,
        "Use an approval kind that fits the operation.";
    DuplicateBudget = "duplicate_budget", Validation,
        "List each budget resource and scope once.";
    DependencyNotRequested = "dependency_not_requested", Validation,
        "Request every dependency.";
    ProductionSandboxWithoutVm = "production_sandbox_without_vm", Validation,
        "Require vm_sandbox in the product policy.";
    OutboundWithoutReleaseBudget = "outbound_without_release_budget", Validation,
        "Give the product a release-bytes budget per generation.";
    CredentialWithoutDelegatedBudget = "credential_without_delegated_budget", Validation,
        "Give the product a short_lived_credential_effects budget that covers the credential.";
    ContractConflict = "contract_conflict", Validation,
        "Drop the permission or the contract requirement that forbids it.";
    ContractBudgetMissing = "contract_budget_missing", Validation,
        "Declare the budget the contract requirement needs.";
    DependencyOutsideLayer = "dependency_outside_layer", Validation,
        "The named layer does not permit the dependency; planning would refuse it.";
    RequiredAuthorityRemoved = "required_authority_removed", Launch,
        "Ask the host to permit it, delegate it, or mark the capability optional.";
    RequirementUnmet = "requirement_unmet", Launch,
        "Provide host evidence for the requirement or change the contract; it is never assumed.";
    NoHostEvidence = "no_host_evidence", Launch,
        "Collect host evidence; a launch needs at least one verified host observation.";
    AuthorizationMissing = "authorization_missing", NonInteractive,
        "Delegate the authority interactively first; a non-interactive run never asks.";
    ApprovalRequired = "approval_required", NonInteractive,
        "Approve it interactively first; a non-interactive run never asks.";
    LaunchNotPlanned = "launch_not_planned", NonInteractive,
        "Plan the launch against host evidence before a non-interactive run.";
}

impl fmt::Display for RefusalCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

strict_declaration_enum! {
    /// The structured detail of one refusal; its tag is the code.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum RefusalDetail tag "code" {
        DeclarationNotJson { message: String },
        DeclarationNotObject,
        DeclarationVersionMissing,
        /// `found` is the JSON text of the version value.
        UnsupportedDeclarationVersion { found: String },
        AuthorityField { path: String, field: String },
        UnknownCapability { path: String, name: String },
        UnknownExtensionRuntime { path: String, name: String },
        UnknownField { field: String },
        InvalidDeclaration { message: String },
        NoSandbox,
        DuplicateSandboxRole { role: RoleName },
        UndeclaredSandboxRole { role: RoleName, path: String },
        DuplicateCapability { tuple: PermissionTuple },
        DuplicateExtension { name: ExtensionName },
        WildcardDestination { destination: String },
        DestinationNotAName { destination: String },
        InvalidDestination { destination: String, reason: String },
        /// `subject` names the sandbox or extension that asked for the runtime.
        LabelledRuntime { subject: String, category: ExecutionCategory },
        CredentialNeverDelivered { name: ResourceName },
        CanaryNotRequestable { name: ResourceName },
        VolumeOnEphemeralSandbox { role: RoleName, volume: ResourceName },
        ApprovalWithoutOperation { path: String },
        RequestMalformed { message: String },
        UnsupportedContractSchema { found: u32 },
        UnknownRequirement { name: String },
        LegacyTierRefused { refusal: MigrationRefusal },
        GenerationBoundInLayer { layer: PolicyLayer, tuple: PermissionTuple },
        OperationOnWrongResource { layer: PolicyLayer, tuple: PermissionTuple },
        ApprovalDoesNotFit { layer: PolicyLayer, rule: ApprovalRule },
        DuplicateBudget { layer: PolicyLayer, key: BudgetKey },
        DependencyNotRequested { tuple: PermissionTuple },
        ProductionSandboxWithoutVm,
        OutboundWithoutReleaseBudget { tuple: PermissionTuple },
        CredentialWithoutDelegatedBudget { tuple: PermissionTuple },
        ContractConflict {
            layer: PolicyLayer,
            predicate: SecurityPredicate,
            tuple: PermissionTuple,
        },
        ContractBudgetMissing {
            layer: PolicyLayer,
            predicate: SecurityPredicate,
            key: BudgetKey,
        },
        DependencyOutsideLayer { layer: PolicyLayer, tuple: PermissionTuple },
        RequiredAuthorityRemoved {
            tuple: PermissionTuple,
            excluded_by: BTreeSet<PolicyLayer>,
        },
        RequirementUnmet { predicate: SecurityPredicate, outcome: PredicateOutcome },
        NoHostEvidence,
        AuthorizationMissing { tuple: PermissionTuple },
        ApprovalRequired { rule: ApprovalRule },
        LaunchNotPlanned,
    }
}

impl RefusalDetail {
    /// The code; the detail's tag.
    pub fn code(&self) -> RefusalCode {
        use RefusalCode as C;
        match self {
            Self::DeclarationNotJson { .. } => C::DeclarationNotJson,
            Self::DeclarationNotObject => C::DeclarationNotObject,
            Self::DeclarationVersionMissing => C::DeclarationVersionMissing,
            Self::UnsupportedDeclarationVersion { .. } => C::UnsupportedDeclarationVersion,
            Self::AuthorityField { .. } => C::AuthorityField,
            Self::UnknownCapability { .. } => C::UnknownCapability,
            Self::UnknownExtensionRuntime { .. } => C::UnknownExtensionRuntime,
            Self::UnknownField { .. } => C::UnknownField,
            Self::InvalidDeclaration { .. } => C::InvalidDeclaration,
            Self::NoSandbox => C::NoSandbox,
            Self::DuplicateSandboxRole { .. } => C::DuplicateSandboxRole,
            Self::UndeclaredSandboxRole { .. } => C::UndeclaredSandboxRole,
            Self::DuplicateCapability { .. } => C::DuplicateCapability,
            Self::DuplicateExtension { .. } => C::DuplicateExtension,
            Self::WildcardDestination { .. } => C::WildcardDestination,
            Self::DestinationNotAName { .. } => C::DestinationNotAName,
            Self::InvalidDestination { .. } => C::InvalidDestination,
            Self::LabelledRuntime { .. } => C::LabelledRuntime,
            Self::CredentialNeverDelivered { .. } => C::CredentialNeverDelivered,
            Self::CanaryNotRequestable { .. } => C::CanaryNotRequestable,
            Self::VolumeOnEphemeralSandbox { .. } => C::VolumeOnEphemeralSandbox,
            Self::ApprovalWithoutOperation { .. } => C::ApprovalWithoutOperation,
            Self::RequestMalformed { .. } => C::RequestMalformed,
            Self::UnsupportedContractSchema { .. } => C::UnsupportedContractSchema,
            Self::UnknownRequirement { .. } => C::UnknownRequirement,
            Self::LegacyTierRefused { .. } => C::LegacyTierRefused,
            Self::GenerationBoundInLayer { .. } => C::GenerationBoundInLayer,
            Self::OperationOnWrongResource { .. } => C::OperationOnWrongResource,
            Self::ApprovalDoesNotFit { .. } => C::ApprovalDoesNotFit,
            Self::DuplicateBudget { .. } => C::DuplicateBudget,
            Self::DependencyNotRequested { .. } => C::DependencyNotRequested,
            Self::ProductionSandboxWithoutVm => C::ProductionSandboxWithoutVm,
            Self::OutboundWithoutReleaseBudget { .. } => C::OutboundWithoutReleaseBudget,
            Self::CredentialWithoutDelegatedBudget { .. } => C::CredentialWithoutDelegatedBudget,
            Self::ContractConflict { .. } => C::ContractConflict,
            Self::ContractBudgetMissing { .. } => C::ContractBudgetMissing,
            Self::DependencyOutsideLayer { .. } => C::DependencyOutsideLayer,
            Self::RequiredAuthorityRemoved { .. } => C::RequiredAuthorityRemoved,
            Self::RequirementUnmet { .. } => C::RequirementUnmet,
            Self::NoHostEvidence => C::NoHostEvidence,
            Self::AuthorizationMissing { .. } => C::AuthorizationMissing,
            Self::ApprovalRequired { .. } => C::ApprovalRequired,
            Self::LaunchNotPlanned => C::LaunchNotPlanned,
        }
    }

    /// The V01 validation issue this detail mirrors, if it is one.
    pub fn validation_issue(&self) -> Option<ValidationIssue> {
        use ValidationIssue as V;
        Some(match self.clone() {
            Self::RequestMalformed { message } => V::Malformed { message },
            Self::UnsupportedContractSchema { found } => V::UnsupportedSchemaVersion { found },
            Self::UnknownRequirement { name } => V::UnknownRequirement { name },
            Self::LegacyTierRefused { refusal } => V::LegacyTierRefused { refusal },
            Self::GenerationBoundInLayer { layer, tuple } => {
                V::GenerationBoundInLayer { layer, tuple }
            }
            Self::OperationOnWrongResource { layer, tuple } => {
                V::OperationOnWrongResource { layer, tuple }
            }
            Self::ApprovalDoesNotFit { layer, rule } => V::ApprovalDoesNotFit { layer, rule },
            Self::DuplicateBudget { layer, key } => V::DuplicateBudget { layer, key },
            Self::DependencyNotRequested { tuple } => V::DependencyNotRequested { tuple },
            Self::ProductionSandboxWithoutVm => V::ProductionSandboxWithoutVm,
            Self::OutboundWithoutReleaseBudget { tuple } => {
                V::OutboundWithoutReleaseBudget { tuple }
            }
            Self::CredentialWithoutDelegatedBudget { tuple } => {
                V::CredentialWithoutDelegatedBudget { tuple }
            }
            Self::ContractConflict {
                layer,
                predicate,
                tuple,
            } => V::ContractConflict {
                layer,
                predicate,
                tuple,
            },
            Self::ContractBudgetMissing {
                layer,
                predicate,
                key,
            } => V::ContractBudgetMissing {
                layer,
                predicate,
                key,
            },
            Self::DependencyOutsideLayer { layer, tuple } => {
                V::DependencyOutsideLayer { layer, tuple }
            }
            _ => return None,
        })
    }

    /// The V01 launch refusal reason this detail mirrors, if it is one.
    pub fn launch_reason(&self) -> Option<LaunchRefusalReason> {
        use LaunchRefusalReason as L;
        Some(match self.clone() {
            Self::RequiredAuthorityRemoved { tuple, excluded_by } => {
                L::RequiredAuthorityRemoved { tuple, excluded_by }
            }
            Self::RequirementUnmet { predicate, outcome } => {
                L::RequirementUnmet { predicate, outcome }
            }
            Self::NoHostEvidence => L::NoHostEvidence,
            _ => return None,
        })
    }

    /// The one-line message. Validation and launch details use V01's wording.
    pub fn message(&self) -> String {
        if let Some(issue) = self.validation_issue() {
            return one_line(&issue.to_string());
        }
        if let Some(reason) = self.launch_reason() {
            return one_line(&reason.to_string());
        }
        one_line(&match self {
            Self::DeclarationNotJson { message } => {
                format!("the declaration is not valid JSON: {message}")
            }
            Self::DeclarationNotObject => "the declaration is not a JSON object".to_owned(),
            Self::DeclarationVersionMissing => {
                "the declaration does not state declaration_version".to_owned()
            }
            Self::UnsupportedDeclarationVersion { found } => format!(
                "declaration version {found} is not supported; this build reads only version \
                 {}; host policy stays in force",
                super::schema::DECLARATION_VERSION
            ),
            Self::AuthorityField { path, field } => format!(
                "{path}: a declaration cannot carry {field:?}; it is a request and never a \
                 grant, so ceilings, delegations, approvals, evidence and trust come only from \
                 the host"
            ),
            Self::UnknownCapability { path, name } => format!(
                "{path}: capability {name:?} is unknown, and an unknown capability is never \
                 ignored"
            ),
            Self::UnknownExtensionRuntime { path, name } => {
                format!("{path}: extension runtime {name:?} is unknown")
            }
            Self::UnknownField { field } => {
                format!("the declaration has the unknown field {field:?}")
            }
            Self::InvalidDeclaration { message } => {
                format!("the declaration is invalid: {message}")
            }
            Self::NoSandbox => "the declaration declares no sandbox".to_owned(),
            Self::DuplicateSandboxRole { role } => {
                format!("sandbox role \"{role}\" is declared twice")
            }
            Self::UndeclaredSandboxRole { role, path } => {
                format!("{path}: sandbox role \"{role}\" is not declared")
            }
            Self::DuplicateCapability { tuple } => {
                format!("the capability {tuple} is declared twice")
            }
            Self::DuplicateExtension { name } => {
                format!("extension executor \"{name}\" is declared twice")
            }
            Self::WildcardDestination { destination } => format!(
                "destination {destination:?} is a wildcard; a declaration names exact \
                 destinations, and only host policy with verified zone ownership grants a \
                 wildcard"
            ),
            Self::DestinationNotAName { destination } => format!(
                "destination {destination:?} is an address; a declaration names destinations \
                 by DNS name, and only host policy grants an exact address endpoint"
            ),
            Self::InvalidDestination {
                destination,
                reason,
            } => format!("destination {destination:?} is invalid: {reason}"),
            Self::LabelledRuntime { subject, category } => format!(
                "{subject} asks for the {} runtime{}, which is never a sandbox; it runs only \
                 in a VM sandbox",
                category.label(),
                category
                    .decision()
                    .map(|decision| format!(" (kept by {decision})"))
                    .unwrap_or_default()
            ),
            Self::CredentialNeverDelivered { name } => format!(
                "credential \"{name}\" is a long-lived external provider credential, which \
                 remains in the vault or executor and is never delivered to the workload"
            ),
            Self::CanaryNotRequestable { name } => format!(
                "\"{name}\" is a fake canary, a detection artifact the host places; a \
                 declaration cannot request one"
            ),
            Self::VolumeOnEphemeralSandbox { role, volume } => format!(
                "sandbox \"{role}\" has ephemeral state, so it cannot write volume \"{volume}\""
            ),
            Self::ApprovalWithoutOperation { path } => format!(
                "{path}: the capability performs no host operation, so there is nothing to \
                 approve"
            ),
            Self::RequestMalformed { .. }
            | Self::UnsupportedContractSchema { .. }
            | Self::UnknownRequirement { .. }
            | Self::LegacyTierRefused { .. }
            | Self::GenerationBoundInLayer { .. }
            | Self::OperationOnWrongResource { .. }
            | Self::ApprovalDoesNotFit { .. }
            | Self::DuplicateBudget { .. }
            | Self::DependencyNotRequested { .. }
            | Self::ProductionSandboxWithoutVm
            | Self::OutboundWithoutReleaseBudget { .. }
            | Self::CredentialWithoutDelegatedBudget { .. }
            | Self::ContractConflict { .. }
            | Self::ContractBudgetMissing { .. }
            | Self::DependencyOutsideLayer { .. }
            | Self::RequiredAuthorityRemoved { .. }
            | Self::RequirementUnmet { .. }
            | Self::NoHostEvidence => String::new(),
            Self::AuthorizationMissing { tuple } => format!(
                "the workload needs {tuple}, and the delegation does not grant it; a \
                 non-interactive run cannot ask for it"
            ),
            Self::ApprovalRequired { rule } => format!(
                "{rule} is required and no valid grant exists; a non-interactive run cannot \
                 ask for it"
            ),
            Self::LaunchNotPlanned => {
                "no launch plan exists; a non-interactive run never proceeds without one".to_owned()
            }
        })
    }
}

impl From<ValidationIssue> for RefusalDetail {
    fn from(issue: ValidationIssue) -> Self {
        use ValidationIssue as V;
        match issue {
            V::Malformed { message } => Self::RequestMalformed {
                message: bounded(&message),
            },
            V::UnsupportedSchemaVersion { found } => Self::UnsupportedContractSchema { found },
            V::UnknownRequirement { name } => Self::UnknownRequirement {
                name: bounded(&name),
            },
            V::LegacyTierRefused { refusal } => Self::LegacyTierRefused {
                refusal: match refusal {
                    MigrationRefusal::Unknown { name } => MigrationRefusal::Unknown {
                        name: bounded(&name),
                    },
                    other => other,
                },
            },
            V::GenerationBoundInLayer { layer, tuple } => {
                Self::GenerationBoundInLayer { layer, tuple }
            }
            V::OperationOnWrongResource { layer, tuple } => {
                Self::OperationOnWrongResource { layer, tuple }
            }
            V::ApprovalDoesNotFit { layer, rule } => Self::ApprovalDoesNotFit { layer, rule },
            V::DuplicateBudget { layer, key } => Self::DuplicateBudget { layer, key },
            V::DependencyNotRequested { tuple } => Self::DependencyNotRequested { tuple },
            V::ProductionSandboxWithoutVm => Self::ProductionSandboxWithoutVm,
            V::OutboundWithoutReleaseBudget { tuple } => {
                Self::OutboundWithoutReleaseBudget { tuple }
            }
            V::CredentialWithoutDelegatedBudget { tuple } => {
                Self::CredentialWithoutDelegatedBudget { tuple }
            }
            V::ContractConflict {
                layer,
                predicate,
                tuple,
            } => Self::ContractConflict {
                layer,
                predicate,
                tuple,
            },
            V::ContractBudgetMissing {
                layer,
                predicate,
                key,
            } => Self::ContractBudgetMissing {
                layer,
                predicate,
                key,
            },
            V::DependencyOutsideLayer { layer, tuple } => {
                Self::DependencyOutsideLayer { layer, tuple }
            }
        }
    }
}

impl From<LaunchRefusalReason> for RefusalDetail {
    fn from(reason: LaunchRefusalReason) -> Self {
        match reason {
            LaunchRefusalReason::RequiredAuthorityRemoved { tuple, excluded_by } => {
                Self::RequiredAuthorityRemoved { tuple, excluded_by }
            }
            LaunchRefusalReason::RequirementUnmet { predicate, outcome } => {
                Self::RequirementUnmet { predicate, outcome }
            }
            LaunchRefusalReason::NoHostEvidence => Self::NoHostEvidence,
        }
    }
}

/// One refusal: version, code, one-line message and detail. Text and JSON are two forms
/// of this one value, so they carry the same code.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RefusalWire")]
pub struct Refusal {
    pub refusal_version: RefusalSchemaVersion,
    pub code: RefusalCode,
    pub message: String,
    pub detail: RefusalDetail,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RefusalWire {
    refusal_version: RefusalSchemaVersion,
    code: RefusalCode,
    message: String,
    detail: RefusalDetail,
}

impl TryFrom<RefusalWire> for Refusal {
    type Error = String;

    fn try_from(wire: RefusalWire) -> Result<Self, Self::Error> {
        if wire.code != wire.detail.code() {
            return Err(format!(
                "the refusal code {} does not match its detail {}",
                wire.code,
                wire.detail.code()
            ));
        }
        if wire.message != wire.detail.message() {
            return Err("the refusal message does not match its detail".to_owned());
        }
        Ok(Self {
            refusal_version: wire.refusal_version,
            code: wire.code,
            message: wire.message,
            detail: wire.detail,
        })
    }
}

impl Refusal {
    pub fn new(detail: RefusalDetail) -> Self {
        Self {
            refusal_version: RefusalSchemaVersion::CURRENT,
            code: detail.code(),
            message: detail.message(),
            detail,
        }
    }

    /// The text form: `[code] message`.
    pub fn render_text(&self) -> String {
        format!("[{}] {}", self.code, self.message)
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render_text())
    }
}

impl std::error::Error for Refusal {}

/// Every refusal found, in a deterministic order; never empty.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ReportWire")]
pub struct RefusalReport {
    refusals: Vec<Refusal>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportWire {
    refusals: Vec<Refusal>,
}

impl TryFrom<ReportWire> for RefusalReport {
    type Error = &'static str;

    fn try_from(wire: ReportWire) -> Result<Self, Self::Error> {
        if wire.refusals.is_empty() {
            Err("a refusal report lists at least one refusal")
        } else {
            Ok(Self {
                refusals: wire.refusals,
            })
        }
    }
}

impl RefusalReport {
    /// A report of `details`; `None` when there are none.
    pub fn from_details(details: impl IntoIterator<Item = RefusalDetail>) -> Option<Self> {
        let refusals: Vec<Refusal> = details.into_iter().map(Refusal::new).collect();
        (!refusals.is_empty()).then_some(Self { refusals })
    }

    pub fn single(detail: RefusalDetail) -> Self {
        Self {
            refusals: vec![Refusal::new(detail)],
        }
    }

    pub fn refusals(&self) -> &[Refusal] {
        &self.refusals
    }

    pub fn codes(&self) -> Vec<RefusalCode> {
        self.refusals.iter().map(|refusal| refusal.code).collect()
    }

    pub fn contains(&self, code: RefusalCode) -> bool {
        self.refusals.iter().any(|refusal| refusal.code == code)
    }

    /// One `[code] message` line per refusal.
    pub fn render_text(&self) -> String {
        let lines: Vec<String> = self.refusals.iter().map(Refusal::render_text).collect();
        lines.join("\n")
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn from_json(text: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(text)
    }
}

impl fmt::Display for RefusalReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render_text())
    }
}

impl std::error::Error for RefusalReport {}

impl From<ValidationRefusal> for RefusalReport {
    fn from(refusal: ValidationRefusal) -> Self {
        Self::from_details(refusal.issues.into_iter().map(RefusalDetail::from)).unwrap_or_else(
            || {
                Self::single(RefusalDetail::RequestMalformed {
                    message: "validation refused without an issue".to_owned(),
                })
            },
        )
    }
}

impl From<&LaunchRefusal> for RefusalReport {
    fn from(refusal: &LaunchRefusal) -> Self {
        Self::from_details(refusal.reasons.iter().cloned().map(RefusalDetail::from))
            .unwrap_or_else(|| Self::single(RefusalDetail::NoHostEvidence))
    }
}

/// `text` on one line, with every character `foundation::text` judges hazardous written
/// as an escape, so untrusted text can neither break a one-line message nor disguise a
/// terminal line (VM part §4.7 line 2139: "prevent control characters from spoofing
/// approval UI").
pub(super) fn one_line(text: &str) -> String {
    let mut line = String::with_capacity(text.len());
    for character in text.chars() {
        if is_hazardous(character) {
            line.extend(character.escape_unicode());
        } else {
            line.push(character);
        }
    }
    line
}

/// An untrusted fragment, escaped like [`one_line`] and cut to [`MAX_UNTRUSTED_CHARS`].
pub(super) fn bounded(text: &str) -> String {
    let mut out = String::new();
    for (count, character) in text.chars().enumerate() {
        if count >= MAX_UNTRUSTED_CHARS {
            out.push_str("...");
            break;
        }
        if is_hazardous(character) {
            out.extend(character.escape_unicode());
        } else {
            out.push(character);
        }
    }
    out
}
