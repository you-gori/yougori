//! The tool/Hub capability declaration (VM-W37; VM part §1.3, §4.5, §4.6).
//!
//! A template or tool declares what it needs: the sandboxes it runs in (VM execution
//! profile and persistence class), data access, typed provider operations, exact
//! destinations, credentials by their §4.5 class, and extension executors. The document
//! is untrusted input (VM-P47). It has a pinned version and a closed set of fields and
//! kinds; reading refuses an unknown version before anything else, then every field that
//! would hand the declaration authority ([`AUTHORITY_FIELDS`]), every unknown capability
//! kind or extension runtime, and every unknown field, each with a typed code.

use std::fmt;
use std::num::NonZeroU64;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use super::refusal::{bounded, RefusalDetail, RefusalReport};
use crate::foundation::ids::{validate_identifier, ExecutionCategory, IdError};
use crate::sandbox_contract::destinations::CanonicalName;
use crate::sandbox_contract::policy::{
    ApprovalKind, Budget, OperationName, Phase, RequestSource, ResourceName, RoleName,
};

/// The declaration version this build reads.
pub const DECLARATION_VERSION: u32 = 1;

/// The pinned declaration version. Any other version is refused, never reinterpreted
/// (VM-P47: an unknown version cannot override host policy).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct DeclarationVersion(u32);

impl DeclarationVersion {
    pub const CURRENT: Self = Self(DECLARATION_VERSION);

    pub const fn get(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for DeclarationVersion {
    type Error = String;

    fn try_from(found: u32) -> Result<Self, Self::Error> {
        if found == DECLARATION_VERSION {
            Ok(Self(found))
        } else {
            Err(format!(
                "declaration version {found} is not supported; this build reads only version \
                 {DECLARATION_VERSION}"
            ))
        }
    }
}

impl From<DeclarationVersion> for u32 {
    fn from(version: DeclarationVersion) -> Self {
        version.0
    }
}

/// The name of an extension executor; the shared identifier grammar.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ExtensionName(String);

impl ExtensionName {
    pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
        let value = value.into();
        validate_identifier(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ExtensionName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ExtensionName({})", self.0)
    }
}

impl fmt::Display for ExtensionName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ExtensionName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// The VM execution profile (VM §1.4): a task VM has fresh writable state and bounded
/// lifetimes; a service VM is renewed under control.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionProfile {
    Task,
    Service,
}

impl fmt::Display for ExecutionProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Task => "task",
            Self::Service => "service",
        })
    }
}

/// The persistence class (§1.3 persistence facet: ephemeral task; declared data volumes).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistenceClass {
    /// No state outlives the task.
    Ephemeral,
    /// Writes to the volumes the declaration names may persist; preserved data remains
    /// potentially hostile (§1.4).
    DeclaredVolumes,
}

impl fmt::Display for PersistenceClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Ephemeral => "ephemeral state",
            Self::DeclaredVolumes => "declared data volumes",
        })
    }
}

/// Whether the workload cannot run without a capability (VM §2.4 line 1800).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Need {
    /// Removing it refuses planning.
    Required,
    /// Removing it drops it; the preview lists it.
    Optional,
}

/// The data class of a named input (§4.5: user private content requires a release
/// policy and is not safe merely because it is not an API key).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    Ordinary,
    /// Adds a private-data access approval for the read (VM-P46).
    UserPrivateContent,
}

/// The six secret classes of VM §4.5 and what a tool may ask for under each.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialClass {
    LongLivedProviderCredential,
    ShortLivedExternalCapability,
    SignedDownloadUrl,
    SandboxLocalSecret,
    UserPrivateContent,
    FakeCanary,
}

impl CredentialClass {
    pub const ALL: [Self; 6] = [
        Self::LongLivedProviderCredential,
        Self::ShortLivedExternalCapability,
        Self::SignedDownloadUrl,
        Self::SandboxLocalSecret,
        Self::UserPrivateContent,
        Self::FakeCanary,
    ];

    /// The treatment column of the §4.5 table.
    pub const fn treatment(self) -> &'static str {
        match self {
            Self::LongLivedProviderCredential => {
                "Remains in vault/executor; never intentionally delivered to the workload"
            }
            Self::ShortLivedExternalCapability => {
                "Scope, audience, expiry and delegated budget explicit; still a credential"
            }
            Self::SignedDownloadUrl => {
                "Bearer capability, not \u{201c}non-secret\u{201d}; avoid guest exposure in \
                 strict profile"
            }
            Self::SandboxLocalSecret => {
                "May exist in guest; cannot authorize host or external privileges"
            }
            Self::UserPrivateContent => {
                "Confidential data requiring release policy; not made safe merely because it \
                 is not an API key"
            }
            Self::FakeCanary => "Detection artifact; never a genuine production credential",
        }
    }

    /// Whether a declaration may ask for it to be present in the guest. A long-lived
    /// provider credential stays with the executor (use a typed provider operation), user
    /// private content is data (declare an input), and canaries are installed by the
    /// host, never requested.
    pub const fn may_be_requested_in_guest(self) -> bool {
        matches!(
            self,
            Self::ShortLivedExternalCapability | Self::SignedDownloadUrl | Self::SandboxLocalSecret
        )
    }

    /// Whether the guest receiving it is an external credential delivery in the §1.3
    /// sense; a sandbox-local secret is not.
    pub const fn is_external_credential(self) -> bool {
        matches!(
            self,
            Self::LongLivedProviderCredential
                | Self::ShortLivedExternalCapability
                | Self::SignedDownloadUrl
        )
    }
}

impl fmt::Display for CredentialClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::LongLivedProviderCredential => "long-lived external provider credential",
            Self::ShortLivedExternalCapability => "short-lived external capability",
            Self::SignedDownloadUrl => "signed download URL",
            Self::SandboxLocalSecret => "sandbox-local secret",
            Self::UserPrivateContent => "user private content",
            Self::FakeCanary => "fake canary",
        })
    }
}

/// The runtime an extension executor uses. None of them is a sandbox: each runs inside
/// the VM of the sandbox role it names (VM-W37, line 2478).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionRuntime {
    Wasm,
    NativePlugin,
    Script,
}

impl ExtensionRuntime {
    pub const ALL: [Self; 3] = [Self::Wasm, Self::NativePlugin, Self::Script];

    /// The stable name in declarations.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Wasm => "wasm",
            Self::NativePlugin => "native_plugin",
            Self::Script => "script",
        }
    }
}

impl fmt::Display for ExtensionRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Wasm => "Wasm",
            Self::NativePlugin => "native plugin",
            Self::Script => "script interpreter",
        })
    }
}

/// One sandbox (one VM) of the setup, by role (VM §1.4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxDeclaration {
    pub role: RoleName,
    pub profile: ExecutionProfile,
    pub persistence: PersistenceClass,
    /// Only `vm_sandbox` is accepted; a labelled runtime is never a sandbox (VM-D4–VM-D6)
    /// and is refused rather than requested here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_category: Option<ExecutionCategory>,
}

strict_declaration_enum! {
    /// What one capability asks for. Every name is exact: the identifier grammar has no
    /// wildcard character, and a wildcard destination is refused (VM-W03).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Capability tag "kind" {
        /// Read a named input through a host file grant.
        ReadInput { grant: ResourceName, data_class: DataClass },
        /// Write a named output through a host file grant.
        WriteOutput { grant: ResourceName },
        /// Write a declared data volume; the sandbox must declare `declared_volumes`.
        WriteVolume { volume: ResourceName },
        /// Use an explicitly assigned GPU; adds the `assigned_gpu_isolated` requirement.
        Gpu { device: ResourceName },
        /// A typed provider operation the host's executor performs on an account (§4.6).
        ProviderOperation { account: ResourceName, operation: OperationName },
        /// Connect to one exact destination, `host` or `host:port` (port 443 by default).
        Connect { destination: String },
        /// Publish a named service.
        PublishService { service: ResourceName },
        /// Release outputs through a named channel.
        Release { channel: ResourceName },
        /// Receive a short-lived external capability in the guest (§4.5: scope,
        /// audience, expiry and delegated budget explicit). `delegated_effects` becomes a
        /// V01 `short_lived_credential_effects` budget on this credential, so it can only
        /// lower the host's limit.
        ShortLivedCredential {
            name: ResourceName,
            audience: CanonicalName,
            scope: OperationName,
            expires_in_seconds: NonZeroU64,
            delegated_effects: NonZeroU64,
        },
        /// Receive a signed download URL, a bearer capability (§4.5).
        SignedDownloadUrl { name: ResourceName },
        /// A secret that exists only in the guest and authorizes nothing outside it.
        SandboxLocalSecret { name: ResourceName },
        /// A long-lived provider credential; always refused (§4.5: never delivered).
        ProviderCredential { name: ResourceName },
        /// A canary; always refused (canaries are the host's detection artifacts).
        FakeCanary { name: ResourceName },
    }
}

impl Capability {
    /// Every capability kind this version knows, as written in the `kind` tag.
    pub const KINDS: [&'static str; 13] = [
        "read_input",
        "write_output",
        "write_volume",
        "gpu",
        "provider_operation",
        "connect",
        "publish_service",
        "release",
        "short_lived_credential",
        "signed_download_url",
        "sandbox_local_secret",
        "provider_credential",
        "fake_canary",
    ];

    /// The `kind` tag of this capability.
    pub const fn kind_name(&self) -> &'static str {
        match self {
            Self::ReadInput { .. } => "read_input",
            Self::WriteOutput { .. } => "write_output",
            Self::WriteVolume { .. } => "write_volume",
            Self::Gpu { .. } => "gpu",
            Self::ProviderOperation { .. } => "provider_operation",
            Self::Connect { .. } => "connect",
            Self::PublishService { .. } => "publish_service",
            Self::Release { .. } => "release",
            Self::ShortLivedCredential { .. } => "short_lived_credential",
            Self::SignedDownloadUrl { .. } => "signed_download_url",
            Self::SandboxLocalSecret { .. } => "sandbox_local_secret",
            Self::ProviderCredential { .. } => "provider_credential",
            Self::FakeCanary { .. } => "fake_canary",
        }
    }

    /// The §4.5 class, for the credential kinds.
    pub const fn credential_class(&self) -> Option<CredentialClass> {
        match self {
            Self::ShortLivedCredential { .. } => {
                Some(CredentialClass::ShortLivedExternalCapability)
            }
            Self::SignedDownloadUrl { .. } => Some(CredentialClass::SignedDownloadUrl),
            Self::SandboxLocalSecret { .. } => Some(CredentialClass::SandboxLocalSecret),
            Self::ProviderCredential { .. } => Some(CredentialClass::LongLivedProviderCredential),
            Self::FakeCanary { .. } => Some(CredentialClass::FakeCanary),
            Self::ReadInput {
                data_class: DataClass::UserPrivateContent,
                ..
            } => Some(CredentialClass::UserPrivateContent),
            Self::ReadInput { .. }
            | Self::WriteOutput { .. }
            | Self::WriteVolume { .. }
            | Self::Gpu { .. }
            | Self::ProviderOperation { .. }
            | Self::Connect { .. }
            | Self::PublishService { .. }
            | Self::Release { .. } => None,
        }
    }
}

/// One capability with the sandbox role and phase it is for, whether the workload needs
/// it, and an approval the declaration asks to be required for it. An approval named
/// here is only ever added to the required approvals (they accumulate, §2.4 line 1802);
/// a declaration cannot grant or satisfy one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityDeclaration {
    pub need: Need,
    pub role: RoleName,
    pub phase: Phase,
    pub capability: Capability,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalKind>,
}

/// An extension executor (Wasm or another plugin runtime). Its code comes from the
/// template or tool, so it is always treated as untrusted and runs inside the VM of
/// `role` (line 2478); it adds no authority of its own.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionDeclaration {
    pub name: ExtensionName,
    pub role: RoleName,
    pub runtime: ExtensionRuntime,
    /// Only `vm_sandbox` is accepted (VM-D4–VM-D6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_category: Option<ExecutionCategory>,
}

/// A tool or Hub template's capability declaration (VM-W37). A request, never a grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Declaration {
    pub declaration_version: DeclarationVersion,
    /// The template, tool or user that wrote it, recorded as V01's request source. A
    /// user-authored declaration is an untrusted request like any other (VM-W37 "user-
    /// authored declarations cannot grant themselves authority").
    pub source: RequestSource,
    pub sandboxes: Vec<SandboxDeclaration>,
    #[serde(default)]
    pub capabilities: Vec<CapabilityDeclaration>,
    #[serde(default)]
    pub extensions: Vec<ExtensionDeclaration>,
    /// Extra required predicates by name; V01 refuses an unknown one.
    #[serde(default)]
    pub requires: Vec<String>,
    /// An old manifest's isolation tier; V01 migrates or refuses it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_tier: Option<String>,
    /// Budgets the declaration asks for; V01 takes minima, so they can only lower a limit.
    #[serde(default)]
    pub budgets: Vec<Budget>,
}

/// Keys that would hand a declaration authority it cannot have: a ceiling, a delegation,
/// granted approvals, satisfied evidence, a bound generation or trust. None is a schema
/// field; each found at any depth refuses with `authority_field`.
pub const AUTHORITY_FIELDS: &[&str] = &[
    "ceiling",
    "product_ceiling",
    "product",
    "delegation",
    "delegated",
    "granted",
    "grants",
    "approved",
    "approval_grants",
    "pre_approved",
    "permitted",
    "satisfied",
    "verified",
    "evidence",
    "host_evidence",
    "attested",
    "trusted",
    "generation",
    "policy_epoch",
    "authorization_epoch",
    "override",
    "budget_override",
    "unlimited",
];

/// Reads a declaration from JSON text (VM-W37; VM-P47).
///
/// Order: the text must be a JSON object; its `declaration_version` must be present and
/// equal to [`DECLARATION_VERSION`] (any other version stops reading, since its fields
/// are not this version's); then every authority field, unknown capability kind and
/// unknown extension runtime is reported together; then the strict schema is applied,
/// which also refuses a key repeated within one object.
pub fn read_declaration(text: &str) -> Result<Declaration, RefusalReport> {
    let value: Value = serde_json::from_str(text).map_err(|error| {
        RefusalReport::single(RefusalDetail::DeclarationNotJson {
            message: bounded(&error.to_string()),
        })
    })?;
    let Value::Object(fields) = &value else {
        return Err(RefusalReport::single(RefusalDetail::DeclarationNotObject));
    };
    match fields.get("declaration_version") {
        None => {
            return Err(RefusalReport::single(
                RefusalDetail::DeclarationVersionMissing,
            ))
        }
        Some(found) if found.as_u64() != Some(u64::from(DECLARATION_VERSION)) => {
            return Err(RefusalReport::single(
                RefusalDetail::UnsupportedDeclarationVersion {
                    found: bounded(&found.to_string()),
                },
            ))
        }
        Some(_) => {}
    }
    let mut found = Vec::new();
    scan_authority_fields(&value, "$", &mut found);
    scan_kinds(fields, &mut found);
    found.sort_by(|left, right| left.0.cmp(&right.0));
    if let Some(report) = RefusalReport::from_details(found.into_iter().map(|(_, detail)| detail)) {
        return Err(report);
    }
    // The strict schema reads the original text, not the parsed value: a value keeps only
    // the last of two equal keys, while the derived reader refuses the duplicate, so a
    // document cannot mean one thing to another reader and another thing here.
    serde_json::from_str(text).map_err(|error| RefusalReport::single(classify(&error)))
}

fn scan_authority_fields(value: &Value, path: &str, found: &mut Vec<(String, RefusalDetail)>) {
    match value {
        Value::Object(fields) => {
            for (key, inner) in fields {
                let here = format!("{path}.{}", bounded(key));
                if AUTHORITY_FIELDS.contains(&key.as_str()) {
                    found.push((
                        here.clone(),
                        RefusalDetail::AuthorityField {
                            path: here.clone(),
                            field: bounded(key),
                        },
                    ));
                }
                scan_authority_fields(inner, &here, found);
            }
        }
        Value::Array(items) => {
            for (index, inner) in items.iter().enumerate() {
                scan_authority_fields(inner, &format!("{path}[{index}]"), found);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn scan_kinds(fields: &serde_json::Map<String, Value>, found: &mut Vec<(String, RefusalDetail)>) {
    if let Some(Value::Array(capabilities)) = fields.get("capabilities") {
        for (index, entry) in capabilities.iter().enumerate() {
            let kind = entry
                .get("capability")
                .and_then(|capability| capability.get("kind"))
                .and_then(Value::as_str);
            if let Some(kind) = kind {
                if !Capability::KINDS.contains(&kind) {
                    let path = format!("$.capabilities[{index}].capability.kind");
                    found.push((
                        path.clone(),
                        RefusalDetail::UnknownCapability {
                            path,
                            name: bounded(kind),
                        },
                    ));
                }
            }
        }
    }
    if let Some(Value::Array(extensions)) = fields.get("extensions") {
        for (index, entry) in extensions.iter().enumerate() {
            if let Some(runtime) = entry.get("runtime").and_then(Value::as_str) {
                if !ExtensionRuntime::ALL
                    .iter()
                    .any(|known| known.name() == runtime)
                {
                    let path = format!("$.extensions[{index}].runtime");
                    found.push((
                        path.clone(),
                        RefusalDetail::UnknownExtensionRuntime {
                            path,
                            name: bounded(runtime),
                        },
                    ));
                }
            }
        }
    }
}

/// serde reports an unknown field as "unknown field `name`, expected ..." (serde 1.x);
/// a test pins this, so a change in serde's wording fails loudly instead of silently
/// reclassifying the refusal.
fn classify(error: &serde_json::Error) -> RefusalDetail {
    let message = error.to_string();
    if let Some(rest) = message.strip_prefix("unknown field `") {
        if let Some(field) = rest.split('`').next() {
            return RefusalDetail::UnknownField {
                field: bounded(field),
            };
        }
    }
    RefusalDetail::InvalidDeclaration {
        message: bounded(&message),
    }
}
