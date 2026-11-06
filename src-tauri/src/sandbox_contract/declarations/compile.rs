//! Compiling a declaration into a V01 request (VM-W37; VM part §2.4, §4.5, §4.6).
//!
//! A declaration is a request, never a grant. Compiling it produces a V01
//! [`RequestDocument`] with the template or tool recorded as its source, and nothing
//! else: the product ceiling, the delegation, approval grants and host evidence are
//! separate inputs the declaration cannot reach. Each capability becomes one permission
//! tuple; required capabilities are also V01 dependencies, so V01 refuses planning when
//! the intersection removes one (§2.4 line 1800). Approvals a declaration names are only
//! added to the required approvals, and its budgets only ever lower a limit, because V01
//! accumulates approvals and takes budget minima (line 1802).
//!
//! Requirements the compiler adds, each a V01 predicate:
//!
//! - `vm_sandbox`, always: every sandbox and every extension executor runs in a VM
//!   (line 2478; VM-D4–VM-D6), and a labelled runtime is refused here.
//! - `contract_bounded_lifetime` when any sandbox has the task profile.
//! - `contract_offline`, `contract_no_external_credentials`, `contract_ephemeral_state`
//!   and `contract_cpu_only` when the declaration asks for no network authority, no
//!   external credential, no volume write and no GPU respectively; these describe the
//!   contract and never claim enforcement.
//! - `assigned_gpu_isolated` when it asks for a GPU (VM-P39), whether required or
//!   optional, since requirements are fixed before resolution.
//!
//! A destination becomes a route resource named by the one shared route reference,
//! canonical `host:port` (V02 `route_reference`, through V01 `ResourceRef::route`), so the
//! product ceiling and delegation name the same route the same way. A short-lived
//! credential's delegated budget becomes a V01 `short_lived_credential_effects` budget on
//! that credential.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;

use serde::{Deserialize, Serialize};

use super::refusal::{bounded, RefusalDetail, RefusalReport};
use super::schema::{
    Capability, CapabilityDeclaration, CredentialClass, DataClass, Declaration, ExecutionProfile,
    ExtensionDeclaration, Need, PersistenceClass, SandboxDeclaration,
};
use crate::sandbox_contract::destinations::{
    Authority, CanonicalName, DestinationHost, DestinationPort, NameError,
};
use crate::sandbox_contract::policy::{
    AccountingScope, Action, ApprovalKind, ApprovalRule, Budget, BudgetResource, Context,
    GenerationScope, Operation, OperationName, PermissionTuple, Principal, RequestDocument,
    RequestSource, ResourceKind, ResourceName, ResourceRef, RoleName, SecurityPredicate, Validator,
    WorkloadRequest, CONTRACT_SCHEMA_VERSION,
};

/// One capability as a V01 permission tuple with the approval rules it adds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledCapability {
    pub need: Need,
    pub tuple: PermissionTuple,
    pub approvals: Vec<ApprovalRule>,
}

/// The §4.5 terms of a credential the declaration asks for, kept for display; V01
/// tuples carry only the credential's name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialTerms {
    pub role: RoleName,
    pub name: ResourceName,
    pub class: CredentialClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<CanonicalName>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<OperationName>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in_seconds: Option<NonZeroU64>,
    /// The delegated budget: external effects the credential may authorize.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_effects: Option<NonZeroU64>,
}

/// What the declaration said beyond its permission tuples, for the preview's "what
/// will run" section: provenance, sandboxes, extensions and credential terms. None of it
/// is authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredContext {
    pub source: RequestSource,
    pub sandboxes: Vec<SandboxDeclaration>,
    pub extensions: Vec<ExtensionDeclaration>,
    pub credentials: Vec<CredentialTerms>,
}

/// A compiled declaration: the V01 request document and how each capability lowered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CompiledDeclaration {
    document: RequestDocument,
    capabilities: Vec<CompiledCapability>,
    context: DeclaredContext,
}

impl CompiledDeclaration {
    /// The V01 request; untrusted input to V01's validator like any other request.
    pub fn document(&self) -> &RequestDocument {
        &self.document
    }

    pub fn capabilities(&self) -> &[CompiledCapability] {
        &self.capabilities
    }

    pub fn context(&self) -> &DeclaredContext {
        &self.context
    }

    /// Validates the request with V01's [`Validator`]; its issues keep their V01
    /// reasons under stable codes.
    pub fn validate(&self) -> Result<WorkloadRequest, RefusalReport> {
        Validator::request(&self.document).map_err(RefusalReport::from)
    }
}

enum Lowered {
    Tuple {
        tuple: PermissionTuple,
        approvals: Vec<ApprovalRule>,
        terms: Option<CredentialTerms>,
    },
    /// A sandbox-local secret: present in the guest only, so no host operation.
    Local(CredentialTerms),
}

impl Declaration {
    /// Compiles the declaration into a V01 request (VM-W37), refusing with every
    /// declaration-level problem found.
    pub fn compile(&self) -> Result<CompiledDeclaration, RefusalReport> {
        let mut refusals = Vec::new();
        if self.sandboxes.is_empty() {
            refusals.push(RefusalDetail::NoSandbox);
        }
        let mut roles: BTreeMap<RoleName, &SandboxDeclaration> = BTreeMap::new();
        for sandbox in &self.sandboxes {
            if roles.insert(sandbox.role.clone(), sandbox).is_some() {
                refusals.push(RefusalDetail::DuplicateSandboxRole {
                    role: sandbox.role.clone(),
                });
            }
            if let Some(category) = sandbox.execution_category {
                if !category.is_vm_sandbox() {
                    refusals.push(RefusalDetail::LabelledRuntime {
                        subject: format!("sandbox \"{}\"", sandbox.role),
                        category,
                    });
                }
            }
        }

        let mut capabilities: Vec<CompiledCapability> = Vec::new();
        let mut credentials = Vec::new();
        let mut seen: BTreeSet<Action> = BTreeSet::new();
        for (index, declared) in self.capabilities.iter().enumerate() {
            let path = format!("$.capabilities[{index}]");
            let Some(sandbox) = roles.get(&declared.role) else {
                refusals.push(RefusalDetail::UndeclaredSandboxRole {
                    role: declared.role.clone(),
                    path,
                });
                continue;
            };
            match lower(declared, sandbox) {
                Ok(Lowered::Tuple {
                    tuple,
                    approvals,
                    terms,
                }) => {
                    if !seen.insert(tuple.action()) {
                        refusals.push(RefusalDetail::DuplicateCapability { tuple });
                        continue;
                    }
                    credentials.extend(terms);
                    capabilities.push(CompiledCapability {
                        need: declared.need,
                        tuple,
                        approvals,
                    });
                }
                Ok(Lowered::Local(terms)) => {
                    if declared.approval.is_some() {
                        refusals.push(RefusalDetail::ApprovalWithoutOperation {
                            path: format!("{path}.approval"),
                        });
                    }
                    credentials.push(terms);
                }
                Err(detail) => refusals.push(*detail),
            }
        }

        let mut extension_names = BTreeSet::new();
        for (index, extension) in self.extensions.iter().enumerate() {
            if !extension_names.insert(extension.name.clone()) {
                refusals.push(RefusalDetail::DuplicateExtension {
                    name: extension.name.clone(),
                });
            }
            if !roles.contains_key(&extension.role) {
                refusals.push(RefusalDetail::UndeclaredSandboxRole {
                    role: extension.role.clone(),
                    path: format!("$.extensions[{index}]"),
                });
            }
            if let Some(category) = extension.execution_category {
                if !category.is_vm_sandbox() {
                    refusals.push(RefusalDetail::LabelledRuntime {
                        subject: format!("extension executor \"{}\"", extension.name),
                        category,
                    });
                }
            }
        }

        if let Some(report) = RefusalReport::from_details(refusals) {
            return Err(report);
        }

        let requires = self.requirement_names(&capabilities);
        let document = RequestDocument {
            schema_version: CONTRACT_SCHEMA_VERSION,
            source: self.source.clone(),
            requested: capabilities.iter().map(|item| item.tuple.clone()).collect(),
            dependencies: capabilities
                .iter()
                .filter(|item| item.need == Need::Required)
                .map(|item| item.tuple.clone())
                .collect(),
            requires,
            legacy_tier: self.legacy_tier.clone(),
            approvals: capabilities
                .iter()
                .flat_map(|item| item.approvals.iter().cloned())
                .collect(),
            budgets: self.budgets_with(&credentials),
        };
        Ok(CompiledDeclaration {
            document,
            capabilities,
            context: DeclaredContext {
                source: self.source.clone(),
                sandboxes: self.sandboxes.clone(),
                extensions: self.extensions.clone(),
                credentials,
            },
        })
    }

    /// The declared budgets, then one `short_lived_credential_effects` budget per
    /// short-lived credential, on that credential. V01 takes minima, so each can only
    /// lower the host's limit; a declared budget under the same key is a duplicate V01
    /// refuses.
    fn budgets_with(&self, credentials: &[CredentialTerms]) -> Vec<Budget> {
        let mut budgets = self.budgets.clone();
        for terms in credentials {
            if let Some(effects) = terms.delegated_effects {
                budgets.push(Budget {
                    resource: BudgetResource::ShortLivedCredentialEffects,
                    scope: AccountingScope::Channel {
                        resource: ResourceRef {
                            kind: ResourceKind::Credential,
                            name: terms.name.clone(),
                        },
                    },
                    limit: effects.get(),
                });
            }
        }
        budgets
    }

    /// The declared requirement names first, in their order, then the derived ones.
    fn requirement_names(&self, capabilities: &[CompiledCapability]) -> Vec<String> {
        use SecurityPredicate as P;
        let has = |test: fn(&Operation) -> bool| {
            capabilities
                .iter()
                .any(|capability| test(&capability.tuple.operation))
        };
        let mut derived = vec![P::VmSandbox];
        if self
            .sandboxes
            .iter()
            .any(|sandbox| sandbox.profile == ExecutionProfile::Task)
        {
            derived.push(P::ContractBoundedLifetime);
        }
        if !has(Operation::is_network_authority) {
            derived.push(P::ContractOffline);
        }
        if !has(|operation| matches!(operation, Operation::ReceiveExternalCredential)) {
            derived.push(P::ContractNoExternalCredentials);
        }
        if !has(|operation| matches!(operation, Operation::VolumeWrite)) {
            derived.push(P::ContractEphemeralState);
        }
        if has(|operation| matches!(operation, Operation::DeviceUse)) {
            derived.push(P::AssignedGpuIsolated);
        } else {
            derived.push(P::ContractCpuOnly);
        }
        let mut names = self.requires.clone();
        for predicate in derived {
            let name = predicate.name();
            if !names.iter().any(|existing| existing == name) {
                names.push(name.to_owned());
            }
        }
        names
    }
}

fn lower(
    declared: &CapabilityDeclaration,
    sandbox: &SandboxDeclaration,
) -> Result<Lowered, Box<RefusalDetail>> {
    let tuple = |operation: Operation, resource: ResourceRef| PermissionTuple {
        principal: Principal {
            role: declared.role.clone(),
        },
        operation,
        resource,
        context: Context {
            phase: declared.phase,
        },
        generation: GenerationScope::EveryGeneration,
    };
    let named = |kind: ResourceKind, name: &ResourceName| ResourceRef {
        kind,
        name: name.clone(),
    };
    let terms = |name: &ResourceName, class: CredentialClass| CredentialTerms {
        role: declared.role.clone(),
        name: name.clone(),
        class,
        audience: None,
        scope: None,
        expires_in_seconds: None,
        delegated_effects: None,
    };
    let (tuple, terms) = match &declared.capability {
        Capability::ReadInput { grant, .. } => (
            tuple(Operation::FileRead, named(ResourceKind::FileGrant, grant)),
            None,
        ),
        Capability::WriteOutput { grant } => (
            tuple(Operation::FileWrite, named(ResourceKind::FileGrant, grant)),
            None,
        ),
        Capability::WriteVolume { volume } => {
            if sandbox.persistence == PersistenceClass::Ephemeral {
                return refuse(RefusalDetail::VolumeOnEphemeralSandbox {
                    role: declared.role.clone(),
                    volume: volume.clone(),
                });
            }
            (
                tuple(Operation::VolumeWrite, named(ResourceKind::Volume, volume)),
                None,
            )
        }
        Capability::Gpu { device } => (
            tuple(Operation::DeviceUse, named(ResourceKind::Device, device)),
            None,
        ),
        Capability::ProviderOperation { account, operation } => (
            tuple(
                Operation::ProviderOperation {
                    name: operation.clone(),
                },
                named(ResourceKind::ProviderAccount, account),
            ),
            None,
        ),
        Capability::Connect { destination } => (
            tuple(Operation::TransportConnect, route_resource(destination)?),
            None,
        ),
        Capability::PublishService { service } => (
            tuple(
                Operation::PublishService,
                named(ResourceKind::Service, service),
            ),
            None,
        ),
        Capability::Release { channel } => (
            tuple(
                Operation::Release,
                named(ResourceKind::ReleaseChannel, channel),
            ),
            None,
        ),
        Capability::ShortLivedCredential {
            name,
            audience,
            scope,
            expires_in_seconds,
            delegated_effects,
        } => (
            tuple(
                Operation::ReceiveExternalCredential,
                named(ResourceKind::Credential, name),
            ),
            Some(CredentialTerms {
                audience: Some(audience.clone()),
                scope: Some(scope.clone()),
                expires_in_seconds: Some(*expires_in_seconds),
                delegated_effects: Some(*delegated_effects),
                ..terms(name, CredentialClass::ShortLivedExternalCapability)
            }),
        ),
        Capability::SignedDownloadUrl { name } => (
            tuple(
                Operation::ReceiveExternalCredential,
                named(ResourceKind::Credential, name),
            ),
            Some(terms(name, CredentialClass::SignedDownloadUrl)),
        ),
        Capability::SandboxLocalSecret { name } => {
            return Ok(Lowered::Local(terms(
                name,
                CredentialClass::SandboxLocalSecret,
            )))
        }
        Capability::ProviderCredential { name } => {
            return refuse(RefusalDetail::CredentialNeverDelivered { name: name.clone() })
        }
        Capability::FakeCanary { name } => {
            return refuse(RefusalDetail::CanaryNotRequestable { name: name.clone() })
        }
    };
    let mut approvals = Vec::new();
    if let Capability::ReadInput {
        data_class: DataClass::UserPrivateContent,
        ..
    } = &declared.capability
    {
        approvals.push(rule(ApprovalKind::PrivateDataAccess, &tuple));
    }
    if let Some(kind) = declared.approval {
        let asked = rule(kind, &tuple);
        if !approvals.contains(&asked) {
            approvals.push(asked);
        }
    }
    Ok(Lowered::Tuple {
        tuple,
        approvals,
        terms,
    })
}

fn rule(kind: ApprovalKind, tuple: &PermissionTuple) -> ApprovalRule {
    ApprovalRule {
        kind,
        operation: tuple.operation.clone(),
        resource: tuple.resource.clone(),
    }
}

/// The route resource for one exact destination, named by the shared route reference
/// (V02 [`route_reference`](crate::sandbox_contract::destinations::route_reference)
/// through V01's [`ResourceRef::route`]).
fn route_resource(destination: &str) -> Result<ResourceRef, Box<RefusalDetail>> {
    let shown = bounded(destination);
    if destination.contains('*') {
        return refuse(RefusalDetail::WildcardDestination { destination: shown });
    }
    let authority = match Authority::parse(destination, DestinationPort::HTTPS) {
        Ok(authority) => authority,
        Err(NameError::IpLiteral { .. }) => {
            return refuse(RefusalDetail::DestinationNotAName { destination: shown })
        }
        Err(error) => {
            return refuse(RefusalDetail::InvalidDestination {
                destination: shown,
                reason: bounded(&error.to_string()),
            })
        }
    };
    let name = match &authority.host {
        DestinationHost::Name(name) => name,
        DestinationHost::Address(_) => {
            return refuse(RefusalDetail::DestinationNotAName { destination: shown })
        }
    };
    if let Some(suffix) = name.special_use_suffix() {
        return refuse(RefusalDetail::InvalidDestination {
            destination: shown,
            reason: format!(
                "{name} is under the special-use suffix {suffix}, which never resolves to a \
                 public service; only host policy grants an exact endpoint there"
            ),
        });
    }
    ResourceRef::route(&authority).map_err(|error| {
        Box::new(RefusalDetail::InvalidDestination {
            destination: shown.clone(),
            reason: error.to_string(),
        })
    })
}

/// A refusal of one capability; boxed, since a detail can hold whole tuples.
fn refuse<T>(detail: RefusalDetail) -> Result<T, Box<RefusalDetail>> {
    Err(Box::new(detail))
}
