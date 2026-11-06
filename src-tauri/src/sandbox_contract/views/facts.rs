//! The facts a view shows (VM-W04: launch and evidence fields; VM-W53: capability,
//! private-data/effect, persistence and evidence fields; §8.1: what a launch record
//! binds).
//!
//! A [`FactValue`] is one typed value, reused from the type that owns it: the launch
//! record's backend identity, pinned artifacts, device profile and host or guest facts
//! (`sandbox::backend`), V02's network mode, and V08's preview lines for what the contract
//! permits. Each value belongs to exactly one [`Section`], and each kind of value may
//! stand on certain bases only: a host fact on a host observation, on its absence or on a
//! guest assertion; a contract line on the contract; and so on ([`FactValue::fits`]). A
//! view whose fact stands on a basis that does not fit is refused when read, so a stored
//! accelerator cannot be relabelled as a contract statement or a contract line as a host
//! observation.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::labels::{AssertedBy, FactBasis, FactLabel};
use super::sections::Section;
use crate::foundation::evidence::{ClockReading, ConfigurationFingerprint, HypervisorKind};
use crate::foundation::ids::Digest;
use crate::sandbox::backend::{
    Accelerator, BackendIdentity, ConfinementControl, CredentialExposure, DeviceExposure,
    DeviceInventory, DeviceProfile, FactName, HostBuild, IsolationObservation, NetworkAuthority,
    OperatorConfidentiality, Persistence, PinnedArtifacts,
};
use crate::sandbox_contract::declarations::{
    AccessLine, ApprovalLine, ApprovalStatus, BudgetLine, CredentialLine, CredentialTerms, Need,
    Refusal, RunLine,
};
use crate::sandbox_contract::destinations::NetworkMode;
use crate::sandbox_contract::policy::{
    ApprovalKind, BudgetResource, BudgetUnit, Operation, PermissionTuple,
};

strict_view_enum! {
    /// One typed fact of a view.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum FactValue tag "kind" {
        /// The backend build that launched the VM (§8.1 "backend and artifact versions").
        Backend { backend: BackendIdentity },
        /// The guest image and backend build the launch was pinned to.
        PinnedArtifacts { pinned: PinnedArtifacts },
        /// The approved device profile the VM was built with (VM-P02).
        DeviceProfile { profile: DeviceProfile },
        /// A usable hardware hypervisor on the host, as CORE-01 host-probe evidence.
        HypervisorAvailable { hypervisor: HypervisorKind },
        /// The accelerator the VM runs on (VM-W22: the actual one, not the requested flag).
        Accelerator { accelerator: Accelerator },
        /// The host operating system, build and architecture.
        HostBuild { host: HostBuild },
        /// The guest image the host observed booted.
        GuestImage { image: Digest },
        Isolation { isolation: IsolationObservation },
        /// The controls the hypervisor process runs under.
        Confinement { controls: BTreeSet<ConfinementControl> },
        /// The network channels the sandbox has.
        Network { authority: NetworkAuthority },
        /// The credentials the sandbox is exposed to.
        Credentials { exposure: CredentialExposure },
        /// What the sandbox keeps across runs.
        Persistence { persistence: Persistence },
        /// The devices the host measured on the VM.
        Devices { inventory: DeviceInventory },
        Confidentiality { confidentiality: OperatorConfidentiality },
        /// A host fact of which the host has no observation.
        Unobserved { fact: FactName },
        /// The V02 network mode the setup chose (§4.1).
        NetworkMode { mode: NetworkMode },
        /// Whether the contract grants any network authority (V01 `contract_offline`).
        ContractNetwork { offline: bool },
        /// One sandbox the setup runs, as declared (V08).
        Run { run: RunLine },
        /// One permitted tuple (V08 preview line).
        Access { access: AccessLine },
        /// A credential the guest would receive, with its §4.5 terms.
        Credential { credential: CredentialLine },
        /// A sandbox-local secret the declaration names.
        LocalSecret { secret: CredentialTerms },
        /// One required approval and its status.
        Approval { approval: ApprovalLine },
        /// One effective budget.
        Budget { budget: BudgetLine },
        /// A requested capability the contract does not permit.
        Requested { tuple: PermissionTuple, need: Need },
        /// A refusal from planning the launch (V08 refusal with its stable code).
        Planning { refusal: Refusal },
    }
}

impl FactValue {
    /// The one section the value is shown in.
    pub fn section(&self) -> Section {
        match self {
            Self::Backend { .. }
            | Self::PinnedArtifacts { .. }
            | Self::DeviceProfile { .. }
            | Self::HypervisorAvailable { .. }
            | Self::Accelerator { .. }
            | Self::HostBuild { .. }
            | Self::GuestImage { .. }
            | Self::Isolation { .. }
            | Self::Confinement { .. }
            | Self::Devices { .. }
            | Self::Confidentiality { .. }
            | Self::Run { .. } => Section::WhatRuns,
            Self::Credentials { .. }
            | Self::Persistence { .. }
            | Self::Credential { .. }
            | Self::LocalSecret { .. } => Section::ReadsAndKeeps,
            Self::Network { .. } | Self::NetworkMode { .. } | Self::ContractNetwork { .. } => {
                Section::Releases
            }
            Self::Requested { .. } | Self::Planning { .. } => Section::Unavailable,
            Self::Unobserved { fact } => fact_section(*fact),
            Self::Access { access } => operation_section(&access.tuple.operation),
            Self::Approval { approval } => match approval.rule.kind {
                ApprovalKind::PrivateDataAccess => Section::ReadsAndKeeps,
                ApprovalKind::OngoingDelegation | ApprovalKind::ExactRelease => Section::Releases,
            },
            Self::Budget { budget } => match budget.key.resource {
                BudgetResource::ReleaseBytes | BudgetResource::ReleaseEffects => Section::Releases,
                BudgetResource::ShortLivedCredentialEffects => Section::ReadsAndKeeps,
                BudgetResource::IdleLifetimeSeconds
                | BudgetResource::AbsoluteLifetimeSeconds
                | BudgetResource::ServiceRenewalSeconds => Section::WhatRuns,
            },
        }
    }

    /// Whether the value may stand on `basis`: a host fact on a host observation, its
    /// absence or a guest assertion; CORE-01 hypervisor evidence on that evidence; what
    /// the launch request pinned on the launch request; declared and contract lines on the
    /// declaration or the contract; a removed capability on the contract's refusal to
    /// permit it; a planning refusal on that refusal.
    pub fn fits(&self, basis: &FactBasis) -> bool {
        let host = matches!(
            basis,
            FactBasis::HostObserved { .. } | FactBasis::HostVerified { .. }
        );
        let asserted = |wanted: AssertedBy| {
            matches!(basis, FactBasis::Asserted { by, received_at }
                if *by == wanted && (received_at.is_some() == (wanted == AssertedBy::Guest)))
        };
        match self {
            Self::Backend { .. } | Self::PinnedArtifacts { .. } | Self::DeviceProfile { .. } => {
                asserted(AssertedBy::LaunchRequest)
            }
            Self::HypervisorAvailable { .. } => matches!(basis, FactBasis::Core01Evidence { .. }),
            Self::HostBuild { .. } | Self::GuestImage { .. } => host,
            Self::Accelerator { .. }
            | Self::Isolation { .. }
            | Self::Confinement { .. }
            | Self::Network { .. }
            | Self::Credentials { .. }
            | Self::Persistence { .. }
            | Self::Devices { .. }
            | Self::Confidentiality { .. } => host || asserted(AssertedBy::Guest),
            Self::Unobserved { .. } => matches!(basis, FactBasis::NotObserved { .. }),
            Self::NetworkMode { .. } | Self::Run { .. } | Self::LocalSecret { .. } => {
                asserted(AssertedBy::Declaration)
            }
            Self::ContractNetwork { .. }
            | Self::Access { .. }
            | Self::Credential { .. }
            | Self::Approval { .. }
            | Self::Budget { .. } => asserted(AssertedBy::Contract),
            Self::Requested { .. } => matches!(basis, FactBasis::NotPermitted { .. }),
            Self::Planning { refusal } => {
                matches!(basis, FactBasis::Refused { code, .. } if *code == refusal.code)
            }
        }
    }
}

/// The section of a host fact by name.
fn fact_section(fact: FactName) -> Section {
    match fact {
        FactName::HypervisorEvidence
        | FactName::Accelerator
        | FactName::Host
        | FactName::GuestImage
        | FactName::Isolation
        | FactName::Confinement
        | FactName::Devices
        | FactName::Confidentiality => Section::WhatRuns,
        FactName::Credentials | FactName::Persistence => Section::ReadsAndKeeps,
        FactName::Network => Section::Releases,
    }
}

/// The section of a permitted operation: outbound channels are releases, devices are part
/// of what runs, and file, volume and credential access is what the sandbox reads, writes
/// and keeps.
fn operation_section(operation: &Operation) -> Section {
    if operation.is_outbound() {
        Section::Releases
    } else if matches!(operation, Operation::DeviceUse) {
        Section::WhatRuns
    } else {
        Section::ReadsAndKeeps
    }
}

fn list<'a>(tags: impl Iterator<Item = &'a str>) -> String {
    let tags: Vec<&str> = tags.collect();
    if tags.is_empty() {
        "none".to_owned()
    } else {
        tags.join(", ")
    }
}

fn devices(exposure: &DeviceExposure) -> String {
    if exposure.is_cpu_only() {
        return "CPU only".to_owned();
    }
    let gpus = exposure.gpus.len();
    format!(
        "{}{} assigned GPU{}",
        if exposure.display { "a display, " } else { "" },
        gpus,
        if gpus == 1 { "" } else { "s" }
    )
}

fn need(need: Need) -> &'static str {
    match need {
        Need::Required => "required",
        Need::Optional => "optional",
    }
}

fn access(line: &AccessLine) -> String {
    format!(
        "{} [{}{}]",
        line.tuple,
        need(line.need),
        if line.private_data {
            "; private data"
        } else {
            ""
        }
    )
}

impl fmt::Display for FactValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Backend { backend } => {
                write!(f, "backend {backend}, build {}", backend.artifact)
            }
            Self::PinnedArtifacts { pinned } => write!(
                f,
                "pinned guest image {} and backend build {}",
                pinned.guest_image, pinned.backend
            ),
            Self::DeviceProfile { profile } => write!(
                f,
                "device profile {}: {}",
                profile.identity,
                devices(&profile.devices)
            ),
            Self::HypervisorAvailable { hypervisor } => {
                write!(f, "a usable {hypervisor} hypervisor on the host")
            }
            Self::Accelerator { accelerator } => write!(f, "runs on {accelerator}"),
            Self::HostBuild { host } => write!(
                f,
                "host {} build {} on {}",
                host.os,
                host.build,
                host.architecture.tag()
            ),
            Self::GuestImage { image } => write!(f, "booted guest image {image}"),
            Self::Isolation { isolation } => write!(
                f,
                "{}, {}",
                if isolation.own_guest_kernel {
                    "its own guest kernel"
                } else {
                    "no guest kernel of its own"
                },
                isolation.physical_host
            ),
            Self::Confinement { controls } => write!(
                f,
                "hypervisor process controls: {}",
                list(controls.iter().map(|control| control.tag()))
            ),
            Self::Network { authority } if authority.is_offline() => {
                f.write_str("network: offline")
            }
            Self::Network { authority } => write!(
                f,
                "network channels: {}",
                list(authority.channels.iter().map(|channel| channel.tag()))
            ),
            Self::Credentials { exposure } => write!(
                f,
                "credentials in the guest: {}",
                list(exposure.credentials.iter().map(|kind| kind.tag()))
            ),
            Self::Persistence { persistence } => {
                let volumes = persistence.volumes().len();
                match persistence {
                    Persistence::EphemeralTask => f.write_str("persistence: ephemeral task"),
                    Persistence::DeclaredDataVolumes { .. } => write!(
                        f,
                        "persistence: {volumes} declared data volume{}",
                        if volumes == 1 { "" } else { "s" }
                    ),
                    Persistence::ControlledServiceRenewal { .. } => write!(
                        f,
                        "persistence: controlled service renewal with {volumes} volume{}",
                        if volumes == 1 { "" } else { "s" }
                    ),
                }
            }
            Self::Devices { inventory } => {
                write!(f, "devices measured: {}", devices(&inventory.exposure()))
            }
            Self::Confidentiality { confidentiality } => match confidentiality {
                OperatorConfidentiality::None => f.write_str("operator confidentiality: none"),
                OperatorConfidentiality::VerifiedConfidentialVm { scope } => write!(
                    f,
                    "operator confidentiality: a confidential VM with stated scope {scope}"
                ),
            },
            Self::Unobserved { fact } => write!(f, "{fact}"),
            Self::NetworkMode { mode } => {
                write!(f, "network mode: {}", mode.label())?;
                if let Some(broader) = mode.broader_authority() {
                    write!(f, "; {broader}")?;
                }
                Ok(())
            }
            Self::ContractNetwork { offline: true } => {
                f.write_str("the contract grants no network authority: offline")
            }
            Self::ContractNetwork { offline: false } => f.write_str(
                "the contract grants network authority; each route, operation and service is \
                 listed",
            ),
            Self::Run { run } => {
                write!(
                    f,
                    "sandbox \"{}\": {} profile, {}, requires a {}",
                    run.role,
                    run.profile,
                    run.persistence,
                    run.required_runtime.label()
                )?;
                for extension in &run.extensions {
                    write!(
                        f,
                        "; extension \"{}\" ({}) runs inside it as untrusted code and adds no \
                         authority",
                        extension.name, extension.runtime
                    )?;
                }
                Ok(())
            }
            Self::Access { access: line } => f.write_str(&access(line)),
            Self::Credential { credential } => {
                f.write_str(&access(&credential.access))?;
                if let Some(terms) = &credential.terms {
                    write!(f, " as a {}: {}", terms.class, terms.class.treatment())?;
                }
                Ok(())
            }
            Self::LocalSecret { secret } => write!(
                f,
                "secret \"{}\" in sandbox \"{}\": {}",
                secret.name,
                secret.role,
                secret.class.treatment()
            ),
            Self::Approval { approval } => write!(
                f,
                "{}: {}",
                approval.rule,
                match approval.status {
                    ApprovalStatus::Needed => "needed",
                    ApprovalStatus::Granted => "already granted for this authorization epoch",
                    ApprovalStatus::NotApplicable => "not applicable; not permitted",
                }
            ),
            Self::Budget { budget } => {
                write!(
                    f,
                    "{}: {} {}",
                    budget.key,
                    budget.limit,
                    match budget.unit {
                        BudgetUnit::Bytes => "bytes",
                        BudgetUnit::Effects => "effects",
                        BudgetUnit::Seconds => "seconds",
                    }
                )?;
                match budget.declared {
                    Some(asked) if asked > budget.limit => write!(
                        f,
                        "; the declaration asked for {asked}, and the lower limit applies"
                    ),
                    Some(asked) => write!(f, "; the declaration asked for {asked}"),
                    None => Ok(()),
                }
            }
            Self::Requested {
                tuple,
                need: wanted,
            } => {
                write!(f, "[{}] {tuple}", need(*wanted))
            }
            Self::Planning { refusal } => f.write_str(&refusal.render_text()),
        }
    }
}

/// One fact of a view and the basis it stands on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ViewFact {
    pub value: FactValue,
    pub basis: FactBasis,
}

impl ViewFact {
    pub(super) fn new(value: FactValue, basis: FactBasis) -> Self {
        Self { value, basis }
    }

    /// The label at `now` under `configuration` for a reader that accepts nothing older
    /// than `max_age`.
    pub fn label_at(
        &self,
        now: ClockReading,
        configuration: ConfigurationFingerprint,
        max_age: std::time::Duration,
    ) -> FactLabel {
        self.basis.label_at(now, configuration, max_age)
    }

    pub fn section(&self) -> Section {
        self.value.section()
    }

    /// Whether the fact comes from the launch record.
    pub fn from_launch_record(&self) -> bool {
        self.basis.from_launch_record()
    }

    /// Whether the basis fits the value ([`FactValue::fits`]).
    pub fn fits(&self) -> bool {
        self.value.fits(&self.basis)
    }
}
