//! Security requirements as predicates over deployment facets (VM part §1.3, §2.4;
//! VM-W01).
//!
//! A requirement is a predicate, not a rung on a ladder: no predicate is "smaller" or
//! "safer" than another, and the derived `Ord` below is only the canonical storage
//! order. Requirements accumulate by union. Each predicate is judged in one way only:
//! host evidence through CORE-01, or a property of the resolved contract. A contract
//! property says what the contract grants; it never says a mechanism enforces it
//! (§2.4 line 1804).

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::budget::{AccountingScope, BudgetKey, BudgetResource, BudgetSet};
use super::evidence::PredicateOutcome;
use super::tuple::{Operation, PermissionSet};

/// The deployment facets that replace the former T1–T4 score (VM §1.3). Each is reported
/// on its own; none is combined with another into a score.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentFacet {
    Isolation,
    HypervisorConfinement,
    NetworkAuthority,
    CredentialExposure,
    Persistence,
    DeviceExposure,
    OperatorConfidentiality,
    Evidence,
}

impl DeploymentFacet {
    pub const ALL: [Self; 8] = [
        Self::Isolation,
        Self::HypervisorConfinement,
        Self::NetworkAuthority,
        Self::CredentialExposure,
        Self::Persistence,
        Self::DeviceExposure,
        Self::OperatorConfidentiality,
        Self::Evidence,
    ];

    /// The examples column of the §1.3 table.
    pub const fn examples(self) -> &'static str {
        match self {
            Self::Isolation => {
                "Own guest kernel; hardware accelerator; dedicated or shared physical host"
            }
            Self::HypervisorConfinement => {
                "Account/process identity; filesystem limits; syscall/OS restrictions; \
                 resource controls"
            }
            Self::NetworkAuthority => {
                "Offline; named transport routes; typed credentialed operations; published \
                 service"
            }
            Self::CredentialExposure => {
                "External provider credentials; narrowly scoped guest credentials explicitly \
                 permitted; sandbox-local secrets"
            }
            Self::Persistence => {
                "Ephemeral task; declared data volumes; controlled service renewal"
            }
            Self::DeviceExposure => {
                "CPU only; display; explicitly assigned GPU and its isolation evidence"
            }
            Self::OperatorConfidentiality => {
                "None; verified platform-specific confidential VM with stated scope"
            }
            Self::Evidence => {
                "Backend version; artifact identities; host observations; test results and \
                 freshness"
            }
        }
    }
}

impl fmt::Display for DeploymentFacet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Isolation => "isolation",
            Self::HypervisorConfinement => "hypervisor confinement",
            Self::NetworkAuthority => "network authority",
            Self::CredentialExposure => "credential exposure",
            Self::Persistence => "persistence",
            Self::DeviceExposure => "device exposure",
            Self::OperatorConfidentiality => "operator confidentiality",
            Self::Evidence => "evidence",
        })
    }
}

/// One required property (VM §1.3, §2.4). See the module notes: the order is storage
/// order only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityPredicate {
    /// A hardware-virtualized VM with its own guest kernel (§0), observed by the host or
    /// the provider API as CORE-01 runtime category "VM sandbox". Labelled runtimes never
    /// satisfy it (VM-D4–VM-D6).
    VmSandbox,
    /// A usable hardware hypervisor on the host, observed by a host probe. It shows that
    /// one is available, not that a given VM used it.
    HardwareHypervisorAvailable,
    /// The launched VM runs on the hardware accelerator, never on emulation (VM-P42).
    HardwareAcceleratedBoot,
    /// The VM runs on a dedicated physical host.
    DedicatedPhysicalHost,
    /// Inner confinement inside the guest (VM-W07). Additional defense only: guest root
    /// is in the threat model, so it is never a mandatory exploit step (§1.2).
    InnerGuestConfinement,
    /// The hypervisor process runs under its own identity with filesystem limits,
    /// syscall/OS restrictions and resource controls, verified independently of the guest
    /// (VM-P04).
    HypervisorConfined,
    /// The guest has no network device of its own; its traffic reaches only the host's
    /// mediating channel.
    NoDirectGuestNetwork,
    /// A host barrier separate from the guest-facing guard still applies when that guard
    /// is disabled (VM-P11).
    IndependentPerimeter,
    /// The contract grants no network authority: no route, provider operation or
    /// published service.
    ContractOffline,
    /// The contract delivers no external credential into the guest.
    ContractNoExternalCredentials,
    /// The contract grants no write to a persistent volume, so writable state is the
    /// task's own.
    ContractEphemeralState,
    /// The contract declares idle and absolute lifetime budgets for the execution.
    ContractBoundedLifetime,
    /// The contract grants no device.
    ContractCpuOnly,
    /// An assigned GPU with its isolation evidence (IOMMU group, reset, detach; VM-P39).
    AssignedGpuIsolated,
    /// A verified platform-specific confidential VM with stated scope (VM-P41).
    VerifiedConfidentialVm,
    /// Host/guest boundary probes passed with host corroboration (VM-W09).
    BoundaryProbesPassed,
    /// Internal canaries are in place (VM-W10).
    InternalCanaries,
}

/// How a predicate is judged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PredicateCheck {
    /// Only by host evidence through CORE-01.
    HostEvidence(EvidenceBinding),
    /// By the resolved contract alone; it never claims enforcement.
    Contract(ContractConstraint),
}

/// The CORE-01 evidence that can satisfy a host predicate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceBinding {
    /// `Capability::RuntimeCategory` evidence admitted under
    /// `RuntimeRequirement::VmSandbox`: host probe or provider API.
    VmSandboxCategory,
    /// `Capability::HypervisorAvailable`, host probe only.
    HypervisorAvailable,
    /// `Capability::PerimeterRuleEnforced` for every block rule of the launch's perimeter
    /// profile, host probe only (VM §4.4 line 1989); one unsatisfied rule leaves the
    /// predicate unmet.
    PerimeterRulesEnforced,
    /// No CORE-01 capability observes this yet, so nothing can satisfy it; `needed`
    /// names the observation a CORE-01 adapter would have to make.
    NoCapabilityYet { needed: &'static str },
}

/// A property of the resolved contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractConstraint {
    NoNetworkAuthority,
    NoExternalCredentialDelivery,
    NoVolumeWrite,
    NoDeviceUse,
    LifetimeBounded,
}

impl ContractConstraint {
    /// Whether a permitted `operation` violates the constraint.
    pub fn forbids(self, operation: &Operation) -> bool {
        match self {
            Self::NoNetworkAuthority => operation.is_network_authority(),
            Self::NoExternalCredentialDelivery => {
                matches!(operation, Operation::ReceiveExternalCredential)
            }
            Self::NoVolumeWrite => matches!(operation, Operation::VolumeWrite),
            Self::NoDeviceUse => matches!(operation, Operation::DeviceUse),
            Self::LifetimeBounded => false,
        }
    }

    /// The budgets the constraint needs, each per execution.
    pub fn required_budgets(self) -> Vec<BudgetKey> {
        match self {
            Self::LifetimeBounded => [
                BudgetResource::IdleLifetimeSeconds,
                BudgetResource::AbsoluteLifetimeSeconds,
            ]
            .into_iter()
            .map(|resource| BudgetKey {
                resource,
                scope: AccountingScope::Execution,
            })
            .collect(),
            Self::NoNetworkAuthority
            | Self::NoExternalCredentialDelivery
            | Self::NoVolumeWrite
            | Self::NoDeviceUse => Vec::new(),
        }
    }

    /// Judges the resolved contract: every violating tuple, or every missing budget.
    pub fn evaluate(self, permitted: &PermissionSet, budgets: &BudgetSet) -> PredicateOutcome {
        let tuples: Vec<_> = permitted
            .iter()
            .filter(|tuple| self.forbids(&tuple.operation))
            .collect();
        if !tuples.is_empty() {
            return PredicateOutcome::ContractViolated { tuples };
        }
        let keys: Vec<BudgetKey> = self
            .required_budgets()
            .into_iter()
            .filter(|key| budgets.limit(key).is_none())
            .collect();
        if !keys.is_empty() {
            return PredicateOutcome::ContractBudgetMissing { keys };
        }
        PredicateOutcome::ContractHolds
    }
}

impl SecurityPredicate {
    pub const ALL: [Self; 17] = [
        Self::VmSandbox,
        Self::HardwareHypervisorAvailable,
        Self::HardwareAcceleratedBoot,
        Self::DedicatedPhysicalHost,
        Self::InnerGuestConfinement,
        Self::HypervisorConfined,
        Self::NoDirectGuestNetwork,
        Self::IndependentPerimeter,
        Self::ContractOffline,
        Self::ContractNoExternalCredentials,
        Self::ContractEphemeralState,
        Self::ContractBoundedLifetime,
        Self::ContractCpuOnly,
        Self::AssignedGpuIsolated,
        Self::VerifiedConfidentialVm,
        Self::BoundaryProbesPassed,
        Self::InternalCanaries,
    ];

    /// The stable name, as written in requests and canonical encodings.
    pub const fn name(self) -> &'static str {
        match self {
            Self::VmSandbox => "vm_sandbox",
            Self::HardwareHypervisorAvailable => "hardware_hypervisor_available",
            Self::HardwareAcceleratedBoot => "hardware_accelerated_boot",
            Self::DedicatedPhysicalHost => "dedicated_physical_host",
            Self::InnerGuestConfinement => "inner_guest_confinement",
            Self::HypervisorConfined => "hypervisor_confined",
            Self::NoDirectGuestNetwork => "no_direct_guest_network",
            Self::IndependentPerimeter => "independent_perimeter",
            Self::ContractOffline => "contract_offline",
            Self::ContractNoExternalCredentials => "contract_no_external_credentials",
            Self::ContractEphemeralState => "contract_ephemeral_state",
            Self::ContractBoundedLifetime => "contract_bounded_lifetime",
            Self::ContractCpuOnly => "contract_cpu_only",
            Self::AssignedGpuIsolated => "assigned_gpu_isolated",
            Self::VerifiedConfidentialVm => "verified_confidential_vm",
            Self::BoundaryProbesPassed => "boundary_probes_passed",
            Self::InternalCanaries => "internal_canaries",
        }
    }

    /// The predicate with this exact name; `None` for an unknown one, which a request
    /// must never list (VM-P47: unknown required capabilities fail).
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|predicate| predicate.name() == name)
    }

    pub const fn facet(self) -> DeploymentFacet {
        match self {
            Self::VmSandbox
            | Self::HardwareHypervisorAvailable
            | Self::HardwareAcceleratedBoot
            | Self::DedicatedPhysicalHost
            | Self::InnerGuestConfinement => DeploymentFacet::Isolation,
            Self::HypervisorConfined => DeploymentFacet::HypervisorConfinement,
            Self::NoDirectGuestNetwork | Self::IndependentPerimeter | Self::ContractOffline => {
                DeploymentFacet::NetworkAuthority
            }
            Self::ContractNoExternalCredentials => DeploymentFacet::CredentialExposure,
            Self::ContractEphemeralState | Self::ContractBoundedLifetime => {
                DeploymentFacet::Persistence
            }
            Self::ContractCpuOnly | Self::AssignedGpuIsolated => DeploymentFacet::DeviceExposure,
            Self::VerifiedConfidentialVm => DeploymentFacet::OperatorConfidentiality,
            Self::BoundaryProbesPassed | Self::InternalCanaries => DeploymentFacet::Evidence,
        }
    }

    pub const fn check(self) -> PredicateCheck {
        use EvidenceBinding::NoCapabilityYet;
        match self {
            Self::VmSandbox => PredicateCheck::HostEvidence(EvidenceBinding::VmSandboxCategory),
            Self::HardwareHypervisorAvailable => {
                PredicateCheck::HostEvidence(EvidenceBinding::HypervisorAvailable)
            }
            Self::HardwareAcceleratedBoot => PredicateCheck::HostEvidence(NoCapabilityYet {
                needed: "the accelerator the backend actually started this VM with",
            }),
            Self::DedicatedPhysicalHost => PredicateCheck::HostEvidence(NoCapabilityYet {
                needed: "the provider's or host's statement that the physical host is dedicated",
            }),
            Self::InnerGuestConfinement => PredicateCheck::HostEvidence(NoCapabilityYet {
                needed: "the inner confinement profile in force in the guest",
            }),
            Self::HypervisorConfined => PredicateCheck::HostEvidence(NoCapabilityYet {
                needed: "the hypervisor process identity, filesystem, syscall and resource \
                         limits observed by the host",
            }),
            Self::NoDirectGuestNetwork => PredicateCheck::HostEvidence(NoCapabilityYet {
                needed: "the VM's device inventory showing no guest network device",
            }),
            Self::IndependentPerimeter => {
                PredicateCheck::HostEvidence(EvidenceBinding::PerimeterRulesEnforced)
            }
            Self::AssignedGpuIsolated => PredicateCheck::HostEvidence(NoCapabilityYet {
                needed: "IOMMU group, reset and detach evidence for the assigned GPU",
            }),
            Self::VerifiedConfidentialVm => PredicateCheck::HostEvidence(NoCapabilityYet {
                needed: "an attestation report verified under an attestation policy",
            }),
            Self::BoundaryProbesPassed => PredicateCheck::HostEvidence(NoCapabilityYet {
                needed: "host-corroborated boundary probe results",
            }),
            Self::InternalCanaries => PredicateCheck::HostEvidence(NoCapabilityYet {
                needed: "the canaries registered for this generation",
            }),
            Self::ContractOffline => {
                PredicateCheck::Contract(ContractConstraint::NoNetworkAuthority)
            }
            Self::ContractNoExternalCredentials => {
                PredicateCheck::Contract(ContractConstraint::NoExternalCredentialDelivery)
            }
            Self::ContractEphemeralState => {
                PredicateCheck::Contract(ContractConstraint::NoVolumeWrite)
            }
            Self::ContractBoundedLifetime => {
                PredicateCheck::Contract(ContractConstraint::LifetimeBounded)
            }
            Self::ContractCpuOnly => PredicateCheck::Contract(ContractConstraint::NoDeviceUse),
        }
    }

    /// The contract constraint, for a contract predicate.
    pub const fn contract_constraint(self) -> Option<ContractConstraint> {
        match self.check() {
            PredicateCheck::Contract(constraint) => Some(constraint),
            PredicateCheck::HostEvidence(_) => None,
        }
    }
}

impl fmt::Display for SecurityPredicate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::VmSandbox => "a VM sandbox with its own guest kernel",
            Self::HardwareHypervisorAvailable => "a usable hardware hypervisor on the host",
            Self::HardwareAcceleratedBoot => "a hardware-accelerated boot, never emulation",
            Self::DedicatedPhysicalHost => "a dedicated physical host",
            Self::InnerGuestConfinement => "inner confinement in the guest",
            Self::HypervisorConfined => "a confined hypervisor process",
            Self::NoDirectGuestNetwork => "no guest network device",
            Self::IndependentPerimeter => "an independent host perimeter",
            Self::ContractOffline => "a contract without network authority",
            Self::ContractNoExternalCredentials => {
                "a contract that delivers no external credential to the guest"
            }
            Self::ContractEphemeralState => "a contract without persistent volume writes",
            Self::ContractBoundedLifetime => "a contract with idle and absolute lifetime budgets",
            Self::ContractCpuOnly => "a contract without devices",
            Self::AssignedGpuIsolated => "an assigned GPU with isolation evidence",
            Self::VerifiedConfidentialVm => "a verified confidential VM",
            Self::BoundaryProbesPassed => "host-corroborated boundary probes",
            Self::InternalCanaries => "internal canaries",
        })
    }
}

/// Required properties, accumulated by union (VM §2.4 line 1796).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RequirementSet {
    predicates: BTreeSet<SecurityPredicate>,
}

impl RequirementSet {
    pub fn new(predicates: impl IntoIterator<Item = SecurityPredicate>) -> Self {
        Self {
            predicates: predicates.into_iter().collect(),
        }
    }

    /// Every predicate of both sets.
    pub fn union(&self, other: &Self) -> Self {
        Self {
            predicates: self.predicates.union(&other.predicates).copied().collect(),
        }
    }

    pub fn contains(&self, predicate: SecurityPredicate) -> bool {
        self.predicates.contains(&predicate)
    }

    pub fn is_subset(&self, other: &Self) -> bool {
        self.predicates.is_subset(&other.predicates)
    }

    pub fn iter(&self) -> impl Iterator<Item = SecurityPredicate> + '_ {
        self.predicates.iter().copied()
    }

    pub fn len(&self) -> usize {
        self.predicates.len()
    }

    pub fn is_empty(&self) -> bool {
        self.predicates.is_empty()
    }
}

impl FromIterator<SecurityPredicate> for RequirementSet {
    fn from_iter<I: IntoIterator<Item = SecurityPredicate>>(predicates: I) -> Self {
        Self::new(predicates)
    }
}

/// An isolation tier from an old manifest (the former T1–T4 score; VM §1.3).
///
/// It has no order on purpose: tiers are migrated to explicit predicate sets, never
/// compared, and never converted downward to a weaker runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LegacyTier {
    /// Shared kernel inside a VM (the old appliance or WSL2 containers).
    T1,
    /// Own VM, hardware accelerated, gate, no NIC, zero secrets, timers.
    T2,
    /// T2 plus jailed hypervisor, second perimeter, inner confinement, probes, canaries.
    T3,
    /// T3 on a dedicated or attested host.
    T4,
}

impl LegacyTier {
    /// Reads the old manifest value `T1`–`T4` exactly.
    pub fn parse(name: &str) -> Result<Self, MigrationRefusal> {
        match name {
            "T1" => Ok(Self::T1),
            "T2" => Ok(Self::T2),
            "T3" => Ok(Self::T3),
            "T4" => Ok(Self::T4),
            _ => Err(MigrationRefusal::Unknown {
                name: name.to_owned(),
            }),
        }
    }

    /// The documented migration (VM-W01; §1.3: an old tier maps to an explicit
    /// requirement set or yields a migration error, with no downward conversion).
    ///
    /// - T1 was a shared kernel, which no production sandbox may be: refused.
    /// - T2 becomes: VM sandbox, hardware hypervisor available, hardware-accelerated
    ///   boot, no direct guest network (the gate and "no NIC"), no external credentials
    ///   in the contract ("zero secrets") and bounded lifetime ("timers").
    /// - T3 becomes T2 plus a confined hypervisor, an independent perimeter, inner guest
    ///   confinement, boundary probes and internal canaries.
    /// - T4 meant "dedicated or attested", two properties that do not imply each other
    ///   (§1.3), so it is refused until the manifest names the one it needs.
    pub fn migrate(self) -> Result<RequirementSet, MigrationRefusal> {
        use SecurityPredicate as P;
        let t2 = [
            P::VmSandbox,
            P::HardwareHypervisorAvailable,
            P::HardwareAcceleratedBoot,
            P::NoDirectGuestNetwork,
            P::ContractNoExternalCredentials,
            P::ContractBoundedLifetime,
        ];
        let t3_extra = [
            P::HypervisorConfined,
            P::IndependentPerimeter,
            P::InnerGuestConfinement,
            P::BoundaryProbesPassed,
            P::InternalCanaries,
        ];
        match self {
            Self::T1 => Err(MigrationRefusal::SharedKernel),
            Self::T2 => Ok(RequirementSet::new(t2)),
            Self::T3 => Ok(RequirementSet::new(t2.into_iter().chain(t3_extra))),
            Self::T4 => Err(MigrationRefusal::AmbiguousOperator),
        }
    }
}

strict_policy_enum! {
    /// Why an old tier could not be migrated (VM-W01).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum MigrationRefusal tag "refusal" {
        /// Not one of T1–T4.
        Unknown { name: String },
        /// T1 was a shared kernel; there is no shared-kernel production sandbox option.
        SharedKernel,
        /// T4 meant a dedicated or an attested host; the manifest must name which.
        AmbiguousOperator,
    }
}

impl fmt::Display for MigrationRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown { name } => write!(
                f,
                "isolation tier {name:?} is unknown; old manifests use T1, T2, T3 or T4"
            ),
            Self::SharedKernel => f.write_str(
                "tier T1 was a shared kernel, and no sandbox runs on a shared kernel; require \
                 a VM sandbox, or choose a labelled non-sandbox runtime as a separate request",
            ),
            Self::AmbiguousOperator => f.write_str(
                "tier T4 meant a dedicated or an attested host, which are different \
                 properties; require dedicated_physical_host or verified_confidential_vm \
                 explicitly",
            ),
        }
    }
}

impl std::error::Error for MigrationRefusal {}
