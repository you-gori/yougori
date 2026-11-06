//! Remote offering records and their selection (VM part §7.6 lines 2242–2247; VM-D5;
//! VM-P42; §1.3 "no automatic downward conversion to a weaker runtime").
//!
//! An offering is a provider, a region, the provider's offering name and its kind. Only
//! a dedicated provider VM or a host that launches the required per-sandbox VM qualifies
//! as a VM sandbox (§7.6). A provider container never does: it is never represented as a
//! VM backend, and VM-D5 ("(c) with (b); never silently") keeps it only as the labelled
//! "remote runtime (provider container), not a sandbox", chosen by an explicit request
//! and with every credential held at home. The category decision is CORE-01's
//! [`RuntimeRequirement`]; this module only maps an offering kind to the category it
//! would be and keeps the refusal CORE-01 gives.
//!
//! The kind here is the provider catalog's claim. It plans; it proves nothing. The
//! adapter later admits the provisioned runtime only on CORE-01 category evidence.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::foundation::evidence::{CategoryRefusal, ProviderKind, RuntimeRequirement};
use crate::foundation::ids::{Digest, DigestBuilder, ExecutionCategory};
use crate::sandbox_contract::effects::AccountRef;

remote_name!(
    /// A provider region, such as `us-east-1`.
    RegionName
);
remote_name!(
    /// The provider's name for one offering, such as an instance type.
    OfferingName
);

/// What a remote offering is (§7.6; VM-D5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfferingKind {
    /// A dedicated provider VM: the VM itself is the sandbox, on the provider's
    /// hypervisor.
    DedicatedVm,
    /// A bare-metal host. It qualifies only by launching the per-sandbox VM; a workload
    /// run on the bare host is a host shell, not a sandbox.
    BareMetal,
    /// A host, such as a VM with nested virtualization, that launches the per-sandbox VM.
    PerSandboxVmHost,
    /// A provider container such as a RunPod pod: never a VM backend (VM-D5).
    ProviderContainer,
}

/// How a VM sandbox is realised on an offering.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmPath {
    /// The provider VM is the sandbox.
    ProviderVm,
    /// A per-sandbox VM launched on the remote host; the host shell is not the sandbox.
    PerSandboxVm,
}

impl OfferingKind {
    pub const ALL: [Self; 4] = [
        Self::DedicatedVm,
        Self::BareMetal,
        Self::PerSandboxVmHost,
        Self::ProviderContainer,
    ];

    /// The execution category a runtime on this offering would be (VM-D5).
    pub const fn category(self) -> ExecutionCategory {
        match self {
            Self::DedicatedVm | Self::BareMetal | Self::PerSandboxVmHost => {
                ExecutionCategory::VmSandbox
            }
            Self::ProviderContainer => ExecutionCategory::ProviderContainerRuntime,
        }
    }

    /// How a VM sandbox is realised here; `None` for a provider container (§7.6).
    pub const fn vm_path(self) -> Option<VmPath> {
        match self {
            Self::DedicatedVm => Some(VmPath::ProviderVm),
            Self::BareMetal | Self::PerSandboxVmHost => Some(VmPath::PerSandboxVm),
            Self::ProviderContainer => None,
        }
    }

    /// The tag written into records and digests.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::DedicatedVm => "dedicated_vm",
            Self::BareMetal => "bare_metal",
            Self::PerSandboxVmHost => "per_sandbox_vm_host",
            Self::ProviderContainer => "provider_container",
        }
    }
}

impl fmt::Display for OfferingKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::DedicatedVm => "dedicated provider VM",
            Self::BareMetal => "bare-metal host",
            Self::PerSandboxVmHost => "host that launches per-sandbox VMs",
            Self::ProviderContainer => "provider container",
        })
    }
}

/// Why a price was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PriceProblem {
    /// A billing increment of zero seconds cannot round anything.
    ZeroBillingIncrement,
    /// The cost does not fit in 64 bits of microunits.
    Overflow,
}

impl fmt::Display for PriceProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ZeroBillingIncrement => "the billing increment must be at least one second",
            Self::Overflow => "the cost does not fit in 64 bits of microunits",
        })
    }
}

impl std::error::Error for PriceProblem {}

/// What the provider charges, in millionths of the account's currency unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfferingPrice {
    pub per_hour_microunits: u64,
    /// Billed time is rounded up to whole increments.
    pub billing_increment_seconds: u64,
    /// The least time billed once anything runs.
    pub minimum_billed_seconds: u64,
}

impl OfferingPrice {
    /// Refuses a zero billing increment.
    pub fn check(&self) -> Result<(), PriceProblem> {
        if self.billing_increment_seconds == 0 {
            return Err(PriceProblem::ZeroBillingIncrement);
        }
        Ok(())
    }

    /// The most `runtime_seconds` of use can cost, rounded against the user:
    ///
    /// ```text
    /// billed_seconds = max(minimum_billed_seconds,
    ///                      ceil(runtime_seconds / increment) × increment)
    /// cost           = ceil(per_hour_microunits × billed_seconds / 3600)
    /// ```
    pub fn max_cost_microunits(&self, runtime_seconds: u64) -> Result<u64, PriceProblem> {
        self.check()?;
        let increment = u128::from(self.billing_increment_seconds);
        let increments = u128::from(runtime_seconds).div_ceil(increment);
        let rounded = increments
            .checked_mul(increment)
            .ok_or(PriceProblem::Overflow)?;
        let billed = rounded.max(u128::from(self.minimum_billed_seconds));
        let cost = u128::from(self.per_hour_microunits)
            .checked_mul(billed)
            .ok_or(PriceProblem::Overflow)?
            .div_ceil(3_600);
        u64::try_from(cost).map_err(|_| PriceProblem::Overflow)
    }
}

/// The resources one instance of an offering provides, as the catalog states them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfferingShape {
    pub vcpus: u32,
    pub memory_bytes: u64,
    pub gpus: u32,
}

/// One remote offering (§7.6; VM-D5).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteOffering {
    pub provider: ProviderKind,
    pub region: RegionName,
    pub offering: OfferingName,
    pub kind: OfferingKind,
    /// The provider account that pays, or the owner's attached-host identity.
    /// Credentials stay at home; an attached host's billing is externally managed.
    pub account: AccountRef,
    /// Missing only for an existing SSH host; never interpreted as free.
    pub price: Option<OfferingPrice>,
    pub shape: OfferingShape,
}

impl RemoteOffering {
    /// Domain of [`RemoteOffering::identity`].
    pub const IDENTITY_DOMAIN: &'static str = "yougori/remote/offering/v1";

    /// The offering's identity: provider, region, offering name, kind and account.
    pub fn identity(&self) -> Digest {
        DigestBuilder::new(Self::IDENTITY_DOMAIN)
            .str(self.provider.tag())
            .str(self.region.as_str())
            .str(self.offering.as_str())
            .str(self.kind.tag())
            .digest(self.account.digest())
            .finish()
    }
}

/// Where the provider account's and other private credentials are held (§7.6 line
/// 2246: an authorized home or off-host executor; VM-D5 (b): all credentials at home).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialPlacement {
    /// The home host's vault and executors.
    Home,
    /// An authorized executor off the remote host.
    OffHostExecutor,
    /// Delivered onto the remote host or into the remote runtime.
    Remote,
}

/// What a remote run asks for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteRequest {
    /// CORE-01's category requirement: a VM sandbox, or labelled runtimes named
    /// explicitly (INT-07).
    pub requirement: RuntimeRequirement,
    pub credentials: CredentialPlacement,
    /// GPUs the run needs; an offering with fewer is refused, never replaced by one of
    /// another kind (VM-P42).
    pub gpus: u32,
}

strict_remote_enum! {
    /// Why one offering was not selected.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum OfferingRefusalReason tag "reason" {
        /// CORE-01 refuses the category the offering would be, with its label and
        /// recorded decision (VM-D4–VM-D6).
        Category { refusal: CategoryRefusal },
        /// The category is missing from CORE-01's matrix row; nothing is assumed.
        CategoryNotInMatrix { category: ExecutionCategory },
        /// Private credentials would leave the home host or an authorized off-host
        /// executor (§7.6).
        CredentialsLeaveHome { placement: CredentialPlacement },
        /// A provider container runs only with every credential held at home (VM-D5 (b)).
        ContainerCredentialsNotHome { placement: CredentialPlacement },
        /// The offering has fewer GPUs than the run needs (VM-P42).
        InsufficientGpus { required: u32, offered: u32 },
        InvalidPrice { problem: PriceProblem },
        /// Managed offerings need a price; attached SSH hosts have no managed
        /// billing and must launch a separate VM rather than use their host shell.
        InvalidBillingOwnership,
    }
}

impl fmt::Display for OfferingRefusalReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Category { refusal } => write!(f, "{refusal}"),
            Self::CategoryNotInMatrix { category } => write!(
                f,
                "\"{}\" has no entry in the requirement's category matrix",
                category.label()
            ),
            Self::CredentialsLeaveHome { .. } => f.write_str(
                "private credentials stay with the home host or an authorized off-host executor",
            ),
            Self::ContainerCredentialsNotHome { .. } => f.write_str(
                "a remote runtime (provider container) runs only with every credential held at \
                 home (VM-D5)",
            ),
            Self::InsufficientGpus { required, offered } => write!(
                f,
                "the run needs {required} GPU(s) and the offering has {offered}"
            ),
            Self::InvalidPrice { problem } => write!(f, "{problem}"),
            Self::InvalidBillingOwnership => f.write_str(
                "the offering's billing ownership or attached-host isolation is invalid",
            ),
        }
    }
}

/// One offering that was refused, by its identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfferingRefusal {
    pub offering: Digest,
    pub kind: OfferingKind,
    pub reason: OfferingRefusalReason,
}

/// No offering was admissible: every refusal, in offering order. Nothing was provisioned
/// or started (VM-P42: no native, emulated or container start in its place).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteSelectionRefusal {
    /// Empty when nothing was offered.
    pub refusals: Vec<OfferingRefusal>,
}

impl fmt::Display for RemoteSelectionRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.refusals.is_empty() {
            return f.write_str("no remote offering was available; nothing was started");
        }
        f.write_str("no remote offering qualifies; nothing was started: ")?;
        for (index, refusal) in self.refusals.iter().enumerate() {
            if index > 0 {
                f.write_str("; ")?;
            }
            write!(
                f,
                "{} ({}): {}",
                refusal.kind, refusal.offering, refusal.reason
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for RemoteSelectionRefusal {}

/// The offering a request selected, with the category it runs as and every offering
/// passed over before it, so nothing is chosen silently. Only [`select_remote`] makes
/// one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RemoteSelection {
    offering: RemoteOffering,
    requirement: RuntimeRequirement,
    credentials: CredentialPlacement,
    passed_over: Vec<OfferingRefusal>,
}

impl RemoteSelection {
    pub fn offering(&self) -> &RemoteOffering {
        &self.offering
    }

    pub fn requirement(&self) -> &RuntimeRequirement {
        &self.requirement
    }

    pub fn credentials(&self) -> CredentialPlacement {
        self.credentials
    }

    /// The category the selected offering runs as.
    pub fn category(&self) -> ExecutionCategory {
        self.offering.kind.category()
    }

    pub fn is_vm_sandbox(&self) -> bool {
        self.category().is_vm_sandbox()
    }

    /// The recorded user-facing label: "VM sandbox", or for a provider container
    /// "remote runtime (provider container), not a sandbox".
    pub fn label(&self) -> &'static str {
        self.category().label()
    }

    /// The decision keeping a labelled runtime, `Some("VM-D5")` for a provider container.
    pub fn decision(&self) -> Option<&'static str> {
        self.category().decision()
    }

    pub fn vm_path(&self) -> Option<VmPath> {
        self.offering.kind.vm_path()
    }

    /// Offerings refused before this one, in order.
    pub fn passed_over(&self) -> &[OfferingRefusal] {
        &self.passed_over
    }
}

/// Selects the first admissible offering in the caller's order of preference
/// (§7.6; VM-D5; VM-P42). Each offering is judged by CORE-01's category matrix for the
/// request, by its price and by where credentials would be held. When none qualifies,
/// every refusal is returned and nothing is selected, so nothing is provisioned.
pub fn select_remote(
    request: &RemoteRequest,
    offerings: &[RemoteOffering],
) -> Result<RemoteSelection, RemoteSelectionRefusal> {
    let matrix = request.requirement.matrix();
    let mut refusals = Vec::new();
    for offering in offerings {
        match judge(request, &matrix, offering) {
            Ok(()) => {
                return Ok(RemoteSelection {
                    offering: offering.clone(),
                    requirement: request.requirement.clone(),
                    credentials: request.credentials,
                    passed_over: refusals,
                })
            }
            Err(reason) => refusals.push(OfferingRefusal {
                offering: offering.identity(),
                kind: offering.kind,
                reason,
            }),
        }
    }
    Err(RemoteSelectionRefusal { refusals })
}

fn judge(
    request: &RemoteRequest,
    matrix: &[(ExecutionCategory, Result<(), CategoryRefusal>)],
    offering: &RemoteOffering,
) -> Result<(), OfferingRefusalReason> {
    let category = offering.kind.category();
    match matrix.iter().find(|(entry, _)| *entry == category) {
        Some((_, Ok(()))) => {}
        Some((_, Err(refusal))) => {
            return Err(OfferingRefusalReason::Category {
                refusal: refusal.clone(),
            })
        }
        None => return Err(OfferingRefusalReason::CategoryNotInMatrix { category }),
    }
    if offering.shape.gpus < request.gpus {
        return Err(OfferingRefusalReason::InsufficientGpus {
            required: request.gpus,
            offered: offering.shape.gpus,
        });
    }
    if offering.kind == OfferingKind::ProviderContainer
        && request.credentials != CredentialPlacement::Home
    {
        return Err(OfferingRefusalReason::ContainerCredentialsNotHome {
            placement: request.credentials,
        });
    }
    if request.credentials == CredentialPlacement::Remote {
        return Err(OfferingRefusalReason::CredentialsLeaveHome {
            placement: request.credentials,
        });
    }
    match (offering.provider, offering.kind, offering.price) {
        (ProviderKind::ExistingSsh, OfferingKind::PerSandboxVmHost, None) => Ok(()),
        (ProviderKind::ExistingSsh, _, _) | (_, _, None) => {
            Err(OfferingRefusalReason::InvalidBillingOwnership)
        }
        (_, _, Some(price)) => price
            .check()
            .map_err(|problem| OfferingRefusalReason::InvalidPrice { problem }),
    }
}

/// The kinds that can satisfy a VM-sandbox requirement (§7.6).
pub fn vm_kinds() -> BTreeSet<OfferingKind> {
    OfferingKind::ALL
        .into_iter()
        .filter(|kind| kind.vm_path().is_some())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox_contract::remote::fakes::{
        container_offering, dedicated_offering, explicit_container, metal_offering, vm_request,
    };

    #[test]
    fn only_vm_kinds_have_a_vm_path_and_a_container_is_never_a_vm_backend() {
        assert_eq!(
            vm_kinds(),
            BTreeSet::from([
                OfferingKind::DedicatedVm,
                OfferingKind::BareMetal,
                OfferingKind::PerSandboxVmHost
            ])
        );
        for kind in OfferingKind::ALL {
            assert_eq!(kind.vm_path().is_some(), kind.category().is_vm_sandbox());
        }
        assert_eq!(OfferingKind::ProviderContainer.vm_path(), None);
        assert_eq!(
            OfferingKind::ProviderContainer.category(),
            ExecutionCategory::ProviderContainerRuntime
        );
        assert_eq!(
            OfferingKind::DedicatedVm.vm_path(),
            Some(VmPath::ProviderVm)
        );
        assert_eq!(
            OfferingKind::BareMetal.vm_path(),
            Some(VmPath::PerSandboxVm)
        );
        // The VM-D4 and VM-D6 labelled runtimes are local; no remote offering is one.
        for kind in OfferingKind::ALL {
            assert!(matches!(
                kind.category(),
                ExecutionCategory::VmSandbox | ExecutionCategory::ProviderContainerRuntime
            ));
        }
    }

    #[test]
    fn a_missing_gpu_path_never_selects_a_provider_container_instead() {
        let mut cpu_only = dedicated_offering();
        cpu_only.shape.gpus = 0;
        let refusal =
            select_remote(&vm_request(), &[cpu_only.clone(), container_offering()]).unwrap_err();
        assert_eq!(
            refusal.refusals[0].reason,
            OfferingRefusalReason::InsufficientGpus {
                required: 1,
                offered: 0
            }
        );
        assert!(matches!(
            refusal.refusals[1].reason,
            OfferingRefusalReason::Category {
                refusal: CategoryRefusal::VmSandboxRequired { .. }
            }
        ));
        let cpu_request = RemoteRequest {
            gpus: 0,
            ..vm_request()
        };
        assert_eq!(
            select_remote(&cpu_request, &[cpu_only])
                .unwrap()
                .offering()
                .shape
                .gpus,
            0
        );
    }

    #[test]
    fn a_vm_request_refuses_a_provider_container_with_its_label_and_decision() {
        let refusal = select_remote(&vm_request(), &[container_offering()]).unwrap_err();
        assert_eq!(refusal.refusals.len(), 1);
        let OfferingRefusalReason::Category { refusal: category } = &refusal.refusals[0].reason
        else {
            panic!("{refusal:?}");
        };
        assert_eq!(
            category,
            &CategoryRefusal::VmSandboxRequired {
                offered: ExecutionCategory::ProviderContainerRuntime
            }
        );
        assert_eq!(
            category.label(),
            "remote runtime (provider container), not a sandbox"
        );
        assert_eq!(category.decision(), Some("VM-D5"));
        assert!(refusal.to_string().contains("nothing was started"));
    }

    #[test]
    fn with_no_vm_path_a_vm_request_selects_nothing() {
        let refusal = select_remote(&vm_request(), &[]).unwrap_err();
        assert!(refusal.refusals.is_empty());
        let refusal = select_remote(&vm_request(), &[container_offering(), container_offering()])
            .unwrap_err();
        assert_eq!(refusal.refusals.len(), 2);
    }

    #[test]
    fn a_vm_request_selects_the_first_vm_offering_and_reports_what_it_passed_over() {
        let selection = select_remote(
            &vm_request(),
            &[container_offering(), metal_offering(), dedicated_offering()],
        )
        .unwrap();
        assert_eq!(selection.offering().kind, OfferingKind::BareMetal);
        assert!(selection.is_vm_sandbox());
        assert_eq!(selection.label(), "VM sandbox");
        assert_eq!(selection.decision(), None);
        assert_eq!(selection.vm_path(), Some(VmPath::PerSandboxVm));
        assert_eq!(selection.passed_over().len(), 1);
        assert_eq!(
            selection.passed_over()[0].kind,
            OfferingKind::ProviderContainer
        );
    }

    #[test]
    fn a_provider_container_runs_only_on_explicit_request_labelled_not_a_sandbox() {
        let selection = select_remote(&explicit_container(), &[container_offering()]).unwrap();
        assert!(!selection.is_vm_sandbox());
        assert_eq!(
            selection.label(),
            "remote runtime (provider container), not a sandbox"
        );
        assert_eq!(selection.decision(), Some("VM-D5"));
        assert_eq!(selection.vm_path(), None);
        // An explicit container request never gets a VM it did not list, either.
        let refusal = select_remote(&explicit_container(), &[dedicated_offering()]).unwrap_err();
        assert!(matches!(
            refusal.refusals[0].reason,
            OfferingRefusalReason::Category {
                refusal: CategoryRefusal::NotExplicitlyAllowed { .. }
            }
        ));
    }

    #[test]
    fn a_provider_container_needs_every_credential_at_home() {
        for placement in [
            CredentialPlacement::OffHostExecutor,
            CredentialPlacement::Remote,
        ] {
            let request = RemoteRequest {
                credentials: placement,
                ..explicit_container()
            };
            let refusal = select_remote(&request, &[container_offering()]).unwrap_err();
            assert_eq!(
                refusal.refusals[0].reason,
                OfferingRefusalReason::ContainerCredentialsNotHome { placement }
            );
        }
    }

    #[test]
    fn private_credentials_never_go_to_a_remote_vm_either() {
        let request = RemoteRequest {
            credentials: CredentialPlacement::Remote,
            ..vm_request()
        };
        let refusal = select_remote(&request, &[dedicated_offering()]).unwrap_err();
        assert_eq!(
            refusal.refusals[0].reason,
            OfferingRefusalReason::CredentialsLeaveHome {
                placement: CredentialPlacement::Remote
            }
        );
        let request = RemoteRequest {
            credentials: CredentialPlacement::OffHostExecutor,
            ..vm_request()
        };
        assert!(select_remote(&request, &[dedicated_offering()]).is_ok());
    }

    #[test]
    fn an_offering_with_an_invalid_price_is_refused() {
        let mut offering = dedicated_offering();
        offering.price.as_mut().unwrap().billing_increment_seconds = 0;
        let refusal = select_remote(&vm_request(), &[offering]).unwrap_err();
        assert_eq!(
            refusal.refusals[0].reason,
            OfferingRefusalReason::InvalidPrice {
                problem: PriceProblem::ZeroBillingIncrement
            }
        );
    }

    #[test]
    fn existing_ssh_requires_explicit_vm_host_ownership_and_no_managed_price() {
        let mut attached = dedicated_offering();
        attached.provider = ProviderKind::ExistingSsh;
        attached.kind = OfferingKind::PerSandboxVmHost;
        let priced = attached.clone();
        attached.price = None;
        assert!(select_remote(&vm_request(), &[attached.clone()]).is_ok());
        for candidate in [
            priced,
            RemoteOffering {
                kind: OfferingKind::DedicatedVm,
                ..attached.clone()
            },
            RemoteOffering {
                provider: ProviderKind::RunPod,
                ..attached
            },
        ] {
            assert!(matches!(
                select_remote(&vm_request(), &[candidate])
                    .unwrap_err()
                    .refusals[0]
                    .reason,
                OfferingRefusalReason::InvalidBillingOwnership
            ));
        }
        // Previously serialized managed offerings keep their object-valued price.
        let old = serde_json::to_value(dedicated_offering()).unwrap();
        assert!(old["price"].is_object());
        assert_eq!(
            serde_json::from_value::<RemoteOffering>(old).unwrap(),
            dedicated_offering()
        );
    }

    #[test]
    fn the_conservative_cost_rounds_against_the_user() {
        let price = OfferingPrice {
            per_hour_microunits: 2_000_000,
            billing_increment_seconds: 60,
            minimum_billed_seconds: 600,
        };
        // 100 minutes: 6,000 s × 2,000,000 µ / 3,600 s = 3,333,333.3 µ, rounded up.
        assert_eq!(price.max_cost_microunits(6_000), Ok(3_333_334));
        // 61 s rounds up to two increments, then to the 600 s minimum.
        assert_eq!(price.max_cost_microunits(61), Ok(333_334));
        // 6,001 s rounds up to 6,060 s.
        assert_eq!(price.max_cost_microunits(6_001), Ok(3_366_667));
        assert_eq!(price.max_cost_microunits(0), Ok(333_334));
        let huge = OfferingPrice {
            per_hour_microunits: u64::MAX,
            ..price
        };
        assert_eq!(
            huge.max_cost_microunits(u64::MAX),
            Err(PriceProblem::Overflow)
        );
        let broken = OfferingPrice {
            billing_increment_seconds: 0,
            ..price
        };
        assert_eq!(
            broken.max_cost_microunits(1),
            Err(PriceProblem::ZeroBillingIncrement)
        );
    }

    #[test]
    fn offering_records_are_read_strictly() {
        let offering = dedicated_offering();
        let mut value = serde_json::to_value(&offering).unwrap();
        assert_eq!(
            serde_json::from_value::<RemoteOffering>(value.clone()).unwrap(),
            offering
        );
        value["fallback_region"] = serde_json::json!("eu-west-1");
        assert!(serde_json::from_value::<RemoteOffering>(value).is_err());
        let reason = OfferingRefusalReason::CategoryNotInMatrix {
            category: ExecutionCategory::VmSandbox,
        };
        let mut value = serde_json::to_value(&reason).unwrap();
        value["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<OfferingRefusalReason>(value).is_err());
    }

    #[test]
    fn identity_changes_with_every_field() {
        let base = dedicated_offering();
        let mut other_region = base.clone();
        other_region.region = RegionName::new("eu-west-1").unwrap();
        let mut other_kind = base.clone();
        other_kind.kind = OfferingKind::ProviderContainer;
        let mut other_provider = base.clone();
        other_provider.provider = ProviderKind::RunPod;
        assert_ne!(base.identity(), other_region.identity());
        assert_ne!(base.identity(), other_kind.identity());
        assert_ne!(base.identity(), other_provider.identity());
    }
}
