//! The exact runtime-category matrix (S5 G0; S1; INT-07; VM part §1.3; VM-D4–VM-D6).
//!
//! A runtime is admitted only as a [`RuntimeOffer`]: the runtime plus current evidence,
//! from the host or the provider API, that it really is the category it is offered as.
//! A caller's label alone admits nothing.

use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::envelope::{Capability, ConfigurationFingerprint, SupportDetail, UnknownReason};
use super::registry::ProbeRegistry;
use super::remedy::Remedy;
use super::requirement::{EvidenceRefusal, Requirement, Satisfied};
use super::subject::{RuntimeSubject, Subject};
use crate::foundation::ids::{Clock, ExecutionCategory};

/// The labelled runtimes an explicit request allows (INT-07).
///
/// It never contains a VM sandbox: [`RuntimeRequirement::VmSandbox`] is the only way to
/// require one, so no request can list a VM beside labelled runtimes and fall back from
/// one to the other (VM part §1.3: no automatic downward conversion to a weaker
/// runtime).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    try_from = "BTreeSet<ExecutionCategory>",
    into = "BTreeSet<ExecutionCategory>"
)]
pub struct LabelledRuntimes(BTreeSet<ExecutionCategory>);

impl LabelledRuntimes {
    /// Refuses a set that lists a VM sandbox.
    pub fn new(
        categories: impl IntoIterator<Item = ExecutionCategory>,
    ) -> Result<Self, RequirementError> {
        let categories: BTreeSet<ExecutionCategory> = categories.into_iter().collect();
        if categories.contains(&ExecutionCategory::VmSandbox) {
            return Err(RequirementError::VmSandboxListed);
        }
        Ok(Self(categories))
    }

    pub fn contains(&self, category: ExecutionCategory) -> bool {
        self.0.contains(&category)
    }

    pub fn iter(&self) -> impl Iterator<Item = ExecutionCategory> + '_ {
        self.0.iter().copied()
    }

    pub fn as_set(&self) -> &BTreeSet<ExecutionCategory> {
        &self.0
    }
}

impl TryFrom<BTreeSet<ExecutionCategory>> for LabelledRuntimes {
    type Error = RequirementError;

    fn try_from(categories: BTreeSet<ExecutionCategory>) -> Result<Self, Self::Error> {
        Self::new(categories)
    }
}

impl From<LabelledRuntimes> for BTreeSet<ExecutionCategory> {
    fn from(runtimes: LabelledRuntimes) -> Self {
        runtimes.0
    }
}

/// Why a runtime requirement could not be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequirementError {
    /// A VM sandbox listed beside labelled runtimes could fall back to them.
    VmSandboxListed,
}

impl fmt::Display for RequirementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VmSandboxListed => f.write_str(
                "a VM sandbox cannot be listed among explicitly allowed runtimes; require a VM \
                 sandbox on its own, so the request never falls back to a labelled runtime",
            ),
        }
    }
}

impl std::error::Error for RequirementError {}

strict_evidence_enum! {
    /// What a request requires of the runtime's execution category (INT-07).
    ///
    /// A VM-required request accepts only a VM sandbox: it can neither select nor
    /// degrade to a labelled runtime (S1). An explicit request names the labelled
    /// runtimes it allows, and nothing else is substituted: the explicit runtime label
    /// and recorded choice are preserved.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum RuntimeRequirement tag "requires" {
        /// Only a VM sandbox, the only way to require one (S1; INT-07).
        VmSandbox,
        /// Exactly these labelled runtimes, each chosen by its recorded label (INT-07).
        Explicit { allowed: LabelledRuntimes },
    }
}

impl RuntimeRequirement {
    /// An explicit requirement; refused when `categories` lists a VM sandbox.
    pub fn explicit(
        categories: impl IntoIterator<Item = ExecutionCategory>,
    ) -> Result<Self, RequirementError> {
        Ok(Self::Explicit {
            allowed: LabelledRuntimes::new(categories)?,
        })
    }

    /// Admits `offer` or refuses it with its label and recorded decision. The offer's
    /// category is the one its evidence confirmed, never only the caller's label.
    pub fn admit(&self, offer: &RuntimeOffer) -> Result<AdmittedRuntime, CategoryRefusal> {
        self.check(offer.category())?;
        Ok(AdmittedRuntime {
            runtime: offer.runtime.clone(),
            evidence: offer.evidence.clone(),
        })
    }

    /// The first admissible offer, in the caller's order of preference. When none is
    /// admissible, every offer's refusal is returned; nothing is silently substituted.
    pub fn select(&self, offers: &[RuntimeOffer]) -> Result<AdmittedRuntime, SelectionRefusal> {
        let mut refusals = Vec::new();
        for offer in offers {
            match self.admit(offer) {
                Ok(admitted) => return Ok(admitted),
                Err(refusal) => refusals.push(refusal),
            }
        }
        Err(SelectionRefusal { refusals })
    }

    /// The whole matrix row for this requirement, one entry per category, for display:
    /// it admits nothing.
    pub fn matrix(&self) -> [(ExecutionCategory, Result<(), CategoryRefusal>); 4] {
        ExecutionCategory::ALL.map(|category| (category, self.check(category)))
    }

    fn check(&self, offered: ExecutionCategory) -> Result<(), CategoryRefusal> {
        match self {
            Self::VmSandbox if offered.is_vm_sandbox() => Ok(()),
            Self::VmSandbox => Err(CategoryRefusal::VmSandboxRequired { offered }),
            Self::Explicit { allowed } if allowed.contains(offered) => Ok(()),
            Self::Explicit { allowed } => Err(CategoryRefusal::NotExplicitlyAllowed {
                offered,
                allowed: allowed.as_set().clone(),
            }),
        }
    }
}

/// A runtime offered for a request, with current evidence that it really is the category
/// it is offered as (INT-07). Only [`RuntimeOffer::observe`] makes one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RuntimeOffer {
    runtime: RuntimeSubject,
    evidence: Satisfied,
}

impl RuntimeOffer {
    /// Offers `runtime` as its category, on the registry's
    /// [`Capability::RuntimeCategory`] evidence for this exact runtime: observed by the
    /// host or the provider API, never a guest report or a declaration, under
    /// `configuration` and no older than `max_age`. A provider container labelled as a VM
    /// sandbox is refused here, because no such evidence exists for it.
    pub fn observe<C: Clock>(
        registry: &ProbeRegistry<C>,
        runtime: RuntimeSubject,
        max_age: Duration,
        configuration: ConfigurationFingerprint,
    ) -> Result<Self, EvidenceRefusal> {
        let capability = Capability::RuntimeCategory;
        let requirement = Requirement::new(
            capability,
            Subject::Runtime(runtime.clone()),
            capability.weakest_source(),
            max_age,
            configuration,
        );
        let evidence = registry.evaluate(&requirement)?;
        let confirmed = SupportDetail::RuntimeCategory {
            category: runtime.category,
        };
        if *evidence.detail() != confirmed {
            return Err(EvidenceRefusal::Unknown {
                capability,
                reason: UnknownReason::InconsistentReport,
            });
        }
        Ok(Self { runtime, evidence })
    }

    pub fn runtime(&self) -> &RuntimeSubject {
        &self.runtime
    }

    /// The category the evidence confirmed.
    pub fn category(&self) -> ExecutionCategory {
        self.runtime.category
    }

    /// The evidence that the runtime is its category.
    pub fn evidence(&self) -> &Satisfied {
        &self.evidence
    }
}

/// A runtime the request admitted. Only [`RuntimeRequirement::admit`] makes one, and it
/// keeps the category's own label: a labelled runtime is never shown as a VM sandbox
/// (CORE-07).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AdmittedRuntime {
    runtime: RuntimeSubject,
    evidence: Satisfied,
}

impl AdmittedRuntime {
    pub fn category(&self) -> ExecutionCategory {
        self.runtime.category
    }

    /// The recorded user-facing label.
    pub fn label(&self) -> &'static str {
        self.category().label()
    }

    /// The recorded decision keeping a labelled runtime; `None` for a VM sandbox.
    pub fn decision(&self) -> Option<&'static str> {
        self.category().decision()
    }

    pub fn is_vm_sandbox(&self) -> bool {
        self.category().is_vm_sandbox()
    }

    /// The exact runtime admitted.
    pub fn runtime(&self) -> &RuntimeSubject {
        &self.runtime
    }

    /// The evidence of its category that admission rested on.
    pub fn evidence(&self) -> &Satisfied {
        &self.evidence
    }
}

strict_evidence_enum! {
    /// Why a category was refused (INT-07). The message names the category's label and,
    /// for a labelled runtime, its recorded decision.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum CategoryRefusal tag "refusal" {
        /// The request requires a VM sandbox and a labelled runtime was offered.
        VmSandboxRequired { offered: ExecutionCategory },
        /// The category is not among the labelled runtimes the request explicitly allows.
        NotExplicitlyAllowed {
            offered: ExecutionCategory,
            allowed: BTreeSet<ExecutionCategory>,
        },
    }
}

impl CategoryRefusal {
    /// The refused category.
    pub fn offered(&self) -> ExecutionCategory {
        match self {
            Self::VmSandboxRequired { offered } | Self::NotExplicitlyAllowed { offered, .. } => {
                *offered
            }
        }
    }

    /// The refused category's recorded label.
    pub fn label(&self) -> &'static str {
        self.offered().label()
    }

    /// The recorded decision keeping the refused category (VM-D4–VM-D6).
    pub fn decision(&self) -> Option<&'static str> {
        self.offered().decision()
    }

    /// What the user can do: choose an allowed category; nothing is substituted.
    pub fn remedy(&self) -> Remedy {
        Remedy::ChooseAllowedCategory
    }
}

impl fmt::Display for CategoryRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let offered = self.offered();
        match self {
            Self::VmSandboxRequired { .. } => {
                write!(
                    f,
                    "this request requires a VM sandbox; \"{}\"",
                    offered.label()
                )?;
                if let Some(decision) = offered.decision() {
                    write!(f, " is kept by {decision} and")?;
                }
                write!(
                    f,
                    " is never selected or substituted for one; choose a VM sandbox runtime"
                )
            }
            Self::NotExplicitlyAllowed { allowed, .. } => {
                write!(f, "\"{}\"", offered.label())?;
                if let Some(decision) = offered.decision() {
                    write!(f, " ({decision})")?;
                }
                f.write_str(" is not among the runtimes this request explicitly allows")?;
                if allowed.is_empty() {
                    f.write_str(", which are none")?;
                } else {
                    f.write_str(": ")?;
                    for (index, category) in allowed.iter().enumerate() {
                        if index > 0 {
                            f.write_str("; ")?;
                        }
                        write!(f, "\"{}\"", category.label())?;
                    }
                }
                write!(f, "; {}", self.remedy())
            }
        }
    }
}

impl std::error::Error for CategoryRefusal {}

/// No offer was admissible.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionRefusal {
    /// One refusal per offer, in offer order; empty when nothing was offered.
    pub refusals: Vec<CategoryRefusal>,
}

impl fmt::Display for SelectionRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.refusals.is_empty() {
            return f.write_str("no runtime was offered for this request");
        }
        for (index, refusal) in self.refusals.iter().enumerate() {
            if index > 0 {
                f.write_str(". ")?;
            }
            write!(f, "{refusal}")?;
        }
        Ok(())
    }
}

impl std::error::Error for SelectionRefusal {}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::foundation::evidence::envelope::{Observation, SourceClass, UnsupportedReason};
    use crate::foundation::evidence::fakes::FakeProbe;
    use crate::foundation::evidence::subject::{Backend, BackendRelease};
    use crate::foundation::ids::{digest, ManualClock};

    const HOUR: Duration = Duration::from_secs(3_600);

    const LABELLED: [ExecutionCategory; 3] = [
        ExecutionCategory::SharedKernelGpuRuntime,
        ExecutionCategory::ProviderContainerRuntime,
        ExecutionCategory::HostProcessModelRuntime,
    ];

    fn config() -> ConfigurationFingerprint {
        ConfigurationFingerprint::from_settings([("launch", "v1")]).unwrap()
    }

    fn runtime(category: ExecutionCategory) -> RuntimeSubject {
        RuntimeSubject {
            category,
            release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
            instance: digest("yougori/test/instance/v1", &[b"r1"]),
        }
    }

    /// Offers a runtime labelled `claimed`, whose category a `source` adapter reports by
    /// `observation`.
    fn offer_with(
        claimed: ExecutionCategory,
        source: SourceClass,
        observation: Observation,
    ) -> Result<RuntimeOffer, EvidenceRefusal> {
        let mut registry = ProbeRegistry::new(ManualClock::default());
        let probe = Arc::new(FakeProbe::runtime_category(source));
        registry.register(Box::new(Arc::clone(&probe))).unwrap();
        let runtime = runtime(claimed);
        let subject = Subject::Runtime(runtime.clone());
        probe.respond(&subject, observation);
        registry
            .refresh(Capability::RuntimeCategory, &subject)
            .unwrap();
        RuntimeOffer::observe(&registry, runtime, HOUR, config())
    }

    fn confirmed(category: ExecutionCategory) -> Observation {
        Observation::supported(config(), HOUR, SupportDetail::RuntimeCategory { category })
    }

    /// An offer whose category a host probe confirmed.
    fn offer(category: ExecutionCategory) -> RuntimeOffer {
        offer_with(category, SourceClass::HostProbe, confirmed(category)).unwrap()
    }

    fn explicit(categories: &[ExecutionCategory]) -> RuntimeRequirement {
        RuntimeRequirement::explicit(categories.iter().copied()).unwrap()
    }

    #[test]
    fn a_vm_required_request_refuses_every_labelled_runtime_with_its_decision() {
        let requirement = RuntimeRequirement::VmSandbox;
        for (category, decision) in LABELLED.into_iter().zip(["VM-D4", "VM-D5", "VM-D6"]) {
            let refusal = requirement.admit(&offer(category)).unwrap_err();
            assert_eq!(
                refusal,
                CategoryRefusal::VmSandboxRequired { offered: category }
            );
            assert_eq!(refusal.decision(), Some(decision));
            assert_eq!(refusal.label(), category.label());
            let message = refusal.to_string();
            assert!(message.contains(decision), "{message}");
            assert!(message.contains(category.label()), "{message}");
            assert_eq!(refusal.remedy(), Remedy::ChooseAllowedCategory);
        }
        let admitted = requirement
            .admit(&offer(ExecutionCategory::VmSandbox))
            .unwrap();
        assert!(admitted.is_vm_sandbox());
        assert_eq!(admitted.label(), "VM sandbox");
        assert_eq!(admitted.decision(), None);
        assert_eq!(admitted.evidence().source(), SourceClass::HostProbe);
        assert_eq!(admitted.runtime(), &runtime(ExecutionCategory::VmSandbox));
    }

    #[test]
    fn a_vm_required_request_never_selects_a_labelled_runtime() {
        let requirement = RuntimeRequirement::VmSandbox;
        let labelled: Vec<RuntimeOffer> = LABELLED.into_iter().map(offer).collect();
        let refusal = requirement.select(&labelled).unwrap_err();
        assert_eq!(refusal.refusals.len(), 3);
        let message = refusal.to_string();
        for decision in ["VM-D4", "VM-D5", "VM-D6"] {
            assert!(message.contains(decision), "{message}");
        }
        let mut offers = labelled;
        offers.push(offer(ExecutionCategory::VmSandbox));
        assert_eq!(
            requirement.select(&offers).unwrap().category(),
            ExecutionCategory::VmSandbox
        );
        assert_eq!(
            requirement.select(&[]).unwrap_err().to_string(),
            "no runtime was offered for this request"
        );
    }

    #[test]
    fn a_labelled_runtime_is_allowed_only_when_explicitly_allowed() {
        for category in LABELLED {
            let admitted = explicit(&[category]).admit(&offer(category)).unwrap();
            assert_eq!(admitted.category(), category);
            assert_eq!(admitted.label(), category.label());
            assert!(!admitted.is_vm_sandbox());
            assert!(admitted.label().ends_with("not a sandbox"));
            for other in LABELLED.into_iter().filter(|other| *other != category) {
                let refusal = explicit(&[category]).admit(&offer(other)).unwrap_err();
                assert!(matches!(
                    refusal,
                    CategoryRefusal::NotExplicitlyAllowed { .. }
                ));
                assert!(refusal.to_string().contains(other.decision().unwrap()));
            }
            assert!(explicit(&[]).admit(&offer(category)).is_err());
        }
    }

    #[test]
    fn an_explicit_choice_is_not_replaced_by_a_vm_sandbox() {
        let requirement = explicit(&[ExecutionCategory::SharedKernelGpuRuntime]);
        let refusal = requirement
            .admit(&offer(ExecutionCategory::VmSandbox))
            .unwrap_err();
        assert!(refusal
            .to_string()
            .contains("GPU runtime (shared kernel), not a sandbox"));
        let chosen = requirement
            .select(&[
                offer(ExecutionCategory::VmSandbox),
                offer(ExecutionCategory::SharedKernelGpuRuntime),
            ])
            .unwrap();
        assert_eq!(chosen.category(), ExecutionCategory::SharedKernelGpuRuntime);
        assert_eq!(chosen.decision(), Some("VM-D4"));
    }

    /// Review finding 4(a): an explicit set mixing a VM sandbox with a labelled runtime
    /// selected the labelled runtime when no VM was offered.
    #[test]
    fn an_explicit_set_never_lists_a_vm_sandbox() {
        let mixed = [
            ExecutionCategory::VmSandbox,
            ExecutionCategory::SharedKernelGpuRuntime,
        ];
        assert_eq!(
            RuntimeRequirement::explicit(mixed),
            Err(RequirementError::VmSandboxListed)
        );
        assert_eq!(
            LabelledRuntimes::new([ExecutionCategory::VmSandbox]),
            Err(RequirementError::VmSandboxListed)
        );
        let parsed = serde_json::from_value::<RuntimeRequirement>(serde_json::json!({
            "requires": "explicit",
            "allowed": ["vm_sandbox", "shared_kernel_gpu_runtime"]
        }));
        let error = parsed.unwrap_err().to_string();
        assert!(error.contains("require a VM sandbox on its own"), "{error}");

        let refusal = RuntimeRequirement::VmSandbox
            .select(&[offer(ExecutionCategory::SharedKernelGpuRuntime)])
            .unwrap_err();
        assert!(matches!(
            refusal.refusals.as_slice(),
            [CategoryRefusal::VmSandboxRequired { .. }]
        ));
    }

    /// Review finding 4(b): admission took a bare category, so a provider container
    /// labelled as a VM sandbox by the caller passed a VM-required request.
    #[test]
    fn admission_needs_host_or_provider_evidence_of_the_category() {
        let pod_as_vm = offer_with(
            ExecutionCategory::VmSandbox,
            SourceClass::ProviderApi,
            Observation::unsupported(config(), HOUR, UnsupportedReason::DifferentCategory),
        )
        .unwrap_err();
        assert_eq!(
            pod_as_vm,
            EvidenceRefusal::Unsupported {
                capability: Capability::RuntimeCategory,
                reason: UnsupportedReason::DifferentCategory,
            }
        );
        assert_eq!(pod_as_vm.remedy(), Remedy::ChooseAllowedCategory);

        let mislabelled = offer_with(
            ExecutionCategory::VmSandbox,
            SourceClass::ProviderApi,
            confirmed(ExecutionCategory::ProviderContainerRuntime),
        )
        .unwrap_err();
        assert_eq!(
            mislabelled,
            EvidenceRefusal::Unknown {
                capability: Capability::RuntimeCategory,
                reason: UnknownReason::InconsistentReport,
            }
        );

        for weak in [
            SourceClass::GuestReport,
            SourceClass::RecordedDeclaration,
            SourceClass::Fixture,
        ] {
            let refused = offer_with(
                ExecutionCategory::VmSandbox,
                weak,
                confirmed(ExecutionCategory::VmSandbox),
            )
            .unwrap_err();
            assert!(matches!(
                refused,
                EvidenceRefusal::SourceTooWeak {
                    required: SourceClass::ProviderApi,
                    ..
                }
            ));
        }

        let pod = offer_with(
            ExecutionCategory::ProviderContainerRuntime,
            SourceClass::ProviderApi,
            confirmed(ExecutionCategory::ProviderContainerRuntime),
        )
        .unwrap();
        assert_eq!(pod.evidence().source(), SourceClass::ProviderApi);
        let refusal = RuntimeRequirement::VmSandbox.admit(&pod).unwrap_err();
        assert!(refusal.to_string().contains("VM-D5"));
        let vm = offer_with(
            ExecutionCategory::VmSandbox,
            SourceClass::ProviderApi,
            confirmed(ExecutionCategory::VmSandbox),
        )
        .unwrap();
        assert!(RuntimeRequirement::VmSandbox.admit(&vm).is_ok());
    }

    #[test]
    fn the_matrix_is_exact_and_admits_nothing() {
        for (category, outcome) in RuntimeRequirement::VmSandbox.matrix() {
            assert_eq!(outcome.is_ok(), category.is_vm_sandbox());
        }
        let labelled = explicit(&LABELLED);
        for (category, outcome) in labelled.matrix() {
            assert_eq!(outcome.is_ok(), !category.is_vm_sandbox());
        }
        for allowed in LABELLED {
            for (category, outcome) in explicit(&[allowed]).matrix() {
                assert_eq!(outcome.is_ok(), category == allowed);
            }
        }
    }

    #[test]
    fn requirements_serialize_by_name_and_refuse_unknown_fields() {
        assert_eq!(
            serde_json::to_value(RuntimeRequirement::VmSandbox).unwrap(),
            serde_json::json!({"requires": "vm_sandbox"})
        );
        let requirement = explicit(&[ExecutionCategory::ProviderContainerRuntime]);
        let json = serde_json::to_value(&requirement).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"requires": "explicit", "allowed": ["provider_container_runtime"]})
        );
        assert_eq!(
            serde_json::from_value::<RuntimeRequirement>(json).unwrap(),
            requirement
        );
        assert!(
            serde_json::from_value::<RuntimeRequirement>(serde_json::json!({
                "requires": "vm_sandbox",
                "allowed": ["shared_kernel_gpu_runtime"]
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<CategoryRefusal>(serde_json::json!({
                "refusal": "vm_sandbox_required",
                "offered": "shared_kernel_gpu_runtime",
                "waived": true
            }))
            .is_err()
        );
    }
}
