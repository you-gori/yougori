//! CORE-01 adapters of the provider API class over the latest provider reports (M11A
//! items 2 and 3), modelled on `host_evidence`'s host adapters.
//!
//! An adapter never calls the provider: it reads the report the provider transport last
//! recorded and turns it into one observation. Its freshness counts from when that call
//! started, so evidence never looks newer than the call behind it; a report older than the
//! capability's freshness yields "not tested", asking for a new call.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;

use super::report::{ProviderReport, ProviderReports, ReportedAccelerators};
use crate::foundation::evidence::{
    Capability, ComputePlatform, ConfigurationFingerprint, HostChange, Observation, ProbeAdapter,
    ProbeRegistry, RegistryError, Requirement, RuntimeSubject, SourceClass, Subject, SupportDetail,
    UnknownReason, UnsupportedReason,
};
use crate::foundation::ids::{digest, Clock};
use crate::sandbox_contract::remote::OfferingKind;

/// How long a provider's report that it runs a resource as a container stays fresh.
pub const PROVIDER_CONTAINER_FRESH_FOR: Duration = Duration::from_secs(60);
/// How long a provider's report of a runtime's execution category stays fresh; admission
/// rests on it, so it is as short as the host probe's.
pub const PROVIDER_CATEGORY_FRESH_FOR: Duration = Duration::from_secs(60);
/// How long a provider's report of a runtime's accelerators stays fresh.
pub const PROVIDER_COMPUTE_FRESH_FOR: Duration = Duration::from_secs(600);

/// A capability the provider API observes here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderCapability {
    /// The provider runs the resource as a container (VM-D5).
    ProviderContainer,
    /// A remote runtime is the execution category it is offered as (INT-07).
    RuntimeCategory,
    /// The compute platform of a remote runtime.
    ComputePlatform,
}

impl ProviderCapability {
    /// Every capability observed here.
    pub const ALL: [Self; 3] = [
        Self::ProviderContainer,
        Self::RuntimeCategory,
        Self::ComputePlatform,
    ];

    /// The CORE-01 capability.
    pub const fn capability(self) -> Capability {
        match self {
            Self::ProviderContainer => Capability::ProviderContainer,
            Self::RuntimeCategory => Capability::RuntimeCategory,
            Self::ComputePlatform => Capability::ComputePlatform,
        }
    }

    /// How long an observation stays fresh, counted from the call's start.
    pub const fn fresh_for(self) -> Duration {
        match self {
            Self::ProviderContainer => PROVIDER_CONTAINER_FRESH_FOR,
            Self::RuntimeCategory => PROVIDER_CATEGORY_FRESH_FOR,
            Self::ComputePlatform => PROVIDER_COMPUTE_FRESH_FOR,
        }
    }
}

impl TryFrom<Capability> for ProviderCapability {
    type Error = NotProviderObserved;

    /// The three capabilities are named; any other, including capabilities added later,
    /// is refused.
    fn try_from(capability: Capability) -> Result<Self, Self::Error> {
        match capability {
            Capability::ProviderContainer => Ok(Self::ProviderContainer),
            Capability::RuntimeCategory => Ok(Self::RuntimeCategory),
            Capability::ComputePlatform => Ok(Self::ComputePlatform),
            other => Err(NotProviderObserved::Capability { capability: other }),
        }
    }
}

/// Why the provider API does not observe a capability of a subject.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum NotProviderObserved {
    /// Only `ProviderContainer`, `RuntimeCategory` and `ComputePlatform` are observed from
    /// the provider API.
    Capability { capability: Capability },
    /// No provider report is about the subject: it is not a reported provider resource,
    /// nor a VM sandbox or provider container on a reported instance, or it is not the
    /// capability's kind of subject.
    Subject,
}

impl fmt::Display for NotProviderObserved {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capability { capability } => {
                write!(f, "{capability} is not observed from the provider API")
            }
            Self::Subject => f.write_str("no provider report is about this subject"),
        }
    }
}

impl std::error::Error for NotProviderObserved {}

impl<C: Clock> ProviderReports<C> {
    /// The requirement for `capability` of `subject`: evidence from at least the
    /// capability's weakest source, no older than its freshness bound, under the
    /// configuration of the latest report about the subject.
    pub fn requirement(
        &self,
        capability: Capability,
        subject: &Subject,
    ) -> Result<Requirement, NotProviderObserved> {
        let observed = ProviderCapability::try_from(capability)?;
        if subject.kind() != capability.subject_kind() {
            return Err(NotProviderObserved::Subject);
        }
        let configuration = self
            .configuration(subject)
            .ok_or(NotProviderObserved::Subject)?;
        Ok(Requirement::new(
            capability,
            subject.clone(),
            capability.weakest_source(),
            observed.fresh_for(),
            configuration,
        ))
    }
}

/// Domain of [`not_reported`].
const NOT_REPORTED_DOMAIN: &str = "yougori/provider-evidence/not-reported/v1";

/// The fingerprint of an observation made without a report; no requirement is ever stated
/// under it.
fn not_reported() -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_digest(digest(NOT_REPORTED_DOMAIN, &[]))
}

type Outcome = Result<SupportDetail, Result<UnsupportedReason, UnknownReason>>;

/// Builds an observation under `configuration`, or "not tested" when the report is too
/// old to back it.
fn observation(
    configuration: ConfigurationFingerprint,
    fresh_for: Duration,
    outcome: Outcome,
) -> Observation {
    if fresh_for.is_zero() {
        return Observation::unknown(configuration, Duration::ZERO, UnknownReason::NotTested);
    }
    match outcome {
        Ok(detail) => Observation::supported(configuration, fresh_for, detail),
        Err(Ok(reason)) => Observation::unsupported(configuration, fresh_for, reason),
        Err(Err(reason)) => Observation::unknown(configuration, fresh_for, reason),
    }
}

/// Whether the provider runs the resource as a container, with the hardening layers it
/// reported. Both layers must be reported; nvproxy is gVisor's GPU proxy, so nvproxy
/// without gVisor does not fit.
fn container(report: &ProviderReport) -> Outcome {
    if report.instance.kind != OfferingKind::ProviderContainer {
        return Err(Ok(UnsupportedReason::NotAProviderContainer));
    }
    match (report.gvisor, report.nvproxy) {
        (Some(false), Some(true)) => Err(Err(UnknownReason::InconsistentReport)),
        (Some(gvisor), Some(nvproxy)) => Ok(SupportDetail::ProviderContainer { gvisor, nvproxy }),
        _ => Err(Err(UnknownReason::NotTested)),
    }
}

/// The runtime's category as the reported kind establishes it. A provider container is
/// never a VM sandbox (VM-D5), and a host that launches per-sandbox VMs is never the
/// sandbox itself.
fn category(report: &ProviderReport, runtime: &RuntimeSubject) -> Outcome {
    match report.instance_category() {
        Some(category) if category == runtime.category => {
            Ok(SupportDetail::RuntimeCategory { category })
        }
        _ => Err(Ok(UnsupportedReason::DifferentCategory)),
    }
}

/// The runtime's compute platform from the reported accelerators: CUDA for NVIDIA GPUs
/// whose driver's CUDA version was reported, the CPU for an instance reported without
/// accelerators. The subject must be what the provider runs.
fn compute_platform(report: &ProviderReport, runtime: &RuntimeSubject) -> Outcome {
    if report.instance_category() != Some(runtime.category) {
        return Err(Err(UnknownReason::InconsistentReport));
    }
    match &report.accelerators {
        Some(ReportedAccelerators::CpuOnly) => Ok(SupportDetail::ComputePlatform {
            platform: ComputePlatform::Cpu,
        }),
        Some(ReportedAccelerators::NvidiaGpus { cuda: Some(_), .. }) => {
            Ok(SupportDetail::ComputePlatform {
                platform: ComputePlatform::Cuda,
            })
        }
        Some(ReportedAccelerators::NvidiaGpus { cuda: None, .. }) | None => {
            Err(Err(UnknownReason::NotTested))
        }
    }
}

/// One capability observed from the provider's reports.
pub(super) struct ProviderProbe<C: Clock> {
    pub(super) capability: ProviderCapability,
    pub(super) reports: Arc<ProviderReports<C>>,
}

impl<C: Clock> ProbeAdapter for ProviderProbe<C> {
    fn capability(&self) -> Capability {
        self.capability.capability()
    }

    fn source(&self) -> SourceClass {
        SourceClass::ProviderApi
    }

    fn host_changes(&self) -> Vec<HostChange> {
        Vec::new()
    }

    /// Exactly the remote subjects a report is about (see [`ProviderReports::about`]).
    fn observes(&self, subject: &Subject) -> bool {
        subject.kind() == self.capability.capability().subject_kind()
            && self.reports.about(subject).is_some()
    }

    fn observe(&self, subject: &Subject) -> Observation {
        let Some(recorded) = self.reports.about(subject) else {
            return Observation::unknown(not_reported(), Duration::ZERO, UnknownReason::NotTested);
        };
        let age = self
            .reports
            .now()
            .saturating_duration_since(recorded.started_at());
        let fresh_for = self.capability.fresh_for().saturating_sub(age);
        let report = recorded.report();
        let outcome = match (self.capability, subject) {
            (ProviderCapability::ProviderContainer, Subject::Provider(_)) => container(report),
            (ProviderCapability::RuntimeCategory, Subject::Runtime(runtime)) => {
                category(report, runtime)
            }
            (ProviderCapability::ComputePlatform, Subject::Runtime(runtime)) => {
                compute_platform(report, runtime)
            }
            _ => Err(Err(UnknownReason::InconsistentReport)),
        };
        observation(recorded.configuration(), fresh_for, outcome)
    }
}

/// Registers the provider API adapters for `ProviderContainer`, `RuntimeCategory` and
/// `ComputePlatform` over `reports`, which must share the registry's clock. Nothing is
/// registered when any of them already has a provider API adapter.
pub fn register_provider_adapters<C: Clock + 'static>(
    registry: &mut ProbeRegistry<Arc<C>>,
    reports: &Arc<ProviderReports<C>>,
) -> Result<(), RegistryError> {
    let source = SourceClass::ProviderApi;
    for observed in ProviderCapability::ALL {
        let capability = observed.capability();
        if registry.sources(capability).contains(&source) {
            return Err(RegistryError::AlreadyRegistered { capability, source });
        }
    }
    for capability in ProviderCapability::ALL {
        registry.register(Box::new(ProviderProbe {
            capability,
            reports: Arc::clone(reports),
        }))?;
    }
    Ok(())
}
