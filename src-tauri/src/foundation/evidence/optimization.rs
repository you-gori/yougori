//! The optimization gate (INT-06; GPU part §1.1 "integration, experiment or capability
//! gate for every technique").
//!
//! An optional optimization is enabled only when the exact runtime profile permits it,
//! its backend release supports it, fresh and sufficiently trusted evidence shows it
//! works on that runtime under the current configuration, and it is compatible with the
//! other enabled modes. Otherwise the ordinary authorized loader runs, or, when the
//! request requires the feature, the request is refused. Support evidence alone never
//! enables what the profile does not permit, so no gate widens confinement.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::envelope::{
    Capability, ClockReading, ClockSession, ConfigurationFingerprint, SourceClass,
};
use super::modes::{BackendModeRules, ModeRefusal};
use super::registry::ProbeRegistry;
use super::remedy::Remedy;
use super::requirement::{EvidenceRefusal, EvidenceStore, Requirement, Satisfied, Staleness};
use super::subject::{RuntimeSubject, Subject};
use crate::foundation::ids::{Clock, MonotonicTime};

/// An optional loader or serving optimization (INT-06).
///
/// The gate covers one runtime, so sharing CUDA handles with another runtime or VM is not
/// expressible here (S3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Optimization {
    /// CUDA IPC through the legacy API family.
    CudaIpcLegacy,
    /// CUDA IPC through CUDA VMM shareable handles, a different API family.
    CudaIpcVmmShareableHandle,
    IoUring,
    GpuDirectStorage,
    /// A capability-gated experiment, not a universal park operation (S7).
    CudaCheckpoint,
    /// A backend mode (GPU part §1.2).
    ZeroCopyPreload,
    /// A backend mode (S7).
    SleepWeightOffload,
    /// A backend mode that discards the weights while asleep, distinct from offloading
    /// them (S7); waking reloads them from a reconstructible copy.
    SleepWeightDiscard,
    /// Executing early groups while later weights still load (GPU-W07); the normal loader
    /// runs otherwise.
    ExecuteWhileLoad,
}

impl Optimization {
    pub const ALL: [Self; 9] = [
        Self::CudaIpcLegacy,
        Self::CudaIpcVmmShareableHandle,
        Self::IoUring,
        Self::GpuDirectStorage,
        Self::CudaCheckpoint,
        Self::ZeroCopyPreload,
        Self::SleepWeightOffload,
        Self::SleepWeightDiscard,
        Self::ExecuteWhileLoad,
    ];

    /// The capability whose evidence the optimization needs.
    pub const fn capability(self) -> Capability {
        match self {
            Self::CudaIpcLegacy => Capability::CudaIpcLegacy,
            Self::CudaIpcVmmShareableHandle => Capability::CudaIpcVmmShareableHandle,
            Self::IoUring => Capability::IoUring,
            Self::GpuDirectStorage => Capability::GpuDirectStorage,
            Self::CudaCheckpoint => Capability::CudaCheckpoint,
            Self::ZeroCopyPreload => Capability::ZeroCopyPreload,
            Self::SleepWeightOffload => Capability::SleepWeightOffload,
            Self::SleepWeightDiscard => Capability::SleepWeightDiscard,
            Self::ExecuteWhileLoad => Capability::ExecuteWhileLoad,
        }
    }

    /// A mode the backend implements, used only on a release recorded as supporting it.
    pub const fn is_backend_mode(self) -> bool {
        matches!(
            self,
            Self::ZeroCopyPreload | Self::SleepWeightOffload | Self::SleepWeightDiscard
        )
    }

    /// A way of parking or switching a model. Two switching modes are combined only
    /// where a tested release supports both (GPU part §1.1; S7).
    pub const fn is_switching_mode(self) -> bool {
        matches!(
            self,
            Self::ZeroCopyPreload
                | Self::SleepWeightOffload
                | Self::SleepWeightDiscard
                | Self::CudaCheckpoint
        )
    }
}

impl fmt::Display for Optimization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.capability().name())
    }
}

/// Whether a request needs an optimization or merely accepts it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Necessity {
    /// Without it, the ordinary authorized loader runs.
    Optional,
    /// Without it, the load is refused (INT-06: "the required feature is refused").
    Required,
}

/// The evidence an optimization needs on a runtime profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidencePolicy {
    /// Raised to the capability's floor when weaker.
    pub minimum_source: SourceClass,
    pub max_age: Duration,
}

/// One exact runtime and profile (INT-06: "the exact runtime/profile permits and
/// supports it").
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeProfile {
    pub runtime: RuntimeSubject,
    /// Fingerprint of the runtime and profile configuration in force now.
    pub configuration: ConfigurationFingerprint,
    /// The optimizations this profile permits, with the evidence each needs. Anything
    /// absent is not permitted, whatever the evidence shows.
    pub permitted: BTreeMap<Optimization, EvidencePolicy>,
}

/// The optimizations a load asks for.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoaderRequest {
    pub optimizations: BTreeMap<Optimization, Necessity>,
}

strict_evidence_enum! {
    /// Why an optimization was not enabled.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum NotEnabled tag "reason" {
        /// The runtime profile does not permit it; enabling it could widen confinement.
        NotPermitted,
        /// The backend release has no recorded support for this mode.
        Release { refusal: ModeRefusal },
        /// No fresh, sufficiently trusted evidence shows support on this runtime.
        Evidence { refusal: EvidenceRefusal },
        /// It cannot be combined with another enabled mode.
        Conflict {
            with: Optimization,
            refusal: ModeRefusal,
        },
    }
}

impl NotEnabled {
    /// What the user can do about it.
    pub fn remedy(&self) -> Remedy {
        match self {
            Self::NotPermitted => Remedy::UseOrdinaryLoader,
            Self::Release { refusal } | Self::Conflict { refusal, .. } => refusal.remedy(),
            Self::Evidence { refusal } => refusal.remedy(),
        }
    }
}

impl fmt::Display for NotEnabled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotPermitted => write!(
                f,
                "this runtime profile does not permit it; {}",
                Remedy::UseOrdinaryLoader
            ),
            Self::Release { refusal } => write!(f, "{refusal}"),
            Self::Evidence { refusal } => write!(f, "{refusal}"),
            Self::Conflict { with, refusal } => {
                write!(f, "it cannot be combined with {with}: {refusal}")
            }
        }
    }
}

/// One optimization the gate enabled, with what justified it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct Enabled {
    necessity: Necessity,
    policy: EvidencePolicy,
    evidence: Satisfied,
}

/// The gate's decision for one load. Only [`LoaderGate::plan`] makes one.
///
/// A plan is bound to the exact runtime, configuration fingerprint and clock session it
/// was made for, and it lasts only while the evidence behind it does: after
/// [`LoaderPlan::valid_until`], or once the registry no longer holds that evidence, plan
/// the load again. The fallback guard checks a fallback against the plan, not against a
/// loader the caller lists (S3.5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LoaderPlan {
    runtime: RuntimeSubject,
    configuration: ConfigurationFingerprint,
    clock: ClockSession,
    enabled: BTreeMap<Optimization, Enabled>,
    ordinary: BTreeMap<Optimization, NotEnabled>,
}

impl LoaderPlan {
    pub fn is_enabled(&self, optimization: Optimization) -> bool {
        self.enabled.contains_key(&optimization)
    }

    pub fn enabled(&self) -> impl Iterator<Item = Optimization> + '_ {
        self.enabled.keys().copied()
    }

    /// The enabled optimizations, as the loader of a
    /// [`RuntimeSettings`](super::RuntimeSettings).
    pub fn enabled_set(&self) -> BTreeSet<Optimization> {
        self.enabled().collect()
    }

    /// The evidence that enabled `optimization`.
    pub fn evidence_for(&self, optimization: Optimization) -> Option<&Satisfied> {
        self.enabled
            .get(&optimization)
            .map(|enabled| &enabled.evidence)
    }

    /// Whether the request required or merely accepted an enabled optimization.
    pub fn necessity(&self, optimization: Optimization) -> Option<Necessity> {
        self.enabled
            .get(&optimization)
            .map(|enabled| enabled.necessity)
    }

    /// The enabled optimizations the request required; no fallback may drop them.
    pub fn required(&self) -> BTreeSet<Optimization> {
        self.enabled
            .iter()
            .filter(|(_, enabled)| enabled.necessity == Necessity::Required)
            .map(|(optimization, _)| *optimization)
            .collect()
    }

    /// Optional optimizations left to the ordinary loader, with the reason for each.
    pub fn ordinary(&self) -> &BTreeMap<Optimization, NotEnabled> {
        &self.ordinary
    }

    /// True when nothing was enabled: the ordinary authorized loader runs unchanged.
    pub fn is_ordinary_loader(&self) -> bool {
        self.enabled.is_empty()
    }

    /// The exact runtime the plan was made for.
    pub fn runtime(&self) -> &RuntimeSubject {
        &self.runtime
    }

    /// The runtime and profile configuration the plan was made under.
    pub fn configuration(&self) -> ConfigurationFingerprint {
        self.configuration
    }

    /// The clock session of the registry the plan was made with.
    pub fn clock(&self) -> ClockSession {
        self.clock
    }

    /// When the earliest evidence behind an enabled optimization stops being fresh, on
    /// [`LoaderPlan::clock`]; `None` when nothing is enabled.
    pub fn valid_until(&self) -> Option<MonotonicTime> {
        self.enabled
            .values()
            .map(|enabled| enabled.evidence.fresh_until())
            .min()
    }

    /// Whether the evidence that enabled `optimization` still holds in `registry`: the
    /// plan's own evidence is still fresh on the same clock, and the registry still has
    /// evidence that meets the same requirement for the plan's runtime and configuration.
    pub fn recheck<C: Clock>(
        &self,
        optimization: Optimization,
        registry: &ProbeRegistry<C>,
    ) -> Result<Satisfied, EvidenceRefusal> {
        self.recheck_at(optimization, registry.evidence(), registry.now())
    }

    pub(super) fn recheck_at(
        &self,
        optimization: Optimization,
        evidence: &EvidenceStore,
        now: ClockReading,
    ) -> Result<Satisfied, EvidenceRefusal> {
        let capability = optimization.capability();
        let enabled = self
            .enabled
            .get(&optimization)
            .ok_or(EvidenceRefusal::Missing { capability })?;
        if now.session() != self.clock {
            return Err(EvidenceRefusal::Stale {
                capability,
                staleness: Staleness::OtherClock,
            });
        }
        let planned = &enabled.evidence;
        if now.at() > planned.fresh_until() {
            return Err(EvidenceRefusal::Stale {
                capability,
                staleness: Staleness::TooOld {
                    age: now.at().saturating_duration_since(planned.observed_at()),
                    limit: planned
                        .fresh_until()
                        .saturating_duration_since(planned.observed_at()),
                },
            });
        }
        let requirement = Requirement::new(
            capability,
            Subject::Runtime(self.runtime.clone()),
            enabled.policy.minimum_source,
            enabled.policy.max_age,
            self.configuration,
        );
        evidence.evaluate(&requirement, now)
    }
}

/// A required optimization could not be enabled, so the load is refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoaderRefusal {
    pub optimization: Optimization,
    pub reason: NotEnabled,
}

impl LoaderRefusal {
    /// What the user can do about the reason.
    pub fn remedy(&self) -> Remedy {
        self.reason.remedy()
    }
}

impl fmt::Display for LoaderRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} is required but cannot be enabled: {}",
            self.optimization, self.reason
        )
    }
}

impl std::error::Error for LoaderRefusal {}

/// Decides which optimizations a load may use (INT-06).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoaderGate {
    rules: BackendModeRules,
}

impl LoaderGate {
    /// A gate with `rules` as its backend-mode rules.
    pub fn new(rules: BackendModeRules) -> Self {
        Self { rules }
    }

    /// A gate with the recorded backend-mode rules.
    pub fn recorded() -> Self {
        Self::new(BackendModeRules::recorded())
    }

    pub fn rules(&self) -> &BackendModeRules {
        &self.rules
    }

    /// Plans one load on `profile`.
    ///
    /// Each requested optimization must be permitted by the profile, supported by the
    /// backend release when it is a backend mode, and shown by evidence about this exact
    /// runtime under the profile's current configuration. Switching modes that the
    /// release has not tested together are then separated: two required ones refuse the
    /// load, a required one keeps priority over an optional one, and two optional ones
    /// both fall back to the ordinary loader rather than one being chosen silently.
    ///
    /// Evidence and time both come from `registry`, read once for the whole plan, and the
    /// plan is bound to that registry's clock session.
    pub fn plan<C: Clock>(
        &self,
        profile: &RuntimeProfile,
        request: &LoaderRequest,
        registry: &ProbeRegistry<C>,
    ) -> Result<LoaderPlan, LoaderRefusal> {
        let now = registry.now();
        let evidence = registry.evidence();
        let subject = Subject::Runtime(profile.runtime.clone());
        let mut candidates = BTreeMap::new();
        let mut ordinary = BTreeMap::new();
        for (&optimization, &necessity) in &request.optimizations {
            match self.check(profile, &subject, optimization, evidence, now) {
                Ok((policy, evidence)) => {
                    candidates.insert(
                        optimization,
                        Enabled {
                            necessity,
                            policy,
                            evidence,
                        },
                    );
                }
                Err(reason) if necessity == Necessity::Required => {
                    return Err(LoaderRefusal {
                        optimization,
                        reason,
                    });
                }
                Err(reason) => {
                    ordinary.insert(optimization, reason);
                }
            }
        }

        let modes: Vec<(Optimization, Necessity)> = candidates
            .iter()
            .filter(|(optimization, _)| optimization.is_switching_mode())
            .map(|(optimization, enabled)| (*optimization, enabled.necessity))
            .collect();
        let mut separated = BTreeMap::new();
        for (index, &(one, one_needed)) in modes.iter().enumerate() {
            for &(other, other_needed) in modes.iter().skip(index + 1) {
                let Err(refusal) = self.rules.check_pair(&profile.runtime.release, one, other)
                else {
                    continue;
                };
                if one_needed == Necessity::Required && other_needed == Necessity::Required {
                    return Err(LoaderRefusal {
                        optimization: one,
                        reason: NotEnabled::Conflict {
                            with: other,
                            refusal,
                        },
                    });
                }
                if one_needed == Necessity::Optional {
                    separated.entry(one).or_insert(NotEnabled::Conflict {
                        with: other,
                        refusal: refusal.clone(),
                    });
                }
                if other_needed == Necessity::Optional {
                    separated
                        .entry(other)
                        .or_insert(NotEnabled::Conflict { with: one, refusal });
                }
            }
        }
        for (optimization, reason) in separated {
            candidates.remove(&optimization);
            ordinary.insert(optimization, reason);
        }
        Ok(LoaderPlan {
            runtime: profile.runtime.clone(),
            configuration: profile.configuration,
            clock: now.session(),
            enabled: candidates,
            ordinary,
        })
    }

    fn check(
        &self,
        profile: &RuntimeProfile,
        subject: &Subject,
        optimization: Optimization,
        evidence: &EvidenceStore,
        now: ClockReading,
    ) -> Result<(EvidencePolicy, Satisfied), NotEnabled> {
        let policy = *profile
            .permitted
            .get(&optimization)
            .ok_or(NotEnabled::NotPermitted)?;
        self.rules
            .check_mode(&profile.runtime.release, optimization)
            .map_err(|refusal| NotEnabled::Release { refusal })?;
        let requirement = Requirement::new(
            optimization.capability(),
            subject.clone(),
            policy.minimum_source,
            policy.max_age,
            profile.configuration,
        );
        evidence
            .evaluate(&requirement, now)
            .map(|satisfied| (policy, satisfied))
            .map_err(|refusal| NotEnabled::Evidence { refusal })
    }
}
