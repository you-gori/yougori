//! A backend runtime: the rows it is on, the techniques it may run, and sleep with the
//! retention it may advertise (GPU part §3.8, §1.1–§1.2; GPU-W01).
//!
//! A runtime's enabled modes come only from a [`LoaderPlan`] that evidence's gate made for
//! that runtime under its current configuration, and a backend mode (sleep or preload) is
//! admitted only while the evidence behind that plan still holds: a plan expires at its
//! earliest evidence expiry (T01). CUDA mechanisms are refused off a declared CUDA
//! platform whatever the evidence claims, and on a declared CUDA platform they need fresh
//! CORE-01 `ComputePlatform` evidence that shows it (see [`PlatformRefusal`]). Evidence's
//! mode rules are checked again before any sleep or preload, so zero-copy preload and
//! sleep weight offloading never meet on a release that documents them as incompatible.
//!
//! Each sleep level runs as its own backend mode: weight offloading, or weight discarding
//! for a level that drops the weights, which needs CORE-01 `SleepWeightDiscard` evidence.
//! CORE-01's recorded rules do not record discarding on vLLM 0.31.0, so a backend that
//! relies on it passes its own rule table and cites the documentation that records it
//! ([`BackendRuntime::cite_discard_sleep`]). A discarding level is entered only under
//! residency's clean-eviction rule: a copy reconstructs exactly those weights.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::capabilities::{
    sleep_recorded, KvRetention, LevelSemantics, PinnedCapabilities, SleepLevel, WeightRetention,
};
use super::declarations::{
    needs_cuda, CapabilityCondition, ComputePlatform, CriticalBoundary, ModeRow, PinnedFeature,
    Stage, Technique, TechniqueGate,
};
use super::platform::PlatformRefusal;
use crate::foundation::evidence::{
    BackendModeRules, BackendRelease, Capability, EvidencePolicy, EvidenceRefusal, LoaderPlan,
    ModeRefusal, Optimization, ProbeRegistry, Remedy, Requirement, RuntimeProfile, Satisfied,
    Subject, SupportDetail,
};
use crate::foundation::ids::{Clock, Digest};
use crate::model_memory::residency::eviction::{Content, ReconstructibleCopy};

/// The vLLM 0.31.0 sleep-mode documentation the plan cites (S7: "[vLLM sleep
/// documentation](https://docs.vllm.ai/en/v0.31.0/features/sleep_mode/)"), the citation a
/// backend gives when its own rule table records discard-mode sleep on that release.
pub const VLLM_0_31_0_SLEEP_DOC: &str = "https://docs.vllm.ai/en/v0.31.0/features/sleep_mode/";

/// Approval to run one later experiment on one exact release (GPU part §1.1: an
/// experiment gate for every technique). Later experiments are off without one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentApproval {
    pub technique: Technique,
    pub release: BackendRelease,
    /// The recorded experiment plan the approval belongs to.
    pub record: Digest,
}

/// Why a runtime could not be assembled.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum RuntimeRefusal {
    /// The pinned capabilities belong to another release.
    PinnedForAnotherRelease {
        runtime: BackendRelease,
        pinned: BackendRelease,
    },
    /// The loader plan was made for another runtime.
    PlanForAnotherRuntime,
    /// The loader plan was made under another configuration than the profile's current
    /// one.
    PlanForAnotherConfiguration,
    /// A CUDA mechanism on a platform without CUDA, whatever the evidence claims (GPU
    /// part §3.8: "CUDA mechanisms are not silently assumed").
    CudaOnOtherPlatform {
        optimization: Optimization,
        platform: ComputePlatform,
    },
    /// Evidence's mode rules refuse the enabled modes together, or do not record the mode
    /// a citation is given for.
    Modes { cause: ModeRefusal },
    /// A citation names no documentation.
    EmptyCitation,
}

impl RuntimeRefusal {
    /// What the user can do about it.
    pub fn remedy(&self) -> Remedy {
        match self {
            Self::PinnedForAnotherRelease { .. } | Self::PlanForAnotherRuntime => Remedy::RunCheck,
            Self::PlanForAnotherConfiguration => Remedy::RecheckCurrentConfiguration,
            Self::CudaOnOtherPlatform { .. } => Remedy::ChooseSupportedRuntime,
            Self::Modes { cause } => cause.remedy(),
            Self::EmptyCitation => Remedy::UseRecordedBackendRelease,
        }
    }
}

impl fmt::Display for RuntimeRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let remedy = self.remedy();
        match self {
            Self::PinnedForAnotherRelease { runtime, pinned } => write!(
                f,
                "the pinned capabilities describe {pinned}, not this runtime's {runtime}; \
                 {remedy}"
            ),
            Self::PlanForAnotherRuntime => {
                write!(f, "the loader plan was made for another runtime; {remedy}")
            }
            Self::PlanForAnotherConfiguration => write!(
                f,
                "the loader plan was made under another configuration; {remedy}"
            ),
            Self::CudaOnOtherPlatform {
                optimization,
                platform,
            } => write!(
                f,
                "{optimization} is a CUDA mechanism and this runtime runs on {platform}, where \
                 CUDA mechanisms are never assumed, whatever a check reports; {remedy}"
            ),
            Self::Modes { cause } => write!(f, "{cause}"),
            Self::EmptyCitation => write!(
                f,
                "a citation must name the documentation that records the mode; {remedy}"
            ),
        }
    }
}

impl std::error::Error for RuntimeRefusal {}

/// Why a runtime may not run a technique (GPU part §3.8, §1.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum TechniqueRefusal {
    /// The technique belongs to a row this runtime is not on.
    OtherRow { technique: Technique, row: ModeRow },
    /// A CUDA mechanism on a platform without CUDA (GPU part §3.8, CPU/Metal/other).
    CudaOnOtherPlatform {
        technique: Technique,
        platform: ComputePlatform,
    },
    /// A CUDA mechanism on a runtime whose CUDA platform fresh CORE-01 evidence does not
    /// show (GPU part §3.8: "CUDA mechanisms are not silently assumed").
    PlatformNotShown {
        technique: Technique,
        cause: PlatformRefusal,
    },
    /// Evidence's mode rules refuse the backend mode on this release, or beside a mode
    /// the runtime already runs.
    Mode {
        technique: Technique,
        cause: ModeRefusal,
    },
    /// Evidence's gate did not enable the backend mode on this runtime.
    ModeNotEnabled {
        technique: Technique,
        mode: Optimization,
    },
    /// The technique rests on a backend mode whose evidence expires, so it is admitted
    /// only with a recheck of that evidence ([`BackendRuntime::admit_with_evidence`]).
    EvidenceNotRechecked {
        technique: Technique,
        mode: Optimization,
    },
    /// The evidence behind the runtime's loader plan no longer holds: a plan expires at
    /// its earliest evidence expiry, and when the registry drops or replaces any of its
    /// evidence, so the load is planned again (T01).
    EvidenceNoLongerHolds {
        technique: Technique,
        cause: EvidenceRefusal,
    },
    /// The pinned release did not report the feature ("where supported").
    FeatureNotReported {
        technique: Technique,
        feature: PinnedFeature,
        release: BackendRelease,
    },
    /// A later experiment with no approval for this release.
    ExperimentNotApproved {
        technique: Technique,
        release: BackendRelease,
    },
}

impl TechniqueRefusal {
    /// The refused technique.
    pub fn technique(&self) -> Technique {
        match self {
            Self::OtherRow { technique, .. }
            | Self::CudaOnOtherPlatform { technique, .. }
            | Self::PlatformNotShown { technique, .. }
            | Self::Mode { technique, .. }
            | Self::ModeNotEnabled { technique, .. }
            | Self::EvidenceNotRechecked { technique, .. }
            | Self::EvidenceNoLongerHolds { technique, .. }
            | Self::FeatureNotReported { technique, .. }
            | Self::ExperimentNotApproved { technique, .. } => *technique,
        }
    }

    /// What the user can do about it.
    pub fn remedy(&self) -> Remedy {
        match self {
            Self::OtherRow { .. }
            | Self::CudaOnOtherPlatform { .. }
            | Self::FeatureNotReported { .. } => Remedy::ChooseSupportedRuntime,
            Self::Mode { cause, .. } => cause.remedy(),
            Self::ModeNotEnabled { .. } | Self::ExperimentNotApproved { .. } => {
                Remedy::UseOrdinaryLoader
            }
            Self::EvidenceNotRechecked { .. } => Remedy::RunCheckAgain,
            Self::EvidenceNoLongerHolds { cause, .. } => cause.remedy(),
            Self::PlatformNotShown { cause, .. } => cause.remedy(),
        }
    }
}

impl fmt::Display for TechniqueRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let remedy = self.remedy();
        match self {
            Self::OtherRow { technique, row } => write!(
                f,
                "{technique} belongs to the {row} row, which this runtime is not on; {remedy}"
            ),
            Self::CudaOnOtherPlatform {
                technique,
                platform,
            } => write!(
                f,
                "{technique} is a CUDA mechanism and this runtime runs on {platform}, where \
                 CUDA mechanisms are never assumed; {remedy}"
            ),
            Self::PlatformNotShown { technique, cause } => write!(
                f,
                "{technique} is a CUDA mechanism, and the runtime's CUDA platform is not \
                 shown: {cause}"
            ),
            Self::Mode { technique, cause } => write!(f, "{technique} cannot run: {cause}"),
            Self::ModeNotEnabled { technique, mode } => write!(
                f,
                "{technique} needs {mode}, which the loader gate did not enable on this \
                 runtime; {remedy}"
            ),
            Self::EvidenceNotRechecked { technique, mode } => write!(
                f,
                "{technique} needs {mode}, whose evidence expires, so it is admitted only \
                 after that evidence is rechecked; {remedy}"
            ),
            Self::EvidenceNoLongerHolds { technique, cause } => write!(
                f,
                "the evidence behind this runtime's loader plan no longer holds, so plan the \
                 load again before {technique} runs: {cause}"
            ),
            Self::FeatureNotReported {
                technique,
                feature,
                release,
            } => write!(
                f,
                "{technique} runs only where supported, and {release} did not report \
                 {feature}; {remedy}"
            ),
            Self::ExperimentNotApproved { technique, release } => write!(
                f,
                "{technique} is a later experiment with no approval for {release}; {remedy}"
            ),
        }
    }
}

impl std::error::Error for TechniqueRefusal {}

/// A technique a runtime may run. Only [`BackendRuntime::admit`] makes one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AdmittedTechnique {
    technique: Technique,
    release: BackendRelease,
}

impl AdmittedTechnique {
    /// The admitted technique.
    pub fn technique(&self) -> Technique {
        self.technique
    }

    /// The release it was admitted on.
    pub fn release(&self) -> &BackendRelease {
        &self.release
    }
}

/// One backend runtime with the modes evidence's gate enabled on it (GPU part §3.8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackendRuntime {
    release: BackendRelease,
    platform: ComputePlatform,
    plan: LoaderPlan,
    enabled: BTreeSet<Optimization>,
    rules: BackendModeRules,
    pinned: PinnedCapabilities,
    platform_policy: Option<EvidencePolicy>,
    discard_citation: Option<String>,
}

impl BackendRuntime {
    /// Assembles the runtime of `profile` on the declared `platform` from the gate's
    /// `plan` for it, the gate's mode `rules` and the capabilities its pinned release
    /// reported.
    ///
    /// The plan must have been made for this exact runtime under the profile's current
    /// configuration, no enabled CUDA mechanism may run off a declared CUDA platform, and
    /// the enabled modes must pass the mode rules together. The declared platform only
    /// ever refuses: what rests on CUDA is judged by CORE-01 evidence under the platform
    /// policy ([`Self::with_platform_policy`]), and without one it is not admitted where
    /// evidence is checked.
    pub fn new(
        profile: &RuntimeProfile,
        platform: ComputePlatform,
        plan: &LoaderPlan,
        rules: &BackendModeRules,
        pinned: PinnedCapabilities,
    ) -> Result<Self, RuntimeRefusal> {
        let release = profile.runtime.release.clone();
        if *pinned.release() != release {
            return Err(RuntimeRefusal::PinnedForAnotherRelease {
                runtime: release,
                pinned: pinned.release().clone(),
            });
        }
        if *plan.runtime() != profile.runtime {
            return Err(RuntimeRefusal::PlanForAnotherRuntime);
        }
        if plan.configuration() != profile.configuration {
            return Err(RuntimeRefusal::PlanForAnotherConfiguration);
        }
        let enabled = plan.enabled_set();
        if let Some(&optimization) = enabled
            .iter()
            .find(|optimization| needs_cuda(**optimization) && !platform.is_cuda())
        {
            return Err(RuntimeRefusal::CudaOnOtherPlatform {
                optimization,
                platform,
            });
        }
        rules
            .check(&release, &enabled)
            .map_err(|cause| RuntimeRefusal::Modes { cause })?;
        Ok(Self {
            release,
            platform,
            plan: plan.clone(),
            enabled,
            rules: rules.clone(),
            pinned,
            platform_policy: None,
            discard_citation: None,
        })
    }

    /// Judges the declared platform by CORE-01 `ComputePlatform` evidence about exactly
    /// this runtime, under its configuration, from at least `policy.minimum_source`
    /// (never below CORE-01's guest-report floor) and no older than `policy.max_age`.
    pub fn with_platform_policy(mut self, policy: EvidencePolicy) -> Self {
        self.platform_policy = Some(policy);
        self
    }

    /// Records `source`, the documentation by which this runtime's own rule table records
    /// discard-mode sleep for its release, such as [`VLLM_0_31_0_SLEEP_DOC`]. CORE-01's
    /// recorded rules do not record it on vLLM 0.31.0, because the plan names only
    /// offloading there, so a backend that relies on it passes its own rule table with a
    /// citation (T01 integration). Refused when the rule table does not record it or the
    /// citation is blank.
    pub fn cite_discard_sleep(mut self, source: impl Into<String>) -> Result<Self, RuntimeRefusal> {
        let source = source.into();
        if source.trim().is_empty() {
            return Err(RuntimeRefusal::EmptyCitation);
        }
        self.rules
            .check_mode(&self.release, Optimization::SleepWeightDiscard)
            .map_err(|cause| RuntimeRefusal::Modes { cause })?;
        self.discard_citation = Some(source);
        Ok(self)
    }

    /// The exact backend release.
    pub fn release(&self) -> &BackendRelease {
        &self.release
    }

    /// The platform the runtime was declared with. A declaration is not evidence: what
    /// rests on CUDA is judged by [`Self::check_platform`].
    pub fn platform(&self) -> ComputePlatform {
        self.platform
    }

    /// The policy the declared platform is judged by, if one was set.
    pub fn platform_policy(&self) -> Option<EvidencePolicy> {
        self.platform_policy
    }

    /// The CORE-01 requirement the declared platform is judged by: `ComputePlatform` about
    /// exactly this runtime, under the plan's configuration, within the platform policy.
    /// `None` without a policy.
    pub fn platform_requirement(&self) -> Option<Requirement> {
        self.platform_policy.map(|policy| {
            Requirement::new(
                Capability::ComputePlatform,
                Subject::Runtime(self.plan.runtime().clone()),
                policy.minimum_source,
                policy.max_age,
                self.plan.configuration(),
            )
        })
    }

    /// The platform fresh CORE-01 evidence in `registry` shows, which must be the declared
    /// one: missing, stale, weaker or other-configuration evidence and a contradicting
    /// observation are refused with their reason.
    pub fn check_platform<C: Clock>(
        &self,
        registry: &ProbeRegistry<C>,
    ) -> Result<ComputePlatform, PlatformRefusal> {
        let requirement = self
            .platform_requirement()
            .ok_or(PlatformRefusal::NoPolicy)?;
        self.judge_platform(registry.evaluate(&requirement))
    }

    /// Judges `evaluated`, an evaluation of [`Self::platform_requirement`] made now
    /// elsewhere, such as through an evidence port: it must be compute-platform evidence
    /// about this runtime under its configuration, from a source and within an age the
    /// policy allows, and show the declared platform.
    pub fn judge_platform(
        &self,
        evaluated: Result<Satisfied, EvidenceRefusal>,
    ) -> Result<ComputePlatform, PlatformRefusal> {
        let policy = self.platform_policy.ok_or(PlatformRefusal::NoPolicy)?;
        let evidence = evaluated.map_err(|cause| PlatformRefusal::Evidence { cause })?;
        let SupportDetail::ComputePlatform { platform } = evidence.detail() else {
            return Err(PlatformRefusal::OtherEvidence);
        };
        let minimum = policy
            .minimum_source
            .max(Capability::ComputePlatform.weakest_source());
        let fresh_for = evidence
            .fresh_until()
            .saturating_duration_since(evidence.observed_at());
        if evidence.capability() != Capability::ComputePlatform
            || evidence.subject() != Subject::Runtime(self.plan.runtime().clone()).identity()
            || evidence.configuration() != self.plan.configuration()
            || !evidence.source().satisfies(minimum)
            || fresh_for > policy.max_age
        {
            return Err(PlatformRefusal::OtherEvidence);
        }
        let observed = ComputePlatform::from(*platform);
        if observed != self.platform {
            return Err(PlatformRefusal::Contradicted {
                declared: self.platform,
                observed,
            });
        }
        Ok(observed)
    }

    /// The citation of discard-mode sleep, if one was given.
    pub fn discard_sleep_citation(&self) -> Option<&str> {
        self.discard_citation.as_deref()
    }

    /// The gate's plan the runtime was assembled from.
    pub fn plan(&self) -> &LoaderPlan {
        &self.plan
    }

    /// The optimizations evidence's gate enabled.
    pub fn enabled(&self) -> &BTreeSet<Optimization> {
        &self.enabled
    }

    /// What the pinned release reported.
    pub fn pinned(&self) -> &PinnedCapabilities {
        &self.pinned
    }

    /// The rows this runtime is on: those of its backend, and CPU/Metal/other off CUDA.
    /// SGLang is not an evidence backend, so no runtime is on its row.
    pub fn rows(&self) -> BTreeSet<ModeRow> {
        ModeRow::ALL
            .into_iter()
            .filter(|row| match row.backend() {
                Some(backend) => backend == self.release.backend,
                None => *row == ModeRow::CpuMetalOther && !self.platform.is_cuda(),
            })
            .collect()
    }

    /// Admits `technique` without evidence that expires: it belongs to one of this
    /// runtime's rows, is not a CUDA mechanism off a declared CUDA platform, and its gate
    /// is an integration, a feature the pinned release reported, or an approval for a
    /// later experiment on this exact release. A technique gated by a backend mode is
    /// refused with [`TechniqueRefusal::EvidenceNotRechecked`] once its other checks pass,
    /// and so is a CUDA mechanism on a runtime with a platform policy, with
    /// [`TechniqueRefusal::PlatformNotShown`]: only [`Self::admit_with_evidence`] rechecks
    /// that evidence. A runtime without a platform policy is still admitted to CUDA
    /// experiments on its declared platform here, for callers that hold no evidence
    /// registry yet; that path is to retire once they do, and
    /// [`Self::admit_with_evidence`] never takes it.
    pub fn admit(
        &self,
        technique: Technique,
        approvals: &[ExperimentApproval],
    ) -> Result<AdmittedTechnique, TechniqueRefusal> {
        let pending = self.check_gate(technique, approvals)?;
        if pending.cuda && self.platform_policy.is_some() {
            return Err(TechniqueRefusal::PlatformNotShown {
                technique,
                cause: PlatformRefusal::NotRechecked,
            });
        }
        match pending.mode {
            Some(mode) => Err(TechniqueRefusal::EvidenceNotRechecked { technique, mode }),
            None => Ok(self.admitted(technique)),
        }
    }

    /// Admits `technique` as [`Self::admit`] does, and with its evidence rechecked in
    /// `registry`, the registry the plan was made with. A CUDA mechanism needs fresh
    /// CORE-01 evidence that shows the declared CUDA platform ([`Self::check_platform`]).
    /// A technique gated by a backend mode the gate enabled, which the mode rules allow
    /// beside the other enabled modes, is admitted only while the plan still holds: the
    /// mode's own evidence first, then the rest of the plan's, because a plan expires at
    /// its earliest evidence expiry (T01). So preload and sleep never run on evidence that
    /// went stale after the runtime was assembled.
    pub fn admit_with_evidence<C: Clock>(
        &self,
        technique: Technique,
        approvals: &[ExperimentApproval],
        registry: &ProbeRegistry<C>,
    ) -> Result<AdmittedTechnique, TechniqueRefusal> {
        let pending = self.check_gate(technique, approvals)?;
        if pending.cuda {
            self.check_platform(registry)
                .map_err(|cause| TechniqueRefusal::PlatformNotShown { technique, cause })?;
        }
        if let Some(mode) = pending.mode {
            self.recheck_plan(mode, registry)
                .map_err(|cause| TechniqueRefusal::EvidenceNoLongerHolds { technique, cause })?;
        }
        Ok(self.admitted(technique))
    }

    /// The row and declared-platform checks: the technique belongs to one of this
    /// runtime's rows and is not a CUDA mechanism off a declared CUDA platform.
    fn check_place(&self, technique: Technique) -> Result<(), TechniqueRefusal> {
        let row = technique.row();
        if !self.rows().contains(&row) {
            return Err(TechniqueRefusal::OtherRow { technique, row });
        }
        if technique.needs_cuda() && !self.platform.is_cuda() {
            return Err(TechniqueRefusal::CudaOnOtherPlatform {
                technique,
                platform: self.platform,
            });
        }
        Ok(())
    }

    /// The row, platform and gate checks of admission, and what the caller still has to
    /// recheck in the evidence registry.
    fn check_gate(
        &self,
        technique: Technique,
        approvals: &[ExperimentApproval],
    ) -> Result<Pending, TechniqueRefusal> {
        self.check_place(technique)?;
        let cuda = technique.needs_cuda();
        match technique.gate() {
            TechniqueGate::Integration => {}
            TechniqueGate::Capability {
                condition: CapabilityCondition::BackendMode { mode },
            } => {
                self.check_backend_mode(technique, mode)?;
                return Ok(Pending {
                    mode: Some(mode),
                    cuda,
                });
            }
            TechniqueGate::Capability {
                condition: CapabilityCondition::PinnedFeature { feature },
            } => {
                if !self.pinned.supports(feature) {
                    return Err(TechniqueRefusal::FeatureNotReported {
                        technique,
                        feature,
                        release: self.release.clone(),
                    });
                }
            }
            TechniqueGate::Experiment => {
                if !approvals.iter().any(|approval| {
                    approval.technique == technique && approval.release == self.release
                }) {
                    return Err(TechniqueRefusal::ExperimentNotApproved {
                        technique,
                        release: self.release.clone(),
                    });
                }
            }
        }
        Ok(Pending { mode: None, cuda })
    }

    fn admitted(&self, technique: Technique) -> AdmittedTechnique {
        AdmittedTechnique {
            technique,
            release: self.release.clone(),
        }
    }

    /// Rechecks every piece of evidence behind the plan in `registry`, `first` first, so a
    /// refusal names the mode's own evidence when that is what failed.
    fn recheck_plan<C: Clock>(
        &self,
        first: Optimization,
        registry: &ProbeRegistry<C>,
    ) -> Result<(), EvidenceRefusal> {
        self.plan.recheck(first, registry)?;
        for &other in self.enabled.iter().filter(|other| **other != first) {
            self.plan.recheck(other, registry)?;
        }
        Ok(())
    }

    /// Every technique of every row this runtime is on, each with its refusal if it has
    /// one, backend modes rechecked in `registry` (CPU/Metal/other: "truthful capability
    /// report").
    pub fn capability_report<C: Clock>(
        &self,
        approvals: &[ExperimentApproval],
        registry: &ProbeRegistry<C>,
    ) -> CapabilityReport {
        let rows = self
            .rows()
            .into_iter()
            .map(|row| {
                let declaration = row.declaration();
                let techniques = declaration
                    .first_implementation
                    .iter()
                    .chain(&declaration.later_experiment)
                    .map(|&technique| TechniqueStatus {
                        technique,
                        stage: technique.stage(),
                        refusal: self
                            .admit_with_evidence(technique, approvals, registry)
                            .err(),
                    })
                    .collect();
                RowReport {
                    row,
                    critical_boundary: declaration.critical_boundary,
                    techniques,
                }
            })
            .collect();
        CapabilityReport {
            release: self.release.clone(),
            platform: self.platform,
            platform_refusal: self.check_platform(registry).err(),
            rows,
        }
    }

    /// Plans sleep at `level` (vLLM retained process: "Version-supported sleep/wake").
    ///
    /// The runtime must be on the vLLM retained-process row on a declared CUDA platform,
    /// and its rules must record a sleep mode for the release. The level must be one the
    /// pinned release reported, and it runs as its own mode ([`LevelSemantics::mode`]):
    /// weight offloading, or weight discarding for a level that drops the weights. The
    /// rules must record that mode, the gate must have enabled it and nothing conflicting
    /// such as zero-copy preload may run beside it. Discarding needs the citation of its
    /// documentation when CORE-01's recorded rules do not record it
    /// ([`Self::cite_discard_sleep`]). Fresh CORE-01 evidence must show the CUDA platform,
    /// and the evidence behind the plan, that of the level's mode first, must still hold
    /// in `registry`, the registry the plan was made with (T01: a plan expires at its
    /// earliest evidence expiry).
    ///
    /// `weights` is the content of the loaded weights, which is immutable. A level that
    /// discards the weights needs a `copy` that
    /// [`reconstructs`](ReconstructibleCopy::reconstructs) them: verified for exactly that
    /// content and kept in a tier that guarantees availability, pinned host RAM or local
    /// storage (GPU part §1.1, line 307: drop clean GPU copies only when a verified
    /// reconstructible copy exists). A copy given for any other level must reconstruct the
    /// weights too, so a plan never names a copy that cannot.
    pub fn plan_sleep<C: Clock>(
        &self,
        level: SleepLevel,
        weights: Content,
        copy: Option<ReconstructibleCopy>,
        registry: &ProbeRegistry<C>,
    ) -> Result<SleepPlan, SleepRefusal> {
        let technique = Technique::VersionSupportedSleepWake;
        let refused = |cause| SleepRefusal::Technique { cause };
        self.check_place(technique).map_err(refused)?;
        sleep_recorded(&self.rules, &self.release)
            .map_err(|cause| refused(TechniqueRefusal::Mode { technique, cause }))?;
        let semantics = self
            .pinned
            .level(level)
            .ok_or_else(|| SleepRefusal::UnknownLevel {
                level,
                release: self.release.clone(),
            })?;
        let mode = semantics.mode();
        self.check_backend_mode(technique, mode).map_err(refused)?;
        let citation = match mode {
            Optimization::SleepWeightDiscard => {
                let recorded = BackendModeRules::recorded()
                    .check_mode(&self.release, mode)
                    .is_ok();
                if self.discard_citation.is_none() && !recorded {
                    return Err(SleepRefusal::DiscardSleepNotCited {
                        level,
                        release: self.release.clone(),
                    });
                }
                self.discard_citation.clone()
            }
            _ => None,
        };
        self.check_platform(registry)
            .map_err(|cause| refused(TechniqueRefusal::PlatformNotShown { technique, cause }))?;
        self.recheck_plan(mode, registry)
            .map_err(|cause| SleepRefusal::EvidenceNoLongerHolds { cause })?;
        if !matches!(weights, Content::Immutable(_)) {
            return Err(SleepRefusal::WeightsNotImmutable { weights });
        }
        match copy {
            Some(copy) if !copy.reconstructs(&weights) => {
                return Err(SleepRefusal::CopyDoesNotReconstruct { level, copy });
            }
            None if !semantics.weights.is_retained() => {
                return Err(SleepRefusal::NoReconstructibleCopy { level });
            }
            _ => {}
        }
        Ok(SleepPlan {
            release: self.release.clone(),
            level,
            semantics,
            mode,
            citation,
            weights,
            reconstructible_copy: copy,
        })
    }

    fn check_backend_mode(
        &self,
        technique: Technique,
        mode: Optimization,
    ) -> Result<(), TechniqueRefusal> {
        let refused = |cause| TechniqueRefusal::Mode { technique, cause };
        self.rules
            .check_mode(&self.release, mode)
            .map_err(refused)?;
        for &other in self.enabled.iter().filter(|other| **other != mode) {
            self.rules
                .check_pair(&self.release, other, mode)
                .map_err(refused)?;
        }
        if self.enabled.contains(&mode) {
            Ok(())
        } else {
            Err(TechniqueRefusal::ModeNotEnabled { technique, mode })
        }
    }
}

/// What admission still has to recheck in the evidence registry once the row, platform
/// and gate checks passed.
struct Pending {
    /// The backend mode the gate rests on.
    mode: Option<Optimization>,
    /// Whether the technique is a CUDA mechanism, so it rests on the CUDA platform.
    cuda: bool,
}

/// Every technique of every row a runtime is on, with the reason for each refusal (GPU
/// part §3.8, CPU/Metal/other: "truthful capability report").
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CapabilityReport {
    pub release: BackendRelease,
    /// The platform the runtime was declared with.
    pub platform: ComputePlatform,
    /// Why fresh CORE-01 evidence does not show the declared platform; `None` when it
    /// does.
    pub platform_refusal: Option<PlatformRefusal>,
    pub rows: Vec<RowReport>,
}

impl CapabilityReport {
    /// The techniques the runtime may run.
    pub fn available(&self) -> impl Iterator<Item = Technique> + '_ {
        self.rows
            .iter()
            .flat_map(|row| &row.techniques)
            .filter(|status| status.refusal.is_none())
            .map(|status| status.technique)
    }
}

/// One row of a [`CapabilityReport`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RowReport {
    pub row: ModeRow,
    pub critical_boundary: CriticalBoundary,
    pub techniques: Vec<TechniqueStatus>,
}

/// One technique of a [`CapabilityReport`]; `refusal` is `None` when the runtime may run
/// it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TechniqueStatus {
    pub technique: Technique,
    pub stage: Stage,
    pub refusal: Option<TechniqueRefusal>,
}

/// Why a runtime may not sleep at a level.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum SleepRefusal {
    /// The runtime may not run version-supported sleep/wake, the level's mode, or a CUDA
    /// mechanism at all.
    Technique { cause: TechniqueRefusal },
    /// The level discards the weights, and the runtime's own rule table records discarding
    /// for the release without the citation of its documentation that CORE-01's recorded
    /// rules would otherwise stand for.
    DiscardSleepNotCited {
        level: SleepLevel,
        release: BackendRelease,
    },
    /// The evidence behind the plan no longer holds: some of it, that of sleep first, went
    /// stale, came from another clock, or the registry dropped or replaced it.
    EvidenceNoLongerHolds { cause: EvidenceRefusal },
    /// The pinned release did not report this level, so nothing is assumed about it.
    UnknownLevel {
        level: SleepLevel,
        release: BackendRelease,
    },
    /// The weights' content must be immutable content, never a session state.
    WeightsNotImmutable { weights: Content },
    /// The level discards the weights and no copy was given to rebuild them from.
    NoReconstructibleCopy { level: SleepLevel },
    /// The copy cannot rebuild the weights: it is unverified, verified for other content,
    /// or kept in a tier that does not guarantee availability.
    CopyDoesNotReconstruct {
        level: SleepLevel,
        copy: ReconstructibleCopy,
    },
}

impl fmt::Display for SleepRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Technique { cause } => write!(f, "{cause}"),
            Self::DiscardSleepNotCited { level, release } => write!(
                f,
                "sleep level {level} discards the weights, which CORE-01's recorded rules do \
                 not record on {release}; a rule table that does must cite the documentation \
                 that records it"
            ),
            Self::EvidenceNoLongerHolds { cause } => write!(
                f,
                "the evidence behind this runtime's loader plan no longer holds, so plan the \
                 load again: {cause}"
            ),
            Self::UnknownLevel { level, release } => write!(
                f,
                "{release} did not report sleep level {level}, so nothing is assumed about it"
            ),
            Self::WeightsNotImmutable { .. } => {
                f.write_str("the weights must be named by the content key of their bytes")
            }
            Self::NoReconstructibleCopy { level } => write!(
                f,
                "sleep level {level} discards the weights, which is allowed only when a copy \
                 verified for exactly these weights is kept in pinned host RAM or local storage"
            ),
            Self::CopyDoesNotReconstruct { level, .. } => write!(
                f,
                "the copy named for sleep level {level} cannot rebuild these weights: only a \
                 copy verified for exactly them and kept in pinned host RAM or local storage can"
            ),
        }
    }
}

impl std::error::Error for SleepRefusal {}

/// A sleep the runtime may enter. Only [`BackendRuntime::plan_sleep`] makes one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SleepPlan {
    release: BackendRelease,
    level: SleepLevel,
    semantics: LevelSemantics,
    mode: Optimization,
    citation: Option<String>,
    weights: Content,
    reconstructible_copy: Option<ReconstructibleCopy>,
}

impl SleepPlan {
    /// The release that sleeps.
    pub fn release(&self) -> &BackendRelease {
        &self.release
    }

    /// The level it sleeps at.
    pub fn level(&self) -> SleepLevel {
        self.level
    }

    /// What the level keeps, as the pinned release reported it.
    pub fn semantics(&self) -> LevelSemantics {
        self.semantics
    }

    /// The backend mode the level runs as, whose evidence admitted it.
    pub fn mode(&self) -> Optimization {
        self.mode
    }

    /// The citation of discard-mode sleep, for a discarding level on a rule table beyond
    /// CORE-01's recorded rules.
    pub fn citation(&self) -> Option<&str> {
        self.citation.as_deref()
    }

    /// The content of the weights that sleep.
    pub fn weights(&self) -> Content {
        self.weights
    }

    /// The copy that reconstructs the weights, which wake reloads discarded weights from;
    /// always present when the level discards them.
    pub fn reconstructible_copy(&self) -> Option<ReconstructibleCopy> {
        self.reconstructible_copy
    }

    /// What may be advertised: weights and KV cache exactly as the level keeps them, and
    /// sessions that recompute their prompts, because sleep can discard KV (vLLM retained
    /// process: "do not advertise session preservation").
    pub fn advertisement(&self) -> RetentionAdvertisement {
        RetentionAdvertisement {
            release: self.release.clone(),
            level: self.level,
            weights: self.semantics.weights,
            kv_cache: self.semantics.kv_cache,
            sessions: SessionContinuity::Recompute,
        }
    }

    /// Checks claims that a runner or status report wants to make about this sleep. A
    /// session claim is always refused; a KV claim holds only where the level itself keeps
    /// the KV cache, never because it keeps the weights (GPU part §3.8).
    pub fn verify_claims(
        &self,
        claims: &BTreeSet<RetentionClaim>,
    ) -> Result<RetentionAdvertisement, RetentionRefusal> {
        if claims.contains(&RetentionClaim::Sessions) {
            return Err(RetentionRefusal::SessionPreservation { level: self.level });
        }
        if claims.contains(&RetentionClaim::KvCache)
            && self.semantics.kv_cache != KvRetention::Retained
        {
            return Err(RetentionRefusal::KvCacheNotRetained {
                level: self.level,
                weights: self.semantics.weights,
            });
        }
        if claims.contains(&RetentionClaim::Weights) && !self.semantics.weights.is_retained() {
            return Err(RetentionRefusal::WeightsNotRetained { level: self.level });
        }
        Ok(self.advertisement())
    }
}

/// A claim about what survived a sleep.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionClaim {
    /// Sessions resume where they were, without recomputing their prompts.
    Sessions,
    /// The KV cache survived.
    KvCache,
    /// The weights survived, on the device or in host memory.
    Weights,
}

/// How sessions continue after a sleep: by recomputing their prompts, because sleep can
/// discard KV (GPU part §3.8) and lost state is never presented as a resume (GPU-W01
/// acceptance).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionContinuity {
    /// Each session's prompt is computed again after wake.
    Recompute,
}

/// What may be advertised about a sleeping runtime (GPU-W01: "expose truthful weight/KV
/// retention").
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RetentionAdvertisement {
    release: BackendRelease,
    level: SleepLevel,
    weights: WeightRetention,
    kv_cache: KvRetention,
    sessions: SessionContinuity,
}

impl RetentionAdvertisement {
    /// The release that sleeps.
    pub fn release(&self) -> &BackendRelease {
        &self.release
    }

    /// The level it sleeps at.
    pub fn level(&self) -> SleepLevel {
        self.level
    }

    /// Where the weights are.
    pub fn weights(&self) -> WeightRetention {
        self.weights
    }

    /// Whether the KV cache was kept, as the level itself states.
    pub fn kv_cache(&self) -> KvRetention {
        self.kv_cache
    }

    /// How sessions continue: always by recomputing.
    pub fn sessions(&self) -> SessionContinuity {
        self.sessions
    }
}

/// An untruthful retention claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum RetentionRefusal {
    /// Sleep can discard KV, so no sleep level advertises session preservation.
    SessionPreservation { level: SleepLevel },
    /// The level does not keep the KV cache; weight retention never implies that it does.
    KvCacheNotRetained {
        level: SleepLevel,
        weights: WeightRetention,
    },
    /// The level discards the weights.
    WeightsNotRetained { level: SleepLevel },
}

impl fmt::Display for RetentionRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SessionPreservation { level } => write!(
                f,
                "sleep level {level} cannot advertise preserved sessions: sleep can discard \
                 KV, so sessions recompute their prompts after wake"
            ),
            Self::KvCacheNotRetained { level, weights } => write!(
                f,
                "sleep level {level} does not keep the KV cache; its weights are {weights}, and \
                 weight retention does not imply KV retention"
            ),
            Self::WeightsNotRetained { level } => {
                write!(f, "sleep level {level} discards the weights")
            }
        }
    }
}

impl std::error::Error for RetentionRefusal {}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use std::sync::Arc;

    use super::super::test_support::{
        configuration, discard_sleep_rules, documented_vllm_levels, evidence, llama_cpp,
        loader_plan, local_copy, pinned, platform_policy, profile, release, runtime_subject,
        transformers, vllm_0_29_0, vllm_0_31_0, weights, Fixture, Loaded, PLATFORM_FRESH_FOR,
    };
    use super::*;
    use crate::foundation::evidence::fakes::FakeProbe;
    use crate::foundation::evidence::{
        self, Backend, BackendModeRule, ConfigurationFingerprint, LoaderGate, ModePair,
        Observation, SourceClass, Staleness, VLLM_0_31_0_PRELOAD_DOC,
    };
    use crate::foundation::ids::{digest, ContentKey, ManualClock, MonotonicTime};
    use crate::model_memory::residency::eviction::{CopyTier, Verification};

    use ComputePlatform::{Cpu, Cuda, Metal, Other};
    use Optimization::{
        CudaCheckpoint, CudaIpcLegacy, GpuDirectStorage, IoUring, SleepWeightDiscard,
        SleepWeightOffload, ZeroCopyPreload,
    };

    fn level(number: u8) -> SleepLevel {
        SleepLevel::new(number)
    }

    fn claims(list: &[RetentionClaim]) -> BTreeSet<RetentionClaim> {
        list.iter().copied().collect()
    }

    fn approval(technique: Technique, release: &BackendRelease) -> ExperimentApproval {
        ExperimentApproval {
            technique,
            release: release.clone(),
            record: digest("yougori/test/experiment/v1", &[technique.name().as_bytes()]),
        }
    }

    /// vLLM's two documented levels plus a level 3 that keeps the weights on the device
    /// and declares the KV cache retained, to show what a declared KV level may claim.
    fn levels_with_kv_retained() -> BTreeMap<SleepLevel, LevelSemantics> {
        let mut levels = documented_vllm_levels();
        levels.insert(
            level(3),
            LevelSemantics {
                weights: WeightRetention::OnDevice,
                kv_cache: KvRetention::Retained,
            },
        );
        levels
    }

    #[test]
    fn cuda_mechanisms_are_never_assumed_on_cpu_or_metal() {
        for platform in [Cpu, Metal, Other] {
            // Lying evidence: the fakes report CUDA IPC, GPUDirect Storage and CUDA
            // checkpoint as supported, and the gate enables them.
            let lying = Fixture::new(llama_cpp()).on(platform).modes(&[
                CudaIpcLegacy,
                GpuDirectStorage,
                CudaCheckpoint,
            ]);
            assert!(lying.plan().is_enabled(CudaIpcLegacy));
            let refusal = lying.build().unwrap_err();
            assert!(matches!(
                refusal,
                RuntimeRefusal::CudaOnOtherPlatform { platform: on, .. } if on == platform
            ));
            assert_eq!(refusal.remedy(), Remedy::ChooseSupportedRuntime);
            assert!(refusal.to_string().contains("never assumed"));

            let sleepy = Fixture::new(vllm_0_31_0())
                .on(platform)
                .modes(&[SleepWeightOffload]);
            assert!(matches!(
                sleepy.build(),
                Err(RuntimeRefusal::CudaOnOtherPlatform {
                    optimization: SleepWeightOffload,
                    ..
                })
            ));

            assert!(Fixture::new(llama_cpp())
                .on(platform)
                .modes(&[IoUring])
                .build()
                .is_ok());

            let vllm = Fixture::new(vllm_0_31_0()).on(platform).build().unwrap();
            let transformers = Fixture::new(transformers()).on(platform).build().unwrap();
            for (runtime, technique) in [
                (&vllm.runtime, Technique::VersionSupportedSleepWake),
                (&vllm.runtime, Technique::CudaGraphs),
                (&vllm.runtime, Technique::PreloadDaemonPilot),
                (&vllm.runtime, Technique::ControlledLocalSharing),
                (&transformers.runtime, Technique::FixedAddressArena),
            ] {
                let approvals = [approval(technique, runtime.release())];
                assert_eq!(
                    runtime.admit(technique, &approvals),
                    Err(TechniqueRefusal::CudaOnOtherPlatform {
                        technique,
                        platform
                    })
                );
            }
            assert!(matches!(
                vllm.sleep(1, None),
                Err(SleepRefusal::Technique {
                    cause: TechniqueRefusal::CudaOnOtherPlatform { .. }
                })
            ));
        }
        assert!(Fixture::new(llama_cpp())
            .modes(&[CudaIpcLegacy, GpuDirectStorage, CudaCheckpoint])
            .build()
            .is_ok());
    }

    #[test]
    fn zero_copy_preload_never_combines_with_sleep_offload() {
        // Asked for both, evidence's gate enables neither on vLLM 0.31.0.
        let both = Fixture::new(vllm_0_31_0()).modes(&[ZeroCopyPreload, SleepWeightOffload]);
        assert!(both.plan().is_ordinary_loader());
        assert!(matches!(
            both.build().unwrap().sleep(1, None),
            Err(SleepRefusal::Technique {
                cause: TechniqueRefusal::ModeNotEnabled {
                    mode: SleepWeightOffload,
                    ..
                }
            })
        ));

        let preloaded = Fixture::new(vllm_0_31_0())
            .modes(&[ZeroCopyPreload])
            .build()
            .unwrap();
        assert!(preloaded
            .admit_rechecked(Technique::PreloadDaemonPilot, &[])
            .is_ok());
        let refusal = preloaded.sleep(1, None).unwrap_err();
        let SleepRefusal::Technique {
            cause:
                TechniqueRefusal::Mode {
                    cause: ModeRefusal::DocumentedConflict { source, .. },
                    ..
                },
        } = &refusal
        else {
            panic!("expected the documented conflict, got {refusal:?}");
        };
        assert_eq!(source, VLLM_0_31_0_PRELOAD_DOC);
        assert!(refusal.to_string().contains(VLLM_0_31_0_PRELOAD_DOC));

        let sleeping = Fixture::new(vllm_0_31_0())
            .modes(&[SleepWeightOffload])
            .build()
            .unwrap();
        assert!(sleeping.sleep(1, None).is_ok());
        let refusal = sleeping
            .admit(Technique::PreloadDaemonPilot, &[])
            .unwrap_err();
        assert!(matches!(
            refusal,
            TechniqueRefusal::Mode {
                cause: ModeRefusal::DocumentedConflict { .. },
                ..
            }
        ));
        assert_eq!(refusal.remedy(), Remedy::UseOneModeAtATime);

        // Only a release recorded as tested with both runs both.
        let tested = release(Backend::Vllm, "9.9.9");
        let rules = BackendModeRules::new([BackendModeRule {
            release: tested.clone(),
            supported: [ZeroCopyPreload, SleepWeightOffload].into(),
            tested_together: [ModePair::new(ZeroCopyPreload, SleepWeightOffload).unwrap()].into(),
            conflicts: Vec::new(),
        }])
        .unwrap();
        let combined = Fixture::new(tested)
            .rules(rules)
            .modes(&[ZeroCopyPreload, SleepWeightOffload])
            .build()
            .unwrap();
        assert_eq!(
            combined.enabled(),
            &BTreeSet::from([ZeroCopyPreload, SleepWeightOffload])
        );
        assert!(combined.sleep(1, None).is_ok());
        assert!(combined
            .admit_rechecked(Technique::PreloadDaemonPilot, &[])
            .is_ok());
    }

    #[test]
    fn sleep_never_advertises_session_preservation() {
        let runtime = Fixture::discarding()
            .levels(levels_with_kv_retained())
            .build()
            .unwrap();
        for (number, copy) in [(1, None), (2, Some(local_copy())), (3, None)] {
            let plan = runtime.sleep(number, copy).unwrap();
            assert_eq!(
                plan.advertisement().sessions(),
                SessionContinuity::Recompute
            );
            for claim_set in [
                claims(&[RetentionClaim::Sessions]),
                claims(&[RetentionClaim::Sessions, RetentionClaim::Weights]),
                claims(&[
                    RetentionClaim::Sessions,
                    RetentionClaim::KvCache,
                    RetentionClaim::Weights,
                ]),
            ] {
                assert_eq!(
                    plan.verify_claims(&claim_set),
                    Err(RetentionRefusal::SessionPreservation {
                        level: level(number)
                    })
                );
            }
            let json = serde_json::to_value(plan.advertisement()).unwrap();
            assert_eq!(json["sessions"], "recompute");
        }
    }

    #[test]
    fn kv_retention_is_never_implied_by_weight_retention() {
        let runtime = Fixture::discarding()
            .levels(levels_with_kv_retained())
            .build()
            .unwrap();

        let one = runtime.sleep(1, None).unwrap();
        let kept = one
            .verify_claims(&claims(&[RetentionClaim::Weights]))
            .unwrap();
        assert_eq!(kept.weights(), WeightRetention::OffloadedToHost);
        assert_eq!(kept.kv_cache(), KvRetention::Discarded);
        for claim_set in [
            claims(&[RetentionClaim::KvCache]),
            claims(&[RetentionClaim::KvCache, RetentionClaim::Weights]),
        ] {
            let refusal = one.verify_claims(&claim_set).unwrap_err();
            assert_eq!(
                refusal,
                RetentionRefusal::KvCacheNotRetained {
                    level: level(1),
                    weights: WeightRetention::OffloadedToHost
                }
            );
            assert!(refusal
                .to_string()
                .contains("weight retention does not imply KV retention"));
        }

        let two = runtime.sleep(2, Some(local_copy())).unwrap();
        assert_eq!(
            two.verify_claims(&claims(&[RetentionClaim::Weights])),
            Err(RetentionRefusal::WeightsNotRetained { level: level(2) })
        );
        assert!(matches!(
            two.verify_claims(&claims(&[RetentionClaim::KvCache])),
            Err(RetentionRefusal::KvCacheNotRetained { .. })
        ));

        // Only a level that itself declares the KV cache kept may say so.
        let three = runtime.sleep(3, None).unwrap();
        let declared = three
            .verify_claims(&claims(&[RetentionClaim::KvCache, RetentionClaim::Weights]))
            .unwrap();
        assert_eq!(declared.kv_cache(), KvRetention::Retained);
    }

    #[test]
    fn a_weight_discarding_level_needs_a_copy_that_reconstructs_the_weights() {
        let loaded = Fixture::discarding().build().unwrap();
        let verified = |content| Verification::Verified { content };
        let copy = |tier, verification| ReconstructibleCopy { tier, verification };

        let refusal = loaded.sleep(2, None).unwrap_err();
        assert_eq!(
            refusal,
            SleepRefusal::NoReconstructibleCopy { level: level(2) }
        );
        assert!(refusal
            .to_string()
            .contains("pinned host RAM or local storage"));

        let other_weights = Content::Immutable(ContentKey::of(b"other weights"));
        for refused in [
            copy(CopyTier::LocalStorage, Verification::Unverified),
            copy(CopyTier::PinnedHost, Verification::Unverified),
            copy(CopyTier::LocalStorage, verified(other_weights)),
            copy(CopyTier::ReclaimableHost, verified(weights())),
            copy(CopyTier::AuthorizedPeer, verified(weights())),
            copy(CopyTier::RemoteSource, verified(weights())),
        ] {
            assert_eq!(
                loaded.sleep(2, Some(refused)),
                Err(SleepRefusal::CopyDoesNotReconstruct {
                    level: level(2),
                    copy: refused
                })
            );
        }

        for accepted in [
            local_copy(),
            copy(CopyTier::PinnedHost, verified(weights())),
        ] {
            let plan = loaded.sleep(2, Some(accepted)).unwrap();
            assert_eq!(plan.reconstructible_copy(), Some(accepted));
            assert_eq!(plan.weights(), weights());
        }

        // A level that keeps the weights needs no copy; a copy given there must still
        // reconstruct them, so a plan never names one that cannot.
        assert_eq!(loaded.sleep(1, None).unwrap().reconstructible_copy(), None);
        assert!(matches!(
            loaded.sleep(1, Some(copy(CopyTier::RemoteSource, verified(weights())))),
            Err(SleepRefusal::CopyDoesNotReconstruct { .. })
        ));

        // Weights are immutable content, never a session state.
        let state = Content::SessionState(digest("yougori/test/session/v1", &[b"kv"]));
        assert_eq!(
            loaded
                .runtime
                .plan_sleep(level(1), state, None, &loaded.registry),
            Err(SleepRefusal::WeightsNotImmutable { weights: state })
        );
    }

    #[test]
    fn sleep_levels_differ() {
        let runtime = Fixture::discarding().build().unwrap();
        let one = runtime.sleep(1, None).unwrap();
        let two = runtime.sleep(2, Some(local_copy())).unwrap();
        assert_ne!(one.semantics(), two.semantics());
        assert_eq!(
            (one.mode(), two.mode()),
            (SleepWeightOffload, SleepWeightDiscard)
        );
        assert_eq!(
            (one.citation(), two.citation()),
            (None, Some(VLLM_0_31_0_SLEEP_DOC))
        );
        assert_ne!(one.advertisement().weights(), two.advertisement().weights());
        assert_eq!(one.advertisement().level(), level(1));
        assert_eq!(two.release(), &vllm_0_31_0());

        let refusal = runtime.sleep(3, None).unwrap_err();
        assert_eq!(
            refusal,
            SleepRefusal::UnknownLevel {
                level: level(3),
                release: vllm_0_31_0()
            }
        );
        assert!(refusal.to_string().contains("nothing is assumed"));
    }

    #[test]
    fn a_sleep_needs_the_evidence_that_enabled_it_to_still_hold() {
        let mut loaded = Fixture::new(vllm_0_31_0())
            .modes(&[SleepWeightOffload])
            .build()
            .unwrap();
        assert!(loaded.sleep(1, None).is_ok());

        // Another registry is another clock session, even where it shows the platform.
        let (other, _) = evidence(&[loaded.plan().runtime()], &[]);
        assert!(matches!(
            loaded.runtime.plan_sleep(level(1), weights(), None, &other),
            Err(SleepRefusal::EvidenceNoLongerHolds {
                cause: EvidenceRefusal::Stale {
                    staleness: Staleness::OtherClock,
                    ..
                }
            })
        ));

        // The registry dropped the evidence.
        let subject = Subject::Runtime(loaded.plan().runtime().clone());
        assert!(loaded
            .registry
            .invalidate(Capability::SleepWeightOffload, &subject));
        assert_eq!(
            loaded.sleep(1, None),
            Err(SleepRefusal::EvidenceNoLongerHolds {
                cause: EvidenceRefusal::Missing {
                    capability: Capability::SleepWeightOffload
                }
            })
        );

        // The evidence went stale on the plan's own clock.
        let fresh = Fixture::new(vllm_0_31_0())
            .modes(&[SleepWeightOffload])
            .build()
            .unwrap();
        fresh.clock.advance(Duration::from_secs(601));
        let refusal = fresh.sleep(1, None).unwrap_err();
        assert!(matches!(
            refusal,
            SleepRefusal::EvidenceNoLongerHolds {
                cause: EvidenceRefusal::Stale {
                    staleness: Staleness::TooOld { .. },
                    ..
                }
            }
        ));
        assert!(refusal.to_string().contains("plan the load again"));
    }

    #[test]
    fn a_backend_mode_is_admitted_only_while_its_evidence_holds() {
        // Review proof (R1-d): admit and PreloadDaemon::attach never looked at the plan's
        // freshness, so zero-copy preload was admitted two hours after its 600-second
        // evidence went stale. Admission now rechecks the plan, as sleep does.
        let preloaded = Fixture::new(vllm_0_31_0())
            .modes(&[ZeroCopyPreload])
            .build()
            .unwrap();
        let pilot = Technique::PreloadDaemonPilot;
        assert!(preloaded.admit_rechecked(pilot, &[]).is_ok());
        // Admission without the registry never admits a backend mode: on a runtime with a
        // platform policy it already stops at the platform, and without one at the mode.
        let unchecked = preloaded.admit(pilot, &[]).unwrap_err();
        assert_eq!(
            unchecked,
            TechniqueRefusal::PlatformNotShown {
                technique: pilot,
                cause: PlatformRefusal::NotRechecked
            }
        );
        assert_eq!(unchecked.remedy(), Remedy::RunCheckAgain);
        assert_eq!(
            Fixture::new(vllm_0_31_0())
                .modes(&[ZeroCopyPreload])
                .declared()
                .unwrap()
                .admit(pilot, &[]),
            Err(TechniqueRefusal::EvidenceNotRechecked {
                technique: pilot,
                mode: ZeroCopyPreload
            })
        );

        // The evidence holds up to its expiry and not one nanosecond later.
        let valid_until = preloaded.plan().valid_until().unwrap();
        preloaded.clock.advance(Duration::from_secs(600));
        assert_eq!(preloaded.clock.now(), valid_until);
        assert!(preloaded.admit_rechecked(pilot, &[]).is_ok());
        preloaded.clock.advance(Duration::from_nanos(1));
        let refusal = preloaded.admit_rechecked(pilot, &[]).unwrap_err();
        assert!(matches!(
            &refusal,
            TechniqueRefusal::EvidenceNoLongerHolds {
                technique: Technique::PreloadDaemonPilot,
                cause: EvidenceRefusal::Stale {
                    staleness: Staleness::TooOld { .. },
                    ..
                },
            }
        ));
        assert_eq!(refusal.remedy(), Remedy::RunCheckAgain);
        assert!(refusal.to_string().contains("plan the load again"));
        let report = preloaded.capability_report(&[], &preloaded.registry);
        let status = report
            .rows
            .iter()
            .flat_map(|row| &row.techniques)
            .find(|status| status.technique == pilot)
            .unwrap();
        assert!(matches!(
            status.refusal,
            Some(TechniqueRefusal::EvidenceNoLongerHolds { .. })
        ));
        assert!(!report.available().any(|technique| technique == pilot));

        // Two hours on, as in the proof: still refused, now on the platform's lapsed
        // evidence too.
        preloaded.clock.advance(Duration::from_secs(7_200));
        assert!(matches!(
            preloaded.admit_rechecked(pilot, &[]),
            Err(TechniqueRefusal::PlatformNotShown {
                cause: PlatformRefusal::Evidence {
                    cause: EvidenceRefusal::Stale { .. }
                },
                ..
            })
        ));
    }

    #[test]
    fn a_plan_expires_at_its_earliest_evidence_expiry() {
        // T01: a loader plan expires at its earliest evidence expiry, so a backend mode is
        // refused once any evidence behind the plan is stale or dropped, not only its own.
        let release = vllm_0_31_0();
        let build = |mode: Optimization| {
            let subject = runtime_subject(&release, "short-lived");
            let mut profile = profile(&subject, &[mode, IoUring]);
            profile.permitted.insert(
                IoUring,
                EvidencePolicy {
                    minimum_source: SourceClass::GuestReport,
                    max_age: Duration::from_secs(60),
                },
            );
            let (registry, clock) = evidence(&[&subject], &[mode, IoUring]);
            let gate = LoaderGate::recorded();
            let plan = loader_plan(&gate, &profile, &registry, &[mode, IoUring]);
            assert_eq!(plan.enabled_set(), BTreeSet::from([mode, IoUring]));
            let capabilities = pinned(release.clone(), documented_vllm_levels(), &[]);
            let runtime = BackendRuntime::new(&profile, Cuda, &plan, gate.rules(), capabilities)
                .unwrap()
                .with_platform_policy(platform_policy());
            (runtime, registry, clock)
        };
        let pilot = Technique::PreloadDaemonPilot;

        let (preload, registry, clock) = build(ZeroCopyPreload);
        assert!(preload.admit_with_evidence(pilot, &[], &registry).is_ok());
        clock.advance(Duration::from_secs(61));
        // Preload's own evidence is still fresh; io_uring's is not, and the plan ended
        // with it.
        assert!(preload.plan().recheck(ZeroCopyPreload, &registry).is_ok());
        match preload.admit_with_evidence(pilot, &[], &registry) {
            Err(TechniqueRefusal::EvidenceNoLongerHolds { cause, .. }) => {
                assert_eq!(cause.capability(), IoUring.capability())
            }
            other => panic!("expected the plan to have expired, got {other:?}"),
        }

        let (sleepy, registry, clock) = build(SleepWeightOffload);
        assert!(sleepy
            .plan_sleep(level(1), weights(), None, &registry)
            .is_ok());
        clock.advance(Duration::from_secs(61));
        assert!(matches!(
            sleepy.plan_sleep(level(1), weights(), None, &registry),
            Err(SleepRefusal::EvidenceNoLongerHolds {
                cause: EvidenceRefusal::Stale { .. }
            })
        ));

        // Evidence the registry dropped ends the plan too.
        let (preload, mut registry, _clock) = build(ZeroCopyPreload);
        let subject = Subject::Runtime(preload.plan().runtime().clone());
        assert!(registry.invalidate(IoUring.capability(), &subject));
        assert!(matches!(
            preload.admit_with_evidence(pilot, &[], &registry),
            Err(TechniqueRefusal::EvidenceNoLongerHolds {
                cause: EvidenceRefusal::Missing { .. },
                ..
            })
        ));
    }

    /// vLLM 0.31.0 declared on CUDA with the test platform policy and the ordinary loader,
    /// whose registry holds one compute-platform observation of it, from `source` under
    /// `observed_under`, or none.
    fn observed_platform(
        source: SourceClass,
        observed_under: ConfigurationFingerprint,
        platform: Option<evidence::ComputePlatform>,
    ) -> Loaded {
        let release = vllm_0_31_0();
        let subject = runtime_subject(&release, "observed");
        let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(1)));
        let mut registry = ProbeRegistry::new(Arc::clone(&clock));
        if let Some(platform) = platform {
            let probe = Arc::new(FakeProbe::new(Capability::ComputePlatform, source));
            probe.respond(
                &Subject::Runtime(subject.clone()),
                Observation::supported(
                    observed_under,
                    PLATFORM_FRESH_FOR,
                    SupportDetail::ComputePlatform { platform },
                ),
            );
            registry.register(Box::new(Arc::clone(&probe))).unwrap();
            registry
                .refresh(
                    Capability::ComputePlatform,
                    &Subject::Runtime(subject.clone()),
                )
                .unwrap();
        }
        let gate = LoaderGate::recorded();
        let profile = profile(&subject, &[]);
        let plan = loader_plan(&gate, &profile, &registry, &[]);
        let capabilities = pinned(release, documented_vllm_levels(), &[]);
        let runtime = BackendRuntime::new(&profile, Cuda, &plan, gate.rules(), capabilities)
            .unwrap()
            .with_platform_policy(platform_policy());
        Loaded {
            runtime,
            registry,
            clock,
        }
    }

    #[test]
    fn cuda_mechanisms_need_compute_platform_evidence() {
        // P06 integration: a declared platform is never evidence. A CUDA mechanism needs
        // fresh CORE-01 compute-platform evidence about exactly this runtime, under its
        // configuration, from at least a guest report, showing the declared CUDA.
        let graphs = Technique::CudaGraphs;
        let approvals = [approval(graphs, &vllm_0_31_0())];
        let refused = |cause| {
            Err(TechniqueRefusal::PlatformNotShown {
                technique: graphs,
                cause,
            })
        };
        let shown = observed_platform(
            SourceClass::GuestReport,
            configuration(),
            Some(evidence::ComputePlatform::Cuda),
        );
        assert_eq!(shown.check_platform(&shown.registry), Ok(Cuda));
        assert!(shown.admit_rechecked(graphs, &approvals).is_ok());
        assert_eq!(
            shown
                .platform_requirement()
                .map(|required| required.capability),
            Some(Capability::ComputePlatform)
        );
        // Not a CUDA mechanism: no platform evidence is asked for.
        let empty = observed_platform(SourceClass::GuestReport, configuration(), None);
        assert!(empty.admit_rechecked(Technique::NormalLoader, &[]).is_ok());

        // Missing, weaker, other-configuration and stale evidence are each refused.
        assert_eq!(
            empty.admit_rechecked(graphs, &approvals),
            refused(PlatformRefusal::Evidence {
                cause: EvidenceRefusal::Missing {
                    capability: Capability::ComputePlatform
                }
            })
        );
        for weak in [SourceClass::Fixture, SourceClass::RecordedDeclaration] {
            let declared =
                observed_platform(weak, configuration(), Some(evidence::ComputePlatform::Cuda));
            assert!(matches!(
                declared.admit_rechecked(graphs, &approvals),
                Err(TechniqueRefusal::PlatformNotShown {
                    cause: PlatformRefusal::Evidence {
                        cause: EvidenceRefusal::SourceTooWeak { .. }
                    },
                    ..
                })
            ));
        }
        let elsewhere = observed_platform(
            SourceClass::GuestReport,
            ConfigurationFingerprint::from_settings([("launch", "changed")]).unwrap(),
            Some(evidence::ComputePlatform::Cuda),
        );
        assert!(matches!(
            elsewhere.admit_rechecked(graphs, &approvals),
            Err(TechniqueRefusal::PlatformNotShown {
                cause: PlatformRefusal::Evidence {
                    cause: EvidenceRefusal::FingerprintChanged { .. }
                },
                ..
            })
        ));
        shown
            .clock
            .advance(PLATFORM_FRESH_FOR + Duration::from_nanos(1));
        let stale = shown.admit_rechecked(graphs, &approvals).unwrap_err();
        assert!(matches!(
            stale,
            TechniqueRefusal::PlatformNotShown {
                cause: PlatformRefusal::Evidence {
                    cause: EvidenceRefusal::Stale {
                        staleness: Staleness::TooOld { .. },
                        ..
                    }
                },
                ..
            }
        ));
        assert_eq!(stale.remedy(), Remedy::RunCheckAgain);

        // Evidence of another platform contradicts the declaration.
        let metal = observed_platform(
            SourceClass::GuestReport,
            configuration(),
            Some(evidence::ComputePlatform::Metal),
        );
        let contradicted = metal.admit_rechecked(graphs, &approvals).unwrap_err();
        assert_eq!(
            contradicted,
            TechniqueRefusal::PlatformNotShown {
                technique: graphs,
                cause: PlatformRefusal::Contradicted {
                    declared: Cuda,
                    observed: Metal
                }
            }
        );
        assert_eq!(contradicted.remedy(), Remedy::ChooseSupportedRuntime);
        assert!(contradicted.to_string().contains("evidence shows Metal"));
        let report = metal.capability_report(&approvals, &metal.registry);
        assert!(!report.available().any(|technique| technique.needs_cuda()));
        assert_eq!(
            report.platform_refusal,
            Some(PlatformRefusal::Contradicted {
                declared: Cuda,
                observed: Metal
            })
        );

        // A stricter policy is the requirement: a guest report no longer does.
        let host_only = observed_platform(
            SourceClass::GuestReport,
            configuration(),
            Some(evidence::ComputePlatform::Cuda),
        );
        let strict = host_only
            .runtime
            .clone()
            .with_platform_policy(EvidencePolicy {
                minimum_source: SourceClass::HostProbe,
                max_age: PLATFORM_FRESH_FOR,
            });
        assert!(matches!(
            strict.check_platform(&host_only.registry),
            Err(PlatformRefusal::Evidence {
                cause: EvidenceRefusal::SourceTooWeak { .. }
            })
        ));

        // Evidence judged elsewhere must be this requirement's: other capabilities, a
        // looser age, or no policy at all are refused.
        let fresh = observed_platform(
            SourceClass::GuestReport,
            configuration(),
            Some(evidence::ComputePlatform::Cuda),
        );
        let mut looser = fresh.platform_requirement().unwrap();
        looser.max_age = PLATFORM_FRESH_FOR * 2;
        let short = fresh.runtime.clone().with_platform_policy(EvidencePolicy {
            minimum_source: SourceClass::GuestReport,
            max_age: Duration::from_secs(60),
        });
        assert_eq!(
            short.judge_platform(fresh.registry.evaluate(&looser)),
            Err(PlatformRefusal::OtherEvidence)
        );
        let mut other_capability = fresh.platform_requirement().unwrap();
        other_capability.capability = Capability::SleepWeightOffload;
        assert_eq!(
            fresh.judge_platform(fresh.registry.evaluate(&other_capability)),
            Err(PlatformRefusal::Evidence {
                cause: EvidenceRefusal::Missing {
                    capability: Capability::SleepWeightOffload
                }
            })
        );
        let declared_only = Fixture::new(vllm_0_31_0()).declared().unwrap();
        assert_eq!(
            declared_only.check_platform(&declared_only.registry),
            Err(PlatformRefusal::NoPolicy)
        );
        assert_eq!(
            declared_only.admit_rechecked(graphs, &approvals),
            refused(PlatformRefusal::NoPolicy)
        );
        assert_eq!(declared_only.platform_requirement(), None);
        // Without a registry and without a policy, the declared platform still admits a
        // CUDA experiment, for callers that hold no registry yet (a path to retire).
        assert!(declared_only.admit(graphs, &approvals).is_ok());
    }

    #[test]
    fn discarding_weights_needs_its_own_evidence_and_a_cited_rule() {
        let copy = Some(local_copy());
        let discard_mode = |cause| SleepRefusal::Technique {
            cause: TechniqueRefusal::Mode {
                technique: Technique::VersionSupportedSleepWake,
                cause,
            },
        };
        // CORE-01's recorded rules do not record discarding on vLLM 0.31.0, because the
        // plan names only offloading there: the discarding level is refused, whatever copy
        // is given, while the offloading level runs.
        let recorded = Fixture::new(vllm_0_31_0())
            .modes(&[SleepWeightOffload])
            .build()
            .unwrap();
        assert!(recorded.sleep(1, None).is_ok());
        let refusal = recorded.sleep(2, copy).unwrap_err();
        assert_eq!(
            refusal,
            discard_mode(ModeRefusal::ModeNotSupported {
                release: vllm_0_31_0(),
                mode: SleepWeightDiscard
            })
        );
        assert!(refusal
            .to_string()
            .contains("no recorded support for sleep-mode weight discarding"));

        // A backend's own rule table records it, but without SleepWeightDiscard evidence
        // the gate does not enable it.
        let own_rules = || discard_sleep_rules(&vllm_0_31_0());
        let unevidenced = Fixture::new(vllm_0_31_0())
            .rules(own_rules())
            .modes(&[SleepWeightOffload])
            .cite(VLLM_0_31_0_SLEEP_DOC)
            .build()
            .unwrap();
        assert_eq!(
            unevidenced.sleep(2, copy),
            Err(SleepRefusal::Technique {
                cause: TechniqueRefusal::ModeNotEnabled {
                    technique: Technique::VersionSupportedSleepWake,
                    mode: SleepWeightDiscard
                }
            })
        );
        // With the rule and the evidence, but no citation of the rule.
        let uncited = Fixture::new(vllm_0_31_0())
            .rules(own_rules())
            .modes(&[SleepWeightOffload, SleepWeightDiscard])
            .build()
            .unwrap();
        let refusal = uncited.sleep(2, copy).unwrap_err();
        assert_eq!(
            refusal,
            SleepRefusal::DiscardSleepNotCited {
                level: level(2),
                release: vllm_0_31_0()
            }
        );
        assert!(refusal.to_string().contains("cite the documentation"));
        assert!(uncited.sleep(1, None).is_ok());

        // Cited: the level runs as discarding, and the plan carries the citation.
        let discarding = Fixture::discarding().build().unwrap();
        assert_eq!(
            discarding.discard_sleep_citation(),
            Some(VLLM_0_31_0_SLEEP_DOC)
        );
        let plan = discarding.sleep(2, copy).unwrap();
        assert_eq!(plan.mode(), SleepWeightDiscard);
        assert_eq!(plan.citation(), Some(VLLM_0_31_0_SLEEP_DOC));
        assert_eq!(
            discarding.sleep(2, None),
            Err(SleepRefusal::NoReconstructibleCopy { level: level(2) })
        );

        // Discarding's own evidence holds the plan: dropped, both levels stop, as a plan
        // ends with any of its evidence.
        let mut lapsed = Fixture::discarding().build().unwrap();
        let subject = Subject::Runtime(lapsed.plan().runtime().clone());
        assert!(lapsed
            .registry
            .invalidate(Capability::SleepWeightDiscard, &subject));
        let missing = Err(SleepRefusal::EvidenceNoLongerHolds {
            cause: EvidenceRefusal::Missing {
                capability: Capability::SleepWeightDiscard,
            },
        });
        assert_eq!(lapsed.sleep(2, copy), missing);
        assert_eq!(lapsed.sleep(1, None), missing);

        // The two sleep modes are switching modes: untested together, the gate enables
        // neither.
        let untested = BackendModeRules::new([BackendModeRule {
            release: vllm_0_31_0(),
            supported: [SleepWeightOffload, SleepWeightDiscard].into(),
            tested_together: BTreeSet::new(),
            conflicts: Vec::new(),
        }])
        .unwrap();
        let separate = Fixture::new(vllm_0_31_0())
            .rules(untested)
            .modes(&[SleepWeightOffload, SleepWeightDiscard])
            .cite(VLLM_0_31_0_SLEEP_DOC)
            .build()
            .unwrap();
        assert!(separate.plan().is_ordinary_loader());
        assert!(matches!(
            separate.sleep(2, copy),
            Err(SleepRefusal::Technique {
                cause: TechniqueRefusal::ModeNotEnabled {
                    mode: SleepWeightDiscard,
                    ..
                }
            })
        ));

        // A citation needs a rule table that records discarding, and a document.
        let plain = recorded.runtime.clone();
        assert_eq!(
            plain.cite_discard_sleep(VLLM_0_31_0_SLEEP_DOC),
            Err(RuntimeRefusal::Modes {
                cause: ModeRefusal::ModeNotSupported {
                    release: vllm_0_31_0(),
                    mode: SleepWeightDiscard
                }
            })
        );
        assert_eq!(
            unevidenced.runtime.clone().cite_discard_sleep(" "),
            Err(RuntimeRefusal::EmptyCitation)
        );
    }

    #[test]
    fn fakes_report_every_optimization_with_a_detail_that_fits() {
        // Each optimization's fake evidence carries the detail CORE-01 accepts for it, so
        // the gate enables every one, execute-while-load and discarding sleep included.
        for optimization in Optimization::ALL {
            let fixture = Fixture::new(vllm_0_31_0())
                .rules(discard_sleep_rules(&vllm_0_31_0()))
                .modes(&[optimization]);
            assert!(fixture.plan().is_enabled(optimization), "{optimization:?}");
        }
    }

    #[test]
    fn pinned_vllm_0_29_0_gets_neither_sleep_nor_preload() {
        let fixture = Fixture::new(vllm_0_29_0()).modes(&[SleepWeightOffload, ZeroCopyPreload]);
        assert!(fixture.plan().is_ordinary_loader());
        let runtime = fixture.build().unwrap();
        let unknown = ModeRefusal::UnknownRelease {
            release: vllm_0_29_0(),
        };
        let refusal = runtime.sleep(1, None).unwrap_err();
        assert_eq!(
            refusal,
            SleepRefusal::Technique {
                cause: TechniqueRefusal::Mode {
                    technique: Technique::VersionSupportedSleepWake,
                    cause: unknown.clone()
                }
            }
        );
        let preload = runtime
            .admit(Technique::PreloadDaemonPilot, &[])
            .unwrap_err();
        assert_eq!(
            preload,
            TechniqueRefusal::Mode {
                technique: Technique::PreloadDaemonPilot,
                cause: unknown
            }
        );
        assert_eq!(preload.remedy(), Remedy::UseRecordedBackendRelease);
        assert!(runtime.admit(Technique::NormalLoader, &[]).is_ok());
    }

    #[test]
    fn transformers_and_llama_cpp_never_sleep() {
        for release in [transformers(), llama_cpp()] {
            let runtime = Fixture::new(release).build().unwrap();
            assert_eq!(
                runtime.sleep(1, None),
                Err(SleepRefusal::Technique {
                    cause: TechniqueRefusal::OtherRow {
                        technique: Technique::VersionSupportedSleepWake,
                        row: ModeRow::VllmRetainedProcess
                    }
                })
            );
        }
    }

    #[test]
    fn later_experiments_need_an_approval_for_the_exact_release() {
        let runtime = Fixture::new(vllm_0_31_0()).build().unwrap();
        let refused = Err(TechniqueRefusal::ExperimentNotApproved {
            technique: Technique::CudaGraphs,
            release: vllm_0_31_0(),
        });
        assert_eq!(runtime.admit(Technique::CudaGraphs, &[]), refused);
        assert_eq!(
            runtime.admit(
                Technique::CudaGraphs,
                &[approval(Technique::CudaGraphs, &vllm_0_29_0())]
            ),
            refused
        );
        assert_eq!(
            runtime.admit(
                Technique::CudaGraphs,
                &[approval(Technique::TunedLoaders, &vllm_0_31_0())]
            ),
            refused
        );
        let approved = [approval(Technique::CudaGraphs, &vllm_0_31_0())];
        let admitted = runtime
            .admit_rechecked(Technique::CudaGraphs, &approved)
            .unwrap();
        assert_eq!(admitted.technique(), Technique::CudaGraphs);
        assert_eq!(admitted.release(), &vllm_0_31_0());
        // Graphs are a CUDA mechanism: approved, they still wait for the platform's
        // evidence.
        assert_eq!(
            runtime.admit(Technique::CudaGraphs, &approved),
            Err(TechniqueRefusal::PlatformNotShown {
                technique: Technique::CudaGraphs,
                cause: PlatformRefusal::NotRechecked
            })
        );

        // An approval never overrides the row (or, as tested above, the platform).
        assert_eq!(
            runtime.admit(
                Technique::NumaTuning,
                &[approval(Technique::NumaTuning, &vllm_0_31_0())]
            ),
            Err(TechniqueRefusal::OtherRow {
                technique: Technique::NumaTuning,
                row: ModeRow::LlamaCppGguf
            })
        );
        let json = serde_json::to_value(approval(Technique::CudaGraphs, &vllm_0_31_0())).unwrap();
        let mut extra = json.clone();
        extra["scope"] = "all".into();
        assert!(serde_json::from_value::<ExperimentApproval>(extra).is_err());
        assert!(serde_json::from_value::<ExperimentApproval>(json).is_ok());
    }

    #[test]
    fn where_supported_means_reported_by_the_pinned_release() {
        let plain = Fixture::new(transformers()).build().unwrap();
        assert_eq!(
            plain.admit(Technique::MetaConstruction, &[]),
            Err(TechniqueRefusal::FeatureNotReported {
                technique: Technique::MetaConstruction,
                feature: PinnedFeature::MetaConstruction,
                release: transformers()
            })
        );
        assert!(plain.admit(Technique::ExistingLoaderBaseline, &[]).is_ok());
        assert!(plain.admit(Technique::BulkIndexedLoad, &[]).is_ok());
        assert!(Fixture::new(transformers())
            .features(&[PinnedFeature::MetaConstruction])
            .build()
            .unwrap()
            .admit(Technique::MetaConstruction, &[])
            .is_ok());

        let llama = Fixture::new(llama_cpp()).build().unwrap();
        assert!(matches!(
            llama.admit(Technique::PersistentProcess, &[]),
            Err(TechniqueRefusal::FeatureNotReported { .. })
        ));
        assert!(Fixture::new(llama_cpp())
            .features(&[PinnedFeature::PersistentProcess])
            .build()
            .unwrap()
            .admit(Technique::PersistentProcess, &[])
            .is_ok());
    }

    #[test]
    fn a_runtime_is_assembled_only_from_its_own_plan() {
        let release = vllm_0_31_0();
        let a = runtime_subject(&release, "a");
        let b = runtime_subject(&release, "b");
        let (registry, _) = evidence(&[&a, &b], &[SleepWeightOffload]);
        let gate = LoaderGate::recorded();
        let plan_a = loader_plan(
            &gate,
            &profile(&a, &[SleepWeightOffload]),
            &registry,
            &[SleepWeightOffload],
        );
        let ordinary_a = loader_plan(&gate, &profile(&a, &[]), &registry, &[]);
        let capabilities = pinned(release.clone(), documented_vllm_levels(), &[]);
        let build = |profile: &RuntimeProfile, plan: &LoaderPlan, pinned: PinnedCapabilities| {
            BackendRuntime::new(profile, Cuda, plan, gate.rules(), pinned)
        };

        for plan in [&plan_a, &ordinary_a] {
            assert_eq!(
                build(
                    &profile(&b, &[SleepWeightOffload]),
                    plan,
                    capabilities.clone()
                ),
                Err(RuntimeRefusal::PlanForAnotherRuntime)
            );
        }
        let mut changed = profile(&a, &[SleepWeightOffload]);
        changed.configuration =
            ConfigurationFingerprint::from_settings([("launch", "changed")]).unwrap();
        let refusal = build(&changed, &plan_a, capabilities.clone()).unwrap_err();
        assert_eq!(refusal, RuntimeRefusal::PlanForAnotherConfiguration);
        assert_eq!(refusal.remedy(), Remedy::RecheckCurrentConfiguration);
        assert_eq!(
            build(
                &profile(&a, &[SleepWeightOffload]),
                &plan_a,
                pinned(vllm_0_29_0(), BTreeMap::new(), &[])
            ),
            Err(RuntimeRefusal::PinnedForAnotherRelease {
                runtime: release.clone(),
                pinned: vllm_0_29_0()
            })
        );
        let runtime = build(&profile(&a, &[SleepWeightOffload]), &plan_a, capabilities)
            .unwrap()
            .with_platform_policy(platform_policy());
        assert_eq!(runtime.enabled(), &BTreeSet::from([SleepWeightOffload]));
        assert_eq!(runtime.platform(), Cuda);
        assert_eq!(runtime.pinned().release(), &release);
        assert_eq!(runtime.plan(), &plan_a);
        assert!(runtime
            .plan_sleep(level(1), weights(), None, &registry)
            .is_ok());
    }

    #[test]
    fn rows_follow_the_backend_and_the_platform() {
        let rows = |fixture: Fixture| fixture.build().unwrap().rows();
        assert_eq!(
            rows(Fixture::new(transformers())),
            BTreeSet::from([ModeRow::Transformers])
        );
        assert_eq!(
            rows(Fixture::new(transformers()).on(Cpu)),
            BTreeSet::from([ModeRow::Transformers, ModeRow::CpuMetalOther])
        );
        assert_eq!(
            rows(Fixture::new(vllm_0_31_0())),
            BTreeSet::from([ModeRow::VllmRetainedProcess, ModeRow::VllmPreloadedWeights])
        );
        assert_eq!(
            rows(Fixture::new(llama_cpp()).on(Metal)),
            BTreeSet::from([ModeRow::LlamaCppGguf, ModeRow::CpuMetalOther])
        );
    }

    #[test]
    fn the_capability_report_is_truthful() {
        let metal = Fixture::new(llama_cpp())
            .on(Metal)
            .features(&[PinnedFeature::PersistentProcess])
            .build()
            .unwrap();
        let report = metal.capability_report(&[], &metal.registry);
        assert_eq!(report.platform_refusal, None);
        assert_eq!(
            report.rows.iter().map(|row| row.row).collect::<Vec<_>>(),
            [ModeRow::LlamaCppGguf, ModeRow::CpuMetalOther]
        );
        assert_eq!(
            report.available().collect::<Vec<_>>(),
            [
                Technique::ExistingMmapPrequantizedPath,
                Technique::PersistentProcess,
                Technique::ExistingSupportedPath,
                Technique::TruthfulCapabilityReport,
            ]
        );
        for status in report.rows.iter().flat_map(|row| &row.techniques) {
            if status.stage == Stage::LaterExperiment {
                assert!(matches!(
                    status.refusal,
                    Some(TechniqueRefusal::ExperimentNotApproved { .. })
                ));
            }
        }
        assert_eq!(
            report.rows[1].critical_boundary,
            CriticalBoundary::NoSilentCudaAssumption
        );

        // A platform nothing can observe is never shown.
        let unknown = Fixture::new(llama_cpp()).on(Other).build().unwrap();
        assert!(matches!(
            unknown
                .capability_report(&[], &unknown.registry)
                .platform_refusal,
            Some(PlatformRefusal::Evidence {
                cause: EvidenceRefusal::Missing { .. }
            })
        ));

        let cpu = Fixture::new(vllm_0_31_0()).on(Cpu).build().unwrap();
        let report = cpu.capability_report(&[], &cpu.registry);
        let mut cuda_techniques = 0;
        for status in report.rows.iter().flat_map(|row| &row.techniques) {
            if status.technique.needs_cuda() {
                cuda_techniques += 1;
                assert!(matches!(
                    status.refusal,
                    Some(TechniqueRefusal::CudaOnOtherPlatform { platform: Cpu, .. })
                ));
            }
        }
        assert_eq!(cuda_techniques, 4);
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["platform"], "cpu");
        assert_eq!(
            json["rows"][0]["techniques"][0]["technique"],
            "version_supported_sleep_wake"
        );
        assert_eq!(
            json["rows"][0]["techniques"][0]["refusal"]["refusal"],
            "cuda_on_other_platform"
        );
    }
}
