//! The performance-fallback guard (S3.5): a fallback may change the loader, batch size
//! or residency within an authorized runtime; it cannot change the required execution
//! category, reopen network access, renew authority or bypass artifact verification.
//!
//! The loader's baseline is the optimization gate's [`LoaderPlan`] for the runtime, not a
//! loader the caller lists, and a fallback keeps an optimization only while the evidence
//! that enabled it still holds (INT-06).

use std::collections::BTreeSet;
use std::fmt;
use std::num::NonZeroU32;

use serde::{Deserialize, Serialize};

use super::envelope::ClockSession;
use super::modes::ModeRefusal;
use super::optimization::{LoaderGate, LoaderPlan, Optimization};
use super::registry::ProbeRegistry;
use super::remedy::Remedy;
use super::requirement::EvidenceRefusal;
use crate::foundation::ids::{AuthorizationEpoch, Clock, Digest, ExecutionCategory, MonotonicTime};

strict_evidence_enum! {
    /// One network grant (VM part §1.3, network authority). A runtime with no grants is
    /// offline.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum NetworkGrant tag "grant" {
        /// A named transport route.
        NamedRoute { route: Digest },
        /// A typed credentialed operation.
        CredentialedOperation { operation: Digest },
        /// A published service.
        PublishedService { service: Digest },
    }
}

/// The authority a runtime holds: its VM authorization epoch and when it expires (S3.1).
/// `expires_at` is a point on `clock`, so grants on different clock sessions, such as
/// before and after a restart, are never compared.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityGrant {
    pub epoch: AuthorizationEpoch,
    /// The clock session `expires_at` was read from.
    pub clock: ClockSession,
    pub expires_at: MonotonicTime,
}

strict_evidence_enum! {
    /// Whether the loader verifies the artifacts it reads (INT-09).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum ArtifactVerification tag "verification" {
        /// Every artifact is verified before use; these are the verified identities.
        Verified { artifacts: BTreeSet<Digest> },
        /// The loader reads without verification.
        Bypassed,
    }
}

/// Where model weights reside.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Residency {
    /// GPU memory.
    Device,
    /// Pinned host memory.
    HostPinned,
    /// Pageable host memory, an explicit CPU offload (S7, consumer hardware).
    HostMemory,
    /// Local storage.
    Disk,
}

/// Everything a performance fallback could touch, each as an explicit field (S3.5).
///
/// A proposal is the complete next state, so the guard compares every field with the
/// authorized state and the approved result is exactly what was checked. The guard
/// destructures this struct exhaustively: a new field does not compile until it is
/// checked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSettings {
    /// Must not change.
    pub execution_category: ExecutionCategory,
    /// May narrow; must not gain a grant.
    pub network: BTreeSet<NetworkGrant>,
    /// Must keep its clock session and epoch; its expiry may only move earlier.
    pub authority: AuthorityGrant,
    /// Must stay verified, over artifacts already verified.
    pub artifact_verification: ArtifactVerification,
    /// May change within the gate's plan: only optimizations it enabled, every required
    /// one kept, modes the backend rules allow together, evidence still holding (INT-06).
    pub loader: BTreeSet<Optimization>,
    /// May change.
    pub batch_size: NonZeroU32,
    /// May change.
    pub residency: Residency,
}

strict_evidence_enum! {
    /// How a fallback would bypass artifact verification.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum ArtifactBypass tag "kind" {
        /// The loader would read without verification.
        VerificationSkipped,
        /// The loader would read artifacts outside the authorized verified set.
        UnverifiedArtifacts { artifacts: BTreeSet<Digest> },
    }
}

strict_evidence_enum! {
    /// One forbidden change in a proposed fallback (S3.5, INT-06).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum FallbackViolation tag "violation" {
        /// Any change of category, including into or out of a VM sandbox.
        ChangesExecutionCategory {
            from: ExecutionCategory,
            to: ExecutionCategory,
        },
        /// The loader plan was made for a runtime of another category.
        PlanForAnotherRuntime {
            plan: ExecutionCategory,
            authorized: ExecutionCategory,
        },
        /// Grants the authorized runtime does not hold.
        ReopensNetworkAccess { added: BTreeSet<NetworkGrant> },
        /// Another clock session or authorization epoch, or a later expiry.
        RenewsAuthority {
            authorized: AuthorityGrant,
            proposed: AuthorityGrant,
        },
        BypassesArtifactVerification { bypass: ArtifactBypass },
        /// The loader would use optimizations the gate's plan did not enable.
        EnablesUngatedOptimization { added: BTreeSet<Optimization> },
        /// The loader would drop optimizations the request required (INT-06: a required
        /// feature is refused, never silently replaced).
        DropsRequiredOptimization { dropped: BTreeSet<Optimization> },
        /// The loader combines modes the backend-mode rules keep apart.
        IncompatibleModes { refusal: ModeRefusal },
        /// The evidence that enabled a kept optimization no longer holds; plan the load
        /// again.
        LoaderEvidenceNoLongerHolds {
            optimization: Optimization,
            refusal: EvidenceRefusal,
        },
    }
}

impl fmt::Display for FallbackViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChangesExecutionCategory { from, to } => {
                write!(
                    f,
                    "the fallback would change the execution category from \"{}\" to \"{}\"",
                    from.label(),
                    to.label()
                )?;
                if let Some(decision) = to.decision() {
                    write!(f, " ({decision})")?;
                }
                f.write_str(", but a performance fallback stays in the authorized category")
            }
            Self::PlanForAnotherRuntime { plan, authorized } => write!(
                f,
                "the loader plan is for a \"{}\" runtime, not this \"{}\" one",
                plan.label(),
                authorized.label()
            ),
            Self::ReopensNetworkAccess { added } => write!(
                f,
                "the fallback would open {} network grant(s) the runtime does not hold",
                added.len()
            ),
            Self::RenewsAuthority {
                authorized,
                proposed,
            } if authorized.clock != proposed.clock => f.write_str(
                "the fallback's authority was issued on another clock, so it cannot be \
                 compared with the authorized one, and a fallback never renews authority",
            ),
            Self::RenewsAuthority {
                authorized,
                proposed,
            } if authorized.epoch != proposed.epoch => write!(
                f,
                "the fallback would move authority from epoch {} to epoch {}, but a fallback \
                 never renews authority",
                authorized.epoch, proposed.epoch
            ),
            Self::RenewsAuthority { .. } => f.write_str(
                "the fallback would extend authority past its expiry, but a fallback never \
                 renews authority",
            ),
            Self::BypassesArtifactVerification {
                bypass: ArtifactBypass::VerificationSkipped,
            } => f.write_str("the fallback would skip artifact verification"),
            Self::BypassesArtifactVerification {
                bypass: ArtifactBypass::UnverifiedArtifacts { artifacts },
            } => write!(
                f,
                "the fallback would load {} artifact(s) outside the verified set",
                artifacts.len()
            ),
            Self::EnablesUngatedOptimization { added } => {
                f.write_str("the fallback would enable ")?;
                list(f, added)?;
                f.write_str(" without passing the optimization gate")
            }
            Self::DropsRequiredOptimization { dropped } => {
                f.write_str("the fallback would drop ")?;
                list(f, dropped)?;
                f.write_str(", which this load requires")
            }
            Self::IncompatibleModes { refusal } => {
                write!(f, "the fallback's loader is not allowed: {refusal}")
            }
            Self::LoaderEvidenceNoLongerHolds {
                optimization,
                refusal,
            } => write!(
                f,
                "the evidence that enabled {optimization} no longer holds: {refusal}"
            ),
        }
    }
}

fn list(f: &mut fmt::Formatter<'_>, optimizations: &BTreeSet<Optimization>) -> fmt::Result {
    for (index, optimization) in optimizations.iter().enumerate() {
        if index > 0 {
            f.write_str(", ")?;
        }
        write!(f, "{optimization}")?;
    }
    Ok(())
}

/// A proposed fallback with at least one forbidden change; every violation is listed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FallbackRefusal {
    violations: Vec<FallbackViolation>,
}

impl FallbackRefusal {
    /// Every forbidden change, in the order the guard checks them.
    pub fn violations(&self) -> &[FallbackViolation] {
        &self.violations
    }

    /// What the user can do: keep the fallback within the authorized runtime (S3.5).
    pub fn remedy(&self) -> Remedy {
        Remedy::KeepWithinAuthorizedRuntime
    }
}

impl fmt::Display for FallbackRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for violation in &self.violations {
            write!(f, "{violation}; ")?;
        }
        write!(f, "{}", self.remedy())
    }
}

impl std::error::Error for FallbackRefusal {}

/// A change a fallback may make.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllowedChange {
    Loader,
    BatchSize,
    Residency,
}

/// An approved fallback. Only [`guard_fallback`] makes one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ApprovedFallback {
    settings: RuntimeSettings,
    changes: BTreeSet<AllowedChange>,
}

impl ApprovedFallback {
    /// The approved settings, exactly as checked.
    pub fn settings(&self) -> &RuntimeSettings {
        &self.settings
    }

    /// The approved settings, exactly as checked.
    pub fn into_settings(self) -> RuntimeSettings {
        self.settings
    }

    /// What the fallback changes; empty when it changes nothing.
    pub fn changes(&self) -> &BTreeSet<AllowedChange> {
        &self.changes
    }
}

/// Approves `proposed` as a performance fallback from `authorized`, or refuses it with
/// every forbidden change (S3.5).
///
/// The loader is checked against `plan`, the decision `gate` made for this runtime with
/// `registry`, never against the loader `authorized` lists: the proposed loader may only
/// use optimizations the plan enabled, must keep every one the request required, must
/// pass `gate`'s backend-mode rules for the plan's release, and keeps an optimization
/// only while the plan's evidence for it is fresh and `registry` still holds evidence
/// that meets the same requirement (INT-06). Authority grants are compared only on one
/// clock session.
pub fn guard_fallback<C: Clock>(
    gate: &LoaderGate,
    registry: &ProbeRegistry<C>,
    plan: &LoaderPlan,
    authorized: &RuntimeSettings,
    proposed: RuntimeSettings,
) -> Result<ApprovedFallback, FallbackRefusal> {
    let RuntimeSettings {
        execution_category,
        network,
        authority,
        artifact_verification,
        loader,
        batch_size,
        residency,
    } = &proposed;

    let mut violations = Vec::new();
    if *execution_category != authorized.execution_category {
        violations.push(FallbackViolation::ChangesExecutionCategory {
            from: authorized.execution_category,
            to: *execution_category,
        });
    }
    if plan.runtime().category != authorized.execution_category {
        violations.push(FallbackViolation::PlanForAnotherRuntime {
            plan: plan.runtime().category,
            authorized: authorized.execution_category,
        });
    }
    let added: BTreeSet<NetworkGrant> = network.difference(&authorized.network).copied().collect();
    if !added.is_empty() {
        violations.push(FallbackViolation::ReopensNetworkAccess { added });
    }
    if authority.clock != authorized.authority.clock
        || authority.epoch != authorized.authority.epoch
        || authority.expires_at > authorized.authority.expires_at
    {
        violations.push(FallbackViolation::RenewsAuthority {
            authorized: authorized.authority,
            proposed: *authority,
        });
    }
    if let Some(bypass) = artifact_bypass(&authorized.artifact_verification, artifact_verification)
    {
        violations.push(FallbackViolation::BypassesArtifactVerification { bypass });
    }
    loader_violations(gate, registry, plan, loader, &mut violations);
    if !violations.is_empty() {
        return Err(FallbackRefusal { violations });
    }

    let mut changes = BTreeSet::new();
    if *loader != authorized.loader {
        changes.insert(AllowedChange::Loader);
    }
    if *batch_size != authorized.batch_size {
        changes.insert(AllowedChange::BatchSize);
    }
    if *residency != authorized.residency {
        changes.insert(AllowedChange::Residency);
    }
    Ok(ApprovedFallback {
        settings: proposed,
        changes,
    })
}

fn loader_violations<C: Clock>(
    gate: &LoaderGate,
    registry: &ProbeRegistry<C>,
    plan: &LoaderPlan,
    loader: &BTreeSet<Optimization>,
    violations: &mut Vec<FallbackViolation>,
) {
    let gated = plan.enabled_set();
    let ungated: BTreeSet<Optimization> = loader.difference(&gated).copied().collect();
    if !ungated.is_empty() {
        violations.push(FallbackViolation::EnablesUngatedOptimization { added: ungated });
    }
    let dropped: BTreeSet<Optimization> = plan.required().difference(loader).copied().collect();
    if !dropped.is_empty() {
        violations.push(FallbackViolation::DropsRequiredOptimization { dropped });
    }
    if let Err(refusal) = gate.rules().check(&plan.runtime().release, loader) {
        violations.push(FallbackViolation::IncompatibleModes { refusal });
    }
    let now = registry.now();
    for optimization in loader.intersection(&gated) {
        if let Err(refusal) = plan.recheck_at(*optimization, registry.evidence(), now) {
            violations.push(FallbackViolation::LoaderEvidenceNoLongerHolds {
                optimization: *optimization,
                refusal,
            });
        }
    }
}

fn artifact_bypass(
    authorized: &ArtifactVerification,
    proposed: &ArtifactVerification,
) -> Option<ArtifactBypass> {
    let ArtifactVerification::Verified { artifacts } = proposed else {
        return Some(ArtifactBypass::VerificationSkipped);
    };
    let unverified: BTreeSet<Digest> = match authorized {
        ArtifactVerification::Verified {
            artifacts: verified,
        } => artifacts.difference(verified).copied().collect(),
        ArtifactVerification::Bypassed => artifacts.clone(),
    };
    (!unverified.is_empty()).then_some(ArtifactBypass::UnverifiedArtifacts {
        artifacts: unverified,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;
    use crate::foundation::evidence::envelope::{
        Capability, ConfigurationFingerprint, Observation, SourceClass, SupportDetail,
    };
    use crate::foundation::evidence::fakes::FakeProbe;
    use crate::foundation::evidence::optimization::{
        EvidencePolicy, LoaderRequest, Necessity, RuntimeProfile,
    };
    use crate::foundation::evidence::requirement::Staleness;
    use crate::foundation::evidence::subject::{Backend, BackendRelease, RuntimeSubject, Subject};
    use crate::foundation::ids::{digest, ManualClock};

    const MINUTE: Duration = Duration::from_secs(60);

    fn artifact(name: &str) -> Digest {
        digest("yougori/test/artifact/v1", &[name.as_bytes()])
    }

    fn route(name: &str) -> NetworkGrant {
        NetworkGrant::NamedRoute {
            route: digest("yougori/test/route/v1", &[name.as_bytes()]),
        }
    }

    fn config() -> ConfigurationFingerprint {
        ConfigurationFingerprint::from_settings([("profile", "p1")]).unwrap()
    }

    fn runtime() -> RuntimeSubject {
        RuntimeSubject {
            category: ExecutionCategory::VmSandbox,
            release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
            instance: digest("yougori/test/instance/v1", &[b"vm-1"]),
        }
    }

    /// A registry with host evidence for io_uring and zero-copy preload on `runtime()`,
    /// and the plan the recorded gate made for a request.
    struct Fixture {
        clock: Arc<ManualClock>,
        registry: ProbeRegistry<Arc<ManualClock>>,
        gate: LoaderGate,
        plan: LoaderPlan,
    }

    impl Fixture {
        fn new(request: &[(Optimization, Necessity)]) -> Self {
            let clock = Arc::new(ManualClock::default());
            let mut registry = ProbeRegistry::new(Arc::clone(&clock));
            let subject = Subject::Runtime(runtime());
            for (capability, detail) in [
                (Capability::IoUring, SupportDetail::Plain),
                (
                    Capability::ZeroCopyPreload,
                    SupportDetail::BackendMode {
                        release: runtime().release,
                    },
                ),
            ] {
                let probe = FakeProbe::new(capability, SourceClass::HostProbe);
                probe.respond(
                    &subject,
                    Observation::supported(config(), MINUTE * 60, detail),
                );
                registry.register(Box::new(probe)).unwrap();
                registry.refresh(capability, &subject).unwrap();
            }
            let gate = LoaderGate::recorded();
            let profile = RuntimeProfile {
                runtime: runtime(),
                configuration: config(),
                permitted: [Optimization::IoUring, Optimization::ZeroCopyPreload]
                    .into_iter()
                    .map(|optimization| {
                        (
                            optimization,
                            EvidencePolicy {
                                minimum_source: SourceClass::HostProbe,
                                max_age: MINUTE,
                            },
                        )
                    })
                    .collect::<BTreeMap<_, _>>(),
            };
            let request = LoaderRequest {
                optimizations: request.iter().copied().collect(),
            };
            let plan = gate.plan(&profile, &request, &registry).unwrap();
            Self {
                clock,
                registry,
                gate,
                plan,
            }
        }

        /// Both optimizations accepted but not required.
        fn optional() -> Self {
            Self::new(&[
                (Optimization::IoUring, Necessity::Optional),
                (Optimization::ZeroCopyPreload, Necessity::Optional),
            ])
        }

        fn authorized(&self) -> RuntimeSettings {
            RuntimeSettings {
                execution_category: ExecutionCategory::VmSandbox,
                network: BTreeSet::from([route("model-download")]),
                authority: AuthorityGrant {
                    epoch: AuthorizationEpoch::new(4),
                    clock: self.registry.session(),
                    expires_at: MonotonicTime::from_nanos(1_000),
                },
                artifact_verification: ArtifactVerification::Verified {
                    artifacts: BTreeSet::from([artifact("weights"), artifact("tokenizer")]),
                },
                loader: self.plan.enabled_set(),
                batch_size: NonZeroU32::new(8).unwrap(),
                residency: Residency::Device,
            }
        }

        fn guard(
            &self,
            authorized: &RuntimeSettings,
            proposed: RuntimeSettings,
        ) -> Result<ApprovedFallback, FallbackRefusal> {
            guard_fallback(&self.gate, &self.registry, &self.plan, authorized, proposed)
        }

        fn refusal(&self, proposed: RuntimeSettings) -> Vec<FallbackViolation> {
            self.guard(&self.authorized(), proposed)
                .unwrap_err()
                .violations()
                .to_vec()
        }
    }

    #[test]
    fn a_fallback_never_changes_the_execution_category() {
        let fixture = Fixture::optional();
        for (to, decision) in [
            (ExecutionCategory::SharedKernelGpuRuntime, "VM-D4"),
            (ExecutionCategory::ProviderContainerRuntime, "VM-D5"),
            (ExecutionCategory::HostProcessModelRuntime, "VM-D6"),
        ] {
            let mut proposed = fixture.authorized();
            proposed.execution_category = to;
            let refused = fixture.guard(&fixture.authorized(), proposed).unwrap_err();
            assert_eq!(
                refused.violations(),
                [FallbackViolation::ChangesExecutionCategory {
                    from: ExecutionCategory::VmSandbox,
                    to
                }]
            );
            assert!(refused.to_string().contains(decision));
            assert_eq!(refused.remedy(), Remedy::KeepWithinAuthorizedRuntime);
        }
        let mut labelled = fixture.authorized();
        labelled.execution_category = ExecutionCategory::SharedKernelGpuRuntime;
        let mut upgraded = labelled.clone();
        upgraded.execution_category = ExecutionCategory::VmSandbox;
        let violations = fixture
            .guard(&labelled, upgraded)
            .unwrap_err()
            .violations()
            .to_vec();
        assert!(
            violations.contains(&FallbackViolation::PlanForAnotherRuntime {
                plan: ExecutionCategory::VmSandbox,
                authorized: ExecutionCategory::SharedKernelGpuRuntime,
            })
        );
        assert!(violations.iter().any(|violation| matches!(
            violation,
            FallbackViolation::ChangesExecutionCategory { .. }
        )));
    }

    #[test]
    fn a_fallback_never_reopens_network_access() {
        let fixture = Fixture::optional();
        let mut proposed = fixture.authorized();
        proposed.network.insert(route("pypi"));
        assert_eq!(
            fixture.refusal(proposed),
            [FallbackViolation::ReopensNetworkAccess {
                added: BTreeSet::from([route("pypi")])
            }]
        );
        let mut offline = fixture.authorized();
        offline.network.clear();
        let mut reopened = offline.clone();
        reopened.network.insert(route("model-download"));
        assert!(fixture.guard(&offline, reopened).is_err());
        let mut narrowed = fixture.authorized();
        narrowed.network.clear();
        assert!(fixture.guard(&fixture.authorized(), narrowed).is_ok());
    }

    #[test]
    fn a_fallback_never_renews_authority() {
        let fixture = Fixture::optional();
        let mut later = fixture.authorized();
        later.authority.expires_at = MonotonicTime::from_nanos(1_001);
        let mut newer = fixture.authorized();
        newer.authority.epoch = AuthorizationEpoch::new(5);
        let mut older = fixture.authorized();
        older.authority.epoch = AuthorizationEpoch::new(3);
        for proposed in [later, newer, older] {
            assert!(matches!(
                fixture.refusal(proposed).as_slice(),
                [FallbackViolation::RenewsAuthority { .. }]
            ));
        }
        let mut sooner = fixture.authorized();
        sooner.authority.expires_at = MonotonicTime::from_nanos(999);
        assert!(fixture.guard(&fixture.authorized(), sooner).is_ok());
    }

    /// Review finding 6: expiry times from two clocks used to be compared, so after a
    /// restart an earlier-looking expiry could pass.
    #[test]
    fn authority_is_compared_only_on_one_clock() {
        let fixture = Fixture::optional();
        let mut restarted = fixture.authorized();
        restarted.authority.clock = ClockSession::generate();
        restarted.authority.expires_at = MonotonicTime::from_nanos(1);
        let violations = fixture.refusal(restarted);
        assert!(matches!(
            violations.as_slice(),
            [FallbackViolation::RenewsAuthority { .. }]
        ));
        assert!(violations[0].to_string().contains("another clock"));
    }

    #[test]
    fn a_fallback_never_bypasses_artifact_verification() {
        let fixture = Fixture::optional();
        let mut skipped = fixture.authorized();
        skipped.artifact_verification = ArtifactVerification::Bypassed;
        assert_eq!(
            fixture.refusal(skipped),
            [FallbackViolation::BypassesArtifactVerification {
                bypass: ArtifactBypass::VerificationSkipped
            }]
        );
        let mut other = fixture.authorized();
        other.artifact_verification = ArtifactVerification::Verified {
            artifacts: BTreeSet::from([artifact("weights"), artifact("unverified-copy")]),
        };
        assert_eq!(
            fixture.refusal(other),
            [FallbackViolation::BypassesArtifactVerification {
                bypass: ArtifactBypass::UnverifiedArtifacts {
                    artifacts: BTreeSet::from([artifact("unverified-copy")])
                }
            }]
        );
        let mut unverified_baseline = fixture.authorized();
        unverified_baseline.artifact_verification = ArtifactVerification::Bypassed;
        assert!(fixture
            .guard(&unverified_baseline, unverified_baseline.clone())
            .is_err());
        let mut subset = fixture.authorized();
        subset.artifact_verification = ArtifactVerification::Verified {
            artifacts: BTreeSet::from([artifact("weights")]),
        };
        assert!(fixture.guard(&fixture.authorized(), subset).is_ok());
    }

    #[test]
    fn a_fallback_cannot_enable_an_ungated_optimization() {
        let fixture = Fixture::optional();
        let mut proposed = fixture.authorized();
        proposed.loader.insert(Optimization::GpuDirectStorage);
        let violations = fixture.refusal(proposed);
        assert_eq!(
            violations,
            [FallbackViolation::EnablesUngatedOptimization {
                added: BTreeSet::from([Optimization::GpuDirectStorage])
            }]
        );
        assert!(violations[0].to_string().contains("GPUDirect Storage"));
    }

    /// Review finding 1: a fallback could silently drop a required optimization.
    #[test]
    fn a_fallback_never_drops_a_required_optimization() {
        let fixture = Fixture::new(&[
            (Optimization::ZeroCopyPreload, Necessity::Required),
            (Optimization::IoUring, Necessity::Optional),
        ]);
        assert_eq!(
            fixture.plan.required(),
            BTreeSet::from([Optimization::ZeroCopyPreload])
        );
        let mut ordinary = fixture.authorized();
        ordinary.loader.clear();
        let violations = fixture.refusal(ordinary);
        assert_eq!(
            violations,
            [FallbackViolation::DropsRequiredOptimization {
                dropped: BTreeSet::from([Optimization::ZeroCopyPreload])
            }]
        );
        assert!(violations[0]
            .to_string()
            .contains("which this load requires"));

        let mut without_optional = fixture.authorized();
        without_optional.loader.remove(&Optimization::IoUring);
        let approved = fixture
            .guard(&fixture.authorized(), without_optional)
            .unwrap();
        assert_eq!(approved.changes(), &BTreeSet::from([AllowedChange::Loader]));
    }

    /// Review finding 1: the guard trusted a listed loader that never passed the gate.
    #[test]
    fn the_loader_baseline_is_the_plan_not_the_listed_loader() {
        let fixture = Fixture::new(&[(Optimization::ZeroCopyPreload, Necessity::Required)]);
        let never_gated: RuntimeSettings = serde_json::from_value(serde_json::json!({
            "execution_category": "vm_sandbox",
            "network": [],
            "authority": {
                "epoch": 1,
                "clock": fixture.registry.session(),
                "expires_at": 1000
            },
            "artifact_verification": {"verification": "verified", "artifacts": []},
            "loader": ["zero_copy_preload", "sleep_weight_offload", "gpu_direct_storage"],
            "batch_size": 8,
            "residency": "device"
        }))
        .unwrap();
        let mut proposed = never_gated.clone();
        proposed.batch_size = NonZeroU32::new(4).unwrap();
        let violations = fixture
            .guard(&never_gated, proposed)
            .unwrap_err()
            .violations()
            .to_vec();
        assert!(
            violations.contains(&FallbackViolation::EnablesUngatedOptimization {
                added: BTreeSet::from([
                    Optimization::GpuDirectStorage,
                    Optimization::SleepWeightOffload
                ])
            })
        );
        assert!(violations.iter().any(|violation| matches!(
            violation,
            FallbackViolation::IncompatibleModes {
                refusal: ModeRefusal::DocumentedConflict { .. }
            }
        )));
    }

    /// Review finding 1: a plan outlived the evidence behind it.
    #[test]
    fn a_plan_backs_a_fallback_only_while_its_evidence_holds() {
        let mut fixture = Fixture::new(&[(Optimization::ZeroCopyPreload, Necessity::Required)]);
        assert_eq!(
            fixture.plan.valid_until(),
            Some(MonotonicTime::ZERO.saturating_add(MINUTE))
        );
        assert!(fixture
            .guard(&fixture.authorized(), fixture.authorized())
            .is_ok());

        assert_eq!(fixture.registry.invalidate_configuration(config()), 2);
        assert!(matches!(
            fixture.refusal(fixture.authorized()).as_slice(),
            [FallbackViolation::LoaderEvidenceNoLongerHolds {
                optimization: Optimization::ZeroCopyPreload,
                refusal: EvidenceRefusal::Missing { .. },
            }]
        ));

        let subject = Subject::Runtime(runtime());
        fixture
            .registry
            .refresh(Capability::ZeroCopyPreload, &subject)
            .unwrap();
        fixture.clock.advance(MINUTE + Duration::from_nanos(1));
        fixture
            .registry
            .refresh(Capability::ZeroCopyPreload, &subject)
            .unwrap();
        assert!(matches!(
            fixture.refusal(fixture.authorized()).as_slice(),
            [FallbackViolation::LoaderEvidenceNoLongerHolds {
                refusal: EvidenceRefusal::Stale {
                    staleness: Staleness::TooOld { .. },
                    ..
                },
                ..
            }]
        ));
        assert_eq!(
            fixture
                .plan
                .recheck(Optimization::ZeroCopyPreload, &fixture.registry),
            Err(EvidenceRefusal::Stale {
                capability: Capability::ZeroCopyPreload,
                staleness: Staleness::TooOld {
                    age: MINUTE + Duration::from_nanos(1),
                    limit: MINUTE,
                },
            })
        );
    }

    #[test]
    fn loader_batch_and_residency_changes_are_allowed() {
        let fixture = Fixture::optional();
        let mut proposed = fixture.authorized();
        proposed.loader = BTreeSet::new();
        proposed.batch_size = NonZeroU32::new(2).unwrap();
        proposed.residency = Residency::HostPinned;
        let approved = fixture
            .guard(&fixture.authorized(), proposed.clone())
            .unwrap();
        assert_eq!(
            approved.changes(),
            &BTreeSet::from([
                AllowedChange::Loader,
                AllowedChange::BatchSize,
                AllowedChange::Residency
            ])
        );
        assert_eq!(approved.settings(), &proposed);
        assert_eq!(approved.into_settings(), proposed);

        for change in [
            AllowedChange::Loader,
            AllowedChange::BatchSize,
            AllowedChange::Residency,
        ] {
            let mut single = fixture.authorized();
            match change {
                AllowedChange::Loader => {
                    single.loader.remove(&Optimization::IoUring);
                }
                AllowedChange::BatchSize => single.batch_size = NonZeroU32::new(16).unwrap(),
                AllowedChange::Residency => single.residency = Residency::Disk,
            }
            let approved = fixture.guard(&fixture.authorized(), single).unwrap();
            assert_eq!(approved.changes(), &BTreeSet::from([change]));
        }

        let unchanged = fixture
            .guard(&fixture.authorized(), fixture.authorized())
            .unwrap();
        assert!(unchanged.changes().is_empty());
    }

    #[test]
    fn every_forbidden_change_is_reported_together() {
        let fixture = Fixture::new(&[(Optimization::ZeroCopyPreload, Necessity::Required)]);
        let mut proposed = fixture.authorized();
        proposed.execution_category = ExecutionCategory::ProviderContainerRuntime;
        proposed.network.insert(route("anything"));
        proposed.authority.expires_at = MonotonicTime::from_nanos(u64::MAX);
        proposed.artifact_verification = ArtifactVerification::Bypassed;
        proposed.loader = BTreeSet::from([Optimization::GpuDirectStorage]);
        proposed.batch_size = NonZeroU32::new(1).unwrap();
        let refused = fixture.guard(&fixture.authorized(), proposed).unwrap_err();
        assert_eq!(refused.violations().len(), 6);
        let message = refused.to_string();
        for part in [
            "execution category",
            "network grant",
            "renews authority",
            "skip artifact verification",
            "optimization gate",
            "which this load requires",
        ] {
            assert!(message.contains(part), "{message}");
        }
    }

    #[test]
    fn settings_and_violations_round_trip_strictly() {
        let fixture = Fixture::optional();
        let settings = fixture.authorized();
        let json = serde_json::to_value(&settings).unwrap();
        assert_eq!(json["execution_category"], "vm_sandbox");
        assert_eq!(json["artifact_verification"]["verification"], "verified");
        assert_eq!(json["network"][0]["grant"], "named_route");
        assert_eq!(
            serde_json::from_value::<RuntimeSettings>(json.clone()).unwrap(),
            settings
        );
        let mut zero = json.clone();
        zero["batch_size"] = 0.into();
        assert!(serde_json::from_value::<RuntimeSettings>(zero).is_err());
        let mut bypassed = json.clone();
        bypassed["artifact_verification"] =
            serde_json::json!({"verification": "bypassed", "artifacts": []});
        assert!(serde_json::from_value::<RuntimeSettings>(bypassed).is_err());
        let mut no_clock = json;
        no_clock["authority"]
            .as_object_mut()
            .unwrap()
            .remove("clock");
        assert!(serde_json::from_value::<RuntimeSettings>(no_clock).is_err());

        let violation = FallbackViolation::DropsRequiredOptimization {
            dropped: BTreeSet::from([Optimization::ZeroCopyPreload]),
        };
        let mut json = serde_json::to_value(&violation).unwrap();
        assert_eq!(
            serde_json::from_value::<FallbackViolation>(json.clone()).unwrap(),
            violation
        );
        json["waived"] = true.into();
        assert!(serde_json::from_value::<FallbackViolation>(json).is_err());
    }
}
