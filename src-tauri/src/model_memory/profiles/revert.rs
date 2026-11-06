//! FAST-02 response to a failing profile (S13 line 242; S3.5).
//!
//! A profile that fails to start reverts to a known-good profile: a validated FAST-05
//! record that is not withdrawn, still valid for the binding in force, proven in the
//! admitted runtime's category, able to serve the same request mix, and approved by the
//! S3.5 guard against the runtime's approved loader plan. Capacity, tool-semantics and
//! security failures are refusals: nothing smaller, lossier or less confined is tried in
//! their place.

use std::fmt;
use std::num::NonZeroU32;

use serde::{Deserialize, Serialize};

use super::guard::{approve_fallback, AuthorizedRuntime};
use super::record::{
    FailureKind, ProfileId, ProfileNeeds, ProfileRecords, ServingProfileRecord, Unusable,
};
use crate::foundation::evidence::{ApprovedFallback, FallbackRefusal, RuntimeSettings};
use crate::foundation::ids::{Clock, ExecutionCategory};

/// How a profile failed to start.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartupFailure {
    EngineExited,
    /// The engine did not report ready before its deadline.
    NotReady,
    GraphCaptureFailed,
    CommunicatorFailed,
}

/// The resource a capacity failure ran out of.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityResource {
    GpuMemory,
    HostMemory,
    PinnedHostMemory,
}

/// How tool calls lost their semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolSemanticsFailure {
    ParserUnavailable,
    CallsAltered,
    SchemaNotPreserved,
}

/// What a security failure concerned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityFailure {
    ArtifactVerification,
    Authority,
    NetworkGrant,
    Confinement,
}

/// A failure of a running or starting profile (FAST-02).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[serde(remote = "Self")]
pub enum ProfileFailure {
    /// The profile did not start; the only failure that reverts.
    Startup {
        failure: StartupFailure,
    },
    Capacity {
        resource: CapacityResource,
        needed_bytes: u64,
        available_bytes: u64,
    },
    ToolSemantics {
        failure: ToolSemanticsFailure,
    },
    Security {
        failure: SecurityFailure,
    },
}

crate::foundation::strict_serde::strict_tag!(ProfileFailure, "kind");

impl ProfileFailure {
    /// The kind recorded in a profile's history.
    pub const fn kind(&self) -> FailureKind {
        match self {
            Self::Startup { .. } => FailureKind::Startup,
            Self::Capacity { .. } => FailureKind::Capacity,
            Self::ToolSemantics { .. } => FailureKind::ToolSemantics,
            Self::Security { .. } => FailureKind::Security,
        }
    }
}

/// Why a profile was not a revert target.
#[derive(Clone, Debug, PartialEq)]
pub enum Exclusion {
    /// The profile that just failed.
    FailedProfile,
    /// Its concurrent-sequence limit is not a valid batch size.
    InvalidBatchSize,
    /// The S3.5 guard refused the fallback against the approved loader plan.
    Fallback {
        refusal: FallbackRefusal,
    },
    Unusable {
        reason: Unusable,
    },
    /// Known-good too, and a profile proven later was chosen.
    Outranked {
        by: ProfileId,
    },
}

/// One profile that was not a revert target.
#[derive(Clone, Debug, PartialEq)]
pub struct Excluded {
    pub profile: ProfileId,
    pub reason: Exclusion,
}

/// The known-good profile a startup failure reverts to.
#[derive(Clone, Debug, PartialEq)]
pub struct Revert<'a> {
    pub profile: &'a ServingProfileRecord,
    /// The runtime settings the guard approved, exactly as checked.
    pub fallback: ApprovedFallback,
    /// Every other profile, and why it was not chosen.
    pub excluded: Vec<Excluded>,
}

/// Why a failure did not revert.
#[derive(Clone, Debug, PartialEq)]
pub enum RevertRefusal {
    /// Capacity, tool-semantics and security failures are refusals, never a silent
    /// downgrade (FAST-02).
    NotRevertible { failure: ProfileFailure },
    /// The admitted runtime is not the one the authorized settings describe.
    RuntimeMismatch {
        admitted: ExecutionCategory,
        authorized: ExecutionCategory,
    },
    /// No known-good profile in the same authorized execution category.
    NoKnownGood {
        category: ExecutionCategory,
        excluded: Vec<Excluded>,
    },
}

impl fmt::Display for RevertRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRevertible { failure } => write!(
                f,
                "a {:?} failure is refused rather than served by a smaller or weaker profile",
                failure.kind()
            ),
            Self::RuntimeMismatch {
                admitted,
                authorized,
            } => write!(
                f,
                "the admitted runtime is \"{}\" and the authorized settings are for \"{}\"",
                admitted.label(),
                authorized.label()
            ),
            Self::NoKnownGood { category, excluded } => write!(
                f,
                "no known-good profile can replace it within \"{}\"; {} profile(s) were \
                 excluded",
                category.label(),
                excluded.len()
            ),
        }
    }
}

impl std::error::Error for RevertRefusal {}

/// Responds to `failure` of the profile `failed` (`None` for a profile FAST-02 chose
/// without a record).
///
/// Only a startup failure reverts. Each other record is then checked: the guard must
/// approve running it in place of the authorized settings against the approved loader
/// plan, which keeps the authorized execution category, network, authority and verified
/// artifacts; and it must be usable for `needs`. Of the records that pass, the one with
/// the latest proof date is chosen, the lowest identity on a tie. The failure itself goes
/// into the failed profile's history through [`ProfileRecords::report_failure`].
pub fn respond_to_failure<'a, C: Clock>(
    failure: &ProfileFailure,
    failed: Option<&ProfileId>,
    authorized: &AuthorizedRuntime<'_, C>,
    records: &'a ProfileRecords,
    needs: &ProfileNeeds<'_>,
) -> Result<Revert<'a>, RevertRefusal> {
    if !matches!(failure, ProfileFailure::Startup { .. }) {
        return Err(RevertRefusal::NotRevertible { failure: *failure });
    }
    let category = authorized.settings().execution_category;
    if needs.runtime.category() != category {
        return Err(RevertRefusal::RuntimeMismatch {
            admitted: needs.runtime.category(),
            authorized: category,
        });
    }
    let mut excluded = Vec::new();
    let mut eligible = Vec::new();
    for record in records.iter() {
        match known_good(record, failed, authorized, needs) {
            Err(reason) => excluded.push(Excluded {
                profile: record.id(),
                reason,
            }),
            Ok(fallback) => eligible.push((record, fallback)),
        }
    }
    // Records come in identity order: the latest proof wins, the earliest position on a
    // tie, which is the lowest identity.
    let best = eligible
        .iter()
        .enumerate()
        .max_by(|(left_index, (left, _)), (right_index, (right, _))| {
            left.proof_date()
                .cmp(&right.proof_date())
                .then(right_index.cmp(left_index))
        })
        .map(|(index, _)| index);
    let mut chosen = None;
    let mut outranked = Vec::new();
    for (index, (record, fallback)) in eligible.into_iter().enumerate() {
        if Some(index) == best {
            chosen = Some((record, fallback));
        } else {
            outranked.push(record.id());
        }
    }
    let Some((profile, fallback)) = chosen else {
        return Err(RevertRefusal::NoKnownGood { category, excluded });
    };
    excluded.extend(outranked.into_iter().map(|id| Excluded {
        profile: id,
        reason: Exclusion::Outranked { by: profile.id() },
    }));
    excluded.sort_by_key(|excluded| excluded.profile);
    Ok(Revert {
        profile,
        fallback,
        excluded,
    })
}

fn known_good<C: Clock>(
    record: &ServingProfileRecord,
    failed: Option<&ProfileId>,
    authorized: &AuthorizedRuntime<'_, C>,
    needs: &ProfileNeeds<'_>,
) -> Result<ApprovedFallback, Exclusion> {
    if failed == Some(&record.id()) {
        return Err(Exclusion::FailedProfile);
    }
    let batch_size =
        NonZeroU32::new(record.settings().max_num_seqs).ok_or(Exclusion::InvalidBatchSize)?;
    let proposed = RuntimeSettings {
        execution_category: record.execution_category(),
        batch_size,
        ..authorized.settings().clone()
    };
    let fallback = approve_fallback(authorized, proposed)
        .map_err(|refusal| Exclusion::Fallback { refusal })?;
    record
        .usable_for(needs)
        .map_err(|reason| Exclusion::Unusable { reason })?;
    Ok(fallback)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;
    use std::time::Duration;

    use chrono::NaiveDate;

    use crate::foundation::coordination::{Coordinator, LedgerCapacity, ModelId, ModelRefusal};
    use crate::foundation::evidence::fakes::FakeProbe;
    use crate::foundation::evidence::{
        AdmittedRuntime, AllowedChange, ArtifactVerification, AuthorityGrant, Capability,
        EvidencePolicy, FallbackViolation, HostSubject, LoaderGate, LoaderPlan, LoaderRequest,
        Necessity, Observation, Optimization, ProbeRegistry, Residency, RuntimeProfile,
        RuntimeSubject, SourceClass, Subject, SupportDetail,
    };
    use crate::foundation::ids::{AuthorizationEpoch, ExecutionId, ManualClock, MonotonicTime};
    use crate::foundation::ledger::{Ledger, LedgerConfig, QueueLimits};
    use crate::model_memory::backends::{BackendRuntime, ExperimentApproval};
    use crate::model_memory::profiles::record::{PrerequisiteFacts, ProfileBinding};
    use crate::model_memory::profiles::selection::RequestMix;
    use crate::model_memory::profiles::testkit::{
        admitted, approvals, backend_for, binding, configuration, d, draft, mix, parent_execution,
        proof_in, registry_on, runtime, session, start_clock, validate, FakeAuthority,
        NotAuthorized, GIB,
    };

    const SHARED: ExecutionCategory = ExecutionCategory::SharedKernelGpuRuntime;
    const PROVIDER: ExecutionCategory = ExecutionCategory::ProviderContainerRuntime;

    /// The authorized shared-kernel runtime: its registry, gate and approved plan, and the
    /// authority record that holds its settings.
    struct Authorized {
        clock: Arc<ManualClock>,
        registry: ProbeRegistry<Arc<ManualClock>>,
        gate: LoaderGate,
        plan: LoaderPlan,
        authority: FakeAuthority,
    }

    impl Authorized {
        /// The ordinary loader: the plan enables nothing.
        fn ordinary() -> Self {
            Self::planned_for(runtime(SHARED), LoaderRequest::default(), BTreeMap::new())
        }

        /// A plan for `planned`, whose legacy CUDA IPC a host probe has shown working,
        /// fresh for a minute.
        fn planned_for(
            planned: RuntimeSubject,
            request: LoaderRequest,
            permitted: BTreeMap<Optimization, EvidencePolicy>,
        ) -> Self {
            let clock = start_clock();
            let mut registry = registry_on(clock.clone(), &[runtime(SHARED)]);
            let probe = FakeProbe::legacy_cuda_ipc();
            probe.respond(
                &Subject::Runtime(planned.clone()),
                Observation::supported(
                    configuration(),
                    Duration::from_secs(60),
                    SupportDetail::CudaIpcLegacy,
                ),
            );
            registry.register(Box::new(probe)).unwrap();
            registry
                .refresh(
                    Capability::CudaIpcLegacy,
                    &Subject::Runtime(planned.clone()),
                )
                .unwrap();
            let gate = LoaderGate::recorded();
            let profile = RuntimeProfile {
                runtime: planned,
                configuration: configuration(),
                permitted,
            };
            let plan = gate.plan(&profile, &request, &registry).unwrap();
            let settings = RuntimeSettings {
                execution_category: SHARED,
                network: BTreeSet::new(),
                authority: AuthorityGrant {
                    epoch: AuthorizationEpoch::FIRST,
                    clock: registry.session(),
                    expires_at: MonotonicTime::from_nanos(3_600_000_000_000),
                },
                artifact_verification: ArtifactVerification::Verified {
                    artifacts: BTreeSet::from([d("checkpoint")]),
                },
                loader: plan.enabled_set(),
                batch_size: NonZeroU32::MIN,
                residency: Residency::Device,
            };
            Self {
                clock,
                registry,
                gate,
                plan,
                authority: FakeAuthority::of(settings),
            }
        }

        /// The settings the authority record holds.
        fn settings(&self) -> &RuntimeSettings {
            &self.authority.settings
        }

        fn runtime(&self) -> AuthorizedRuntime<'_, Arc<ManualClock>> {
            AuthorizedRuntime::from_authority(
                &self.gate,
                &self.registry,
                &self.plan,
                &self.authority,
                &parent_execution(),
                &d("model"),
            )
            .unwrap()
        }
    }

    /// The binding in force, the admitted shared-kernel runtime and its backend gate with
    /// CUDA graphs and concurrency approved, the mix and the facts.
    struct Context {
        current: ProfileBinding,
        runtime: AdmittedRuntime,
        backend: BackendRuntime,
        approvals: Vec<ExperimentApproval>,
        mix: RequestMix,
        facts: PrerequisiteFacts,
    }

    impl Context {
        fn new() -> Self {
            Self {
                current: binding(),
                runtime: admitted(SHARED),
                backend: backend_for(runtime(SHARED)),
                approvals: approvals(),
                mix: mix(8_192, 1),
                facts: PrerequisiteFacts {
                    peer_access_verified: true,
                    pinned_host_bytes: 8 * GIB,
                    managed_disk_bytes: 100 * GIB,
                },
            }
        }

        fn needs(&self) -> ProfileNeeds<'_> {
            ProfileNeeds {
                current: &self.current,
                runtime: &self.runtime,
                backend: &self.backend,
                approvals: &self.approvals,
                mix: &self.mix,
                facts: &self.facts,
            }
        }
    }

    /// A known-good profile proven in `category` on 2026-10-`day`.
    fn record(category: ExecutionCategory, day: u32) -> ServingProfileRecord {
        let mut draft = draft();
        draft.qualification.execution_category = category;
        draft.proof = proof_in(category);
        draft.proof_date = NaiveDate::from_ymd_opt(2026, 10, day).unwrap();
        validate(draft).unwrap()
    }

    fn records(list: &[&ServingProfileRecord]) -> ProfileRecords {
        let mut records = ProfileRecords::new();
        for record in list {
            records.add((*record).clone()).unwrap();
        }
        records
    }

    fn startup() -> ProfileFailure {
        ProfileFailure::Startup {
            failure: StartupFailure::EngineExited,
        }
    }

    fn excluded_for(excluded: &[Excluded], id: ProfileId) -> &Exclusion {
        &excluded
            .iter()
            .find(|excluded| excluded.profile == id)
            .unwrap()
            .reason
    }

    #[test]
    fn a_startup_failure_reverts_to_a_known_good_profile_in_the_same_category() {
        let older = record(SHARED, 20);
        let newer = record(SHARED, 25);
        let provider = record(PROVIDER, 26);
        let records = records(&[&older, &newer, &provider]);
        let (authorized, context) = (Authorized::ordinary(), Context::new());
        let revert = respond_to_failure(
            &startup(),
            None,
            &authorized.runtime(),
            &records,
            &context.needs(),
        )
        .unwrap();
        assert_eq!(revert.profile.id(), newer.id());
        let settings = revert.fallback.settings();
        assert_eq!(settings.execution_category, SHARED);
        assert_eq!(settings.batch_size.get(), 4);
        assert_eq!(settings.network, authorized.settings().network);
        assert_eq!(settings.authority, authorized.settings().authority);
        assert_eq!(
            revert.fallback.changes(),
            &BTreeSet::from([AllowedChange::BatchSize])
        );
        assert_eq!(
            excluded_for(&revert.excluded, older.id()),
            &Exclusion::Outranked { by: newer.id() }
        );
        // Proven later, but in another category: the guard refuses it.
        let Exclusion::Fallback { refusal } = excluded_for(&revert.excluded, provider.id()) else {
            panic!("expected the guard to refuse the provider-container profile");
        };
        assert_eq!(
            refusal.violations(),
            &[FallbackViolation::ChangesExecutionCategory {
                from: SHARED,
                to: PROVIDER
            }]
        );
    }

    #[test]
    fn a_revert_never_leaves_the_category() {
        let provider = record(PROVIDER, 26);
        let records = records(&[&provider]);
        let (authorized, context) = (Authorized::ordinary(), Context::new());
        let Err(RevertRefusal::NoKnownGood { category, excluded }) = respond_to_failure(
            &startup(),
            None,
            &authorized.runtime(),
            &records,
            &context.needs(),
        ) else {
            panic!("expected no known-good profile");
        };
        assert_eq!(category, SHARED);
        assert_eq!(excluded.len(), 1);
        assert!(matches!(
            excluded_for(&excluded, provider.id()),
            Exclusion::Fallback { .. }
        ));
    }

    #[test]
    fn capacity_tool_and_security_failures_refuse() {
        let known_good = record(SHARED, 25);
        let records = records(&[&known_good]);
        let (authorized, context) = (Authorized::ordinary(), Context::new());
        for failure in [
            ProfileFailure::Capacity {
                resource: CapacityResource::GpuMemory,
                needed_bytes: 25 * GIB,
                available_bytes: 24 * GIB,
            },
            ProfileFailure::ToolSemantics {
                failure: ToolSemanticsFailure::CallsAltered,
            },
            ProfileFailure::Security {
                failure: SecurityFailure::ArtifactVerification,
            },
        ] {
            assert_eq!(
                respond_to_failure(
                    &failure,
                    None,
                    &authorized.runtime(),
                    &records,
                    &context.needs()
                ),
                Err(RevertRefusal::NotRevertible { failure }),
                "{failure:?}"
            );
        }
        // The same records do give a revert for a startup failure.
        assert!(respond_to_failure(
            &startup(),
            None,
            &authorized.runtime(),
            &records,
            &context.needs()
        )
        .is_ok());
    }

    #[test]
    fn a_withdrawn_or_failed_profile_is_never_a_revert_target() {
        let failed = record(SHARED, 25);
        let withdrawn = record(SHARED, 20);
        let mut records = records(&[&failed, &withdrawn]);
        records
            .report_failure(&withdrawn.id(), d("failure 1"), FailureKind::Startup)
            .unwrap();
        records
            .report_failure(&withdrawn.id(), d("failure 2"), FailureKind::Startup)
            .unwrap();
        let (authorized, context) = (Authorized::ordinary(), Context::new());
        let Err(RevertRefusal::NoKnownGood { excluded, .. }) = respond_to_failure(
            &startup(),
            Some(&failed.id()),
            &authorized.runtime(),
            &records,
            &context.needs(),
        ) else {
            panic!("expected no known-good profile");
        };
        assert_eq!(
            excluded_for(&excluded, failed.id()),
            &Exclusion::FailedProfile
        );
        assert_eq!(
            excluded_for(&excluded, withdrawn.id()),
            &Exclusion::Unusable {
                reason: Unusable::Withdrawn
            }
        );
    }

    #[test]
    fn a_known_good_profile_needing_an_unapproved_technique_is_not_used() {
        // The known-good profile captures CUDA graphs and runs 4 sequences.
        let known_good = record(SHARED, 25);
        let records = records(&[&known_good]);
        let authorized = Authorized::ordinary();
        let mut context = Context::new();
        context.approvals.clear();
        let Err(RevertRefusal::NoKnownGood { excluded, .. }) = respond_to_failure(
            &startup(),
            None,
            &authorized.runtime(),
            &records,
            &context.needs(),
        ) else {
            panic!("expected no known-good profile");
        };
        assert!(matches!(
            excluded_for(&excluded, known_good.id()),
            Exclusion::Unusable {
                reason: Unusable::TechniqueNotAdmitted { .. }
            }
        ));
    }

    #[test]
    fn a_known_good_profile_that_cannot_serve_the_mix_is_not_used() {
        let known_good = record(SHARED, 25);
        let records = records(&[&known_good]);
        let authorized = Authorized::ordinary();
        let mut context = Context::new();
        context.mix = mix(32_768, 1);
        let Err(RevertRefusal::NoKnownGood { excluded, .. }) = respond_to_failure(
            &startup(),
            None,
            &authorized.runtime(),
            &records,
            &context.needs(),
        ) else {
            panic!("expected no known-good profile");
        };
        assert_eq!(
            excluded_for(&excluded, known_good.id()),
            &Exclusion::Unusable {
                reason: Unusable::ContextTooShort {
                    context_tokens: 16_384,
                    needed_tokens: 32_768
                }
            }
        );
    }

    #[test]
    fn the_revert_is_checked_against_the_approved_loader_plan() {
        let permitted = BTreeMap::from([(
            Optimization::CudaIpcLegacy,
            EvidencePolicy {
                minimum_source: SourceClass::GuestReport,
                max_age: Duration::from_secs(60),
            },
        )]);
        let request = LoaderRequest {
            optimizations: BTreeMap::from([(Optimization::CudaIpcLegacy, Necessity::Required)]),
        };
        let authorized = Authorized::planned_for(runtime(SHARED), request, permitted);
        assert_eq!(
            authorized.settings().loader,
            BTreeSet::from([Optimization::CudaIpcLegacy])
        );
        let known_good = record(SHARED, 25);
        let records = records(&[&known_good]);
        let context = Context::new();
        let revert = respond_to_failure(
            &startup(),
            None,
            &authorized.runtime(),
            &records,
            &context.needs(),
        )
        .unwrap();
        assert_eq!(
            revert.fallback.settings().loader,
            BTreeSet::from([Optimization::CudaIpcLegacy])
        );
        // Once the evidence behind the plan's required optimization is stale, no
        // fallback is approved: the load has to be planned again.
        authorized.clock.advance(Duration::from_secs(61));
        let Err(RevertRefusal::NoKnownGood { excluded, .. }) = respond_to_failure(
            &startup(),
            None,
            &authorized.runtime(),
            &records,
            &context.needs(),
        ) else {
            panic!("expected no known-good profile");
        };
        let Exclusion::Fallback { refusal } = excluded_for(&excluded, known_good.id()) else {
            panic!("expected the guard to refuse");
        };
        assert!(matches!(
            refusal.violations(),
            [FallbackViolation::LoaderEvidenceNoLongerHolds {
                optimization: Optimization::CudaIpcLegacy,
                ..
            }]
        ));
    }

    #[test]
    fn a_plan_for_another_runtime_approves_no_revert() {
        let authorized =
            Authorized::planned_for(runtime(PROVIDER), LoaderRequest::default(), BTreeMap::new());
        let known_good = record(SHARED, 25);
        let records = records(&[&known_good]);
        let context = Context::new();
        let Err(RevertRefusal::NoKnownGood { excluded, .. }) = respond_to_failure(
            &startup(),
            None,
            &authorized.runtime(),
            &records,
            &context.needs(),
        ) else {
            panic!("expected no known-good profile");
        };
        let Exclusion::Fallback { refusal } = excluded_for(&excluded, known_good.id()) else {
            panic!("expected the guard to refuse");
        };
        assert_eq!(
            refusal.violations(),
            &[FallbackViolation::PlanForAnotherRuntime {
                plan: PROVIDER,
                authorized: SHARED
            }]
        );
    }

    #[test]
    fn the_admitted_runtime_must_be_the_authorized_one() {
        let known_good = record(SHARED, 25);
        let records = records(&[&known_good]);
        let authorized = Authorized::ordinary();
        let mut context = Context::new();
        context.runtime = admitted(PROVIDER);
        context.backend = backend_for(runtime(PROVIDER));
        assert_eq!(
            respond_to_failure(
                &startup(),
                None,
                &authorized.runtime(),
                &records,
                &context.needs()
            ),
            Err(RevertRefusal::RuntimeMismatch {
                admitted: PROVIDER,
                authorized: SHARED
            })
        );
    }

    #[test]
    fn failures_are_read_strictly_and_recorded_by_kind() {
        let startup_json = r#"{"kind":"startup","failure":"engine_exited"}"#;
        assert_eq!(
            serde_json::from_str::<ProfileFailure>(startup_json).unwrap(),
            startup()
        );
        assert_eq!(serde_json::to_string(&startup()).unwrap(), startup_json);
        assert!(serde_json::from_str::<ProfileFailure>(
            r#"{"kind":"startup","failure":"engine_exited","retry":true}"#
        )
        .is_err());
        assert_eq!(startup().kind(), FailureKind::Startup);
        assert_eq!(
            ProfileFailure::Security {
                failure: SecurityFailure::Authority
            }
            .kind(),
            FailureKind::Security
        );
    }

    #[test]
    fn the_authorized_settings_come_from_the_authority_record() {
        let authorized = Authorized::ordinary();
        let from = |execution: &ExecutionId, model| {
            AuthorizedRuntime::from_authority(
                &authorized.gate,
                &authorized.registry,
                &authorized.plan,
                &authorized.authority,
                execution,
                &model,
            )
            .map(|runtime| runtime.settings().clone())
        };
        // The record holds settings for its own model under its own parent only.
        assert_eq!(
            from(&parent_execution(), d("model")),
            Ok(authorized.settings().clone())
        );
        assert_eq!(
            from(&ExecutionId::new("exe-other-parent").unwrap(), d("model")),
            Err(NotAuthorized)
        );
        assert_eq!(
            from(&parent_execution(), d("other model")),
            Err(NotAuthorized)
        );
        // A revert is judged against what the record holds: a later expiry there is the
        // one the approved fallback keeps.
        let mut later = Authorized::ordinary();
        later.authority.settings.authority.expires_at =
            MonotonicTime::from_nanos(7_200_000_000_000);
        let known_good = record(SHARED, 25);
        let records = records(&[&known_good]);
        let context = Context::new();
        let revert = respond_to_failure(
            &startup(),
            None,
            &later.runtime(),
            &records,
            &context.needs(),
        )
        .unwrap();
        assert_eq!(
            revert.fallback.settings().authority,
            later.settings().authority
        );
    }

    #[test]
    fn the_coordinator_is_the_authority_record() {
        let clock = start_clock();
        let ledger = Ledger::new(
            clock.clone(),
            HostSubject {
                machine: d("machine"),
            },
            LedgerConfig {
                queue: QueueLimits {
                    max_entries: 8,
                    max_entries_per_tenant: 4,
                    max_wait: Duration::from_secs(60),
                },
                grant_ttl: Duration::from_secs(300),
                unmanaged_usage_max_age: Duration::from_secs(3600),
            },
        );
        let coordinator = Coordinator::new(clock, session(), LedgerCapacity::new(ledger));
        let authorized = Authorized::ordinary();
        // A parent the coordinator never launched holds no authority, so no settings are
        // authorized and nothing can be reverted to.
        assert!(matches!(
            AuthorizedRuntime::from_authority(
                &authorized.gate,
                &authorized.registry,
                &authorized.plan,
                &coordinator,
                &parent_execution(),
                &ModelId::new(d("model")),
            ),
            Err(ModelRefusal::Parent { .. })
        ));
    }
}
