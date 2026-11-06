//! Launch records and lifecycle measurements as assurance-ledger claims (S2 CORE-01 and
//! CORE-08 rows, lines 210 and 217; VM part §8.1 lines 2433–2439: evidence records, not
//! certificates, re-evaluated after configuration changes; VM-W52; VM-P01 line 2776;
//! VM-P14 line 2789; VM-P50 line 2825; VM-CP-01 line 3151; VM-CP-14 line 3164; VM-CP-35
//! line 3185).
//!
//! A VM-P01 claim cites the CORE-01 hypervisor evidence a launch record was admitted
//! on, as a probe citation the ledger re-evaluates against the live registry: once the
//! evidence is older than the record's required freshness, superseded, or observed under
//! another configuration than the one in force, the claim is invalidated, and a changed
//! ledger configuration invalidates it outright. A record of the fake backend certifies
//! nothing and backs no claim (S2 line 206), and a measurement on the fake substrate is
//! refused by the ledger itself (VM-P50). A VM-P14 claim cites the four stop-phase
//! distributions as CORE-08 test records, each bound to its configuration, with the
//! two-second figure held as a target and never as a guarantee (§6.5).

use std::collections::BTreeSet;
use std::fmt;

use serde::Serialize;

use crate::foundation::events::EvidenceLink;
use crate::foundation::evidence::{ConfigurationFingerprint, HypervisorSubject, Subject};
use crate::foundation::ids::{digest, Digest, ExecutionCategory, IdError};
use crate::foundation::report::{ReportError, RunSubstrate};
use crate::sandbox::audit::{
    AssumptionId, Citation, Claim, ClaimId, ClaimSupport, LedgerError, ProbeCitation, ProfileId,
    Property, RiskId, TestCitation, TestId,
};
use crate::sandbox::backend::{Accelerator, BackendKind, LaunchRecord};
use crate::sandbox::lifecycle::{
    KillMeasurements, PhaseSummary, StopPhase, TargetAssessment, STOP_TARGET,
};

/// The digest domain of a measurement record cited as CORE-08 evidence.
pub const MEASUREMENT_RECORD_DOMAIN: &str = "yougori/sandbox/integration/measurement-record/v1";

/// What every claim names beside its evidence: its identity, the profile it is about,
/// the assumptions it rests on and the residual risks it leaves (VM-W52).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimParts {
    pub id: ClaimId,
    pub profile: ProfileId,
    pub assumptions: BTreeSet<AssumptionId>,
    pub residual_risks: BTreeSet<RiskId>,
}

/// Why a record or a measurement backs no claim.
#[derive(Clone, Debug, PartialEq)]
pub enum ClaimRefusal {
    /// The record is the fake backend's; it certifies nothing (S2 line 206).
    FakeBackend {
        backend: BackendKind,
    },
    /// The record's accelerator is not hardware virtualization; no VM-only claim.
    NotHardwareVirtualized {
        observed: Accelerator,
    },
    /// The record's hypervisor evidence is not about this machine's hypervisor.
    EvidenceSubjectMismatch {
        cited: Digest,
        expected: Digest,
    },
    /// A stop phase has no successful sample, so the phase was not measured.
    NotMeasured {
        phase: StopPhase,
    },
    Ledger(LedgerError),
    Report(ReportError),
    Identifier(IdError),
    Encoding {
        detail: String,
    },
}

impl fmt::Display for ClaimRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FakeBackend { backend } => {
                write!(f, "a launch record of the {backend} certifies nothing")
            }
            Self::NotHardwareVirtualized { observed } => {
                write!(
                    f,
                    "the VM runs under {observed}; no VM-only execution claim"
                )
            }
            Self::EvidenceSubjectMismatch { .. } => f.write_str(
                "the record's hypervisor evidence is not about this machine's hypervisor",
            ),
            Self::NotMeasured { phase } => write!(f, "the {phase} phase was not measured"),
            Self::Ledger(error) => write!(f, "{error}"),
            Self::Report(error) => write!(f, "{error}"),
            Self::Identifier(error) => write!(f, "{error}"),
            Self::Encoding { detail } => write!(f, "the record could not be encoded: {detail}"),
        }
    }
}

impl std::error::Error for ClaimRefusal {}

impl From<LedgerError> for ClaimRefusal {
    fn from(error: LedgerError) -> Self {
        Self::Ledger(error)
    }
}

impl From<ReportError> for ClaimRefusal {
    fn from(error: ReportError) -> Self {
        Self::Report(error)
    }
}

/// The CORE-01 hypervisor evidence of `record`, as a probe citation the ledger can
/// re-evaluate: the link names the envelope exactly, the subject is this machine's
/// hypervisor, and the age the claim tolerates is the record's required freshness.
pub fn hypervisor_citation(
    record: &LaunchRecord,
    machine: Digest,
) -> Result<ProbeCitation, ClaimRefusal> {
    if record.backend().kind.is_fake() {
        return Err(ClaimRefusal::FakeBackend {
            backend: record.backend().kind,
        });
    }
    let observed = *record.accelerator().value();
    if !observed.is_hardware_virtualized() {
        return Err(ClaimRefusal::NotHardwareVirtualized { observed });
    }
    let subject = Subject::Hypervisor(HypervisorSubject {
        machine,
        hypervisor: record.backend().hypervisor,
    });
    let evidence = record.hypervisor_evidence();
    if evidence.subject() != subject.identity() {
        return Err(ClaimRefusal::EvidenceSubjectMismatch {
            cited: evidence.subject(),
            expected: subject.identity(),
        });
    }
    Ok(ProbeCitation {
        link: EvidenceLink {
            capability: evidence.capability(),
            subject: evidence.subject(),
            configuration: evidence.configuration(),
            source: evidence.source(),
            clock: record.clock(),
            observed_at: evidence.observed_at(),
        },
        subject,
        max_age: record.required().evidence.max_age,
    })
}

/// The VM-P01 claim "VM-only execution" for the configuration `record` was admitted
/// under, backed by the record's hypervisor evidence (VM-CP-01: the record names a
/// hardware accelerator).
pub fn vm_only_execution_claim(
    record: &LaunchRecord,
    machine: Digest,
    parts: ClaimParts,
) -> Result<Claim, ClaimRefusal> {
    let citation = hypervisor_citation(record, machine)?;
    Ok(Claim::new(
        parts.id,
        Property::VmOnlyExecution,
        ExecutionCategory::VmSandbox,
        parts.profile,
        record.configuration(),
        parts.assumptions,
        parts.residual_risks,
        ClaimSupport::Evidence {
            citations: vec![Citation::Probe(citation)],
        },
    )?)
}

/// One stop phase's distribution as a CORE-08 record: the summary, the target
/// assessment where the phase has one, and the citation of their digest.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct MeasurementCitation {
    pub phase: StopPhase,
    pub summary: PhaseSummary,
    /// The §6.5 target held against the summary, for the VM stop phase only.
    pub assessment: Option<TargetAssessment>,
    pub citation: TestCitation,
}

const fn phase_test_id(phase: StopPhase) -> &'static str {
    match phase {
        StopPhase::RevokeToDeny => "vm-p14-revoke-to-deny",
        StopPhase::ChannelClose => "vm-p14-channel-close",
        StopPhase::VmStop => "vm-p14-vm-stop",
        StopPhase::Cleanup => "vm-p14-cleanup",
    }
}

/// The four stop phases of `measurements` as CORE-08 test citations bound to
/// `configuration` and `substrate` (VM-CP-14: five times measured separately, p50, p95
/// and p99 recorded, the target reported as a target). A phase without a successful
/// sample is refused: an unmeasured phase is not evidence.
pub fn measurement_citations(
    measurements: &KillMeasurements,
    configuration: ConfigurationFingerprint,
    substrate: RunSubstrate,
) -> Result<Vec<MeasurementCitation>, ClaimRefusal> {
    let mut citations = Vec::with_capacity(StopPhase::ALL.len());
    for phase in StopPhase::ALL {
        let summary = measurements.summarize(phase)?;
        if summary.successes == 0 {
            return Err(ClaimRefusal::NotMeasured { phase });
        }
        let assessment =
            (phase == STOP_TARGET.phase).then(|| TargetAssessment::of(&summary, STOP_TARGET));
        let summary_bytes = encode(&summary)?;
        let assessment_bytes = encode(&assessment)?;
        let record = digest(
            MEASUREMENT_RECORD_DOMAIN,
            &[
                phase_test_id(phase).as_bytes(),
                &summary_bytes,
                &assessment_bytes,
            ],
        );
        citations.push(MeasurementCitation {
            phase,
            citation: TestCitation {
                test: TestId::new(phase_test_id(phase)).map_err(ClaimRefusal::Identifier)?,
                record,
                configuration,
                substrate: substrate.clone(),
            },
            summary,
            assessment,
        });
    }
    Ok(citations)
}

/// The VM-P14 claim "revocation measured separately", backed by the four phase records.
/// The ledger refuses it on the fake substrate (VM-P50) and invalidates it when the
/// configuration changes.
pub fn revocation_claim(
    measurements: &KillMeasurements,
    configuration: ConfigurationFingerprint,
    substrate: RunSubstrate,
    parts: ClaimParts,
) -> Result<Claim, ClaimRefusal> {
    let citations = measurement_citations(measurements, configuration, substrate)?
        .into_iter()
        .map(|measured| Citation::Test(measured.citation))
        .collect();
    Ok(Claim::new(
        parts.id,
        Property::Revocation,
        ExecutionCategory::VmSandbox,
        parts.profile,
        configuration,
        parts.assumptions,
        parts.residual_risks,
        ClaimSupport::Evidence { citations },
    )?)
}

/// The canonical JSON of one value, for a record digest.
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, ClaimRefusal> {
    serde_json::to_vec(value).map_err(|error| ClaimRefusal::Encoding {
        detail: error.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::ExecutionId;
    use crate::foundation::report::Label;
    use crate::sandbox::lifecycle::{PhaseFailure, PhaseSample, StopFailureCause};

    fn parts(id: &str) -> ClaimParts {
        ClaimParts {
            id: ClaimId::new(id).unwrap(),
            profile: ProfileId::new("local-containment").unwrap(),
            assumptions: BTreeSet::from([AssumptionId::new("host-admin").unwrap()]),
            residual_risks: BTreeSet::from([RiskId::new("unknown-escape").unwrap()]),
        }
    }

    fn sample(phase: StopPhase, millis: u64) -> PhaseSample {
        PhaseSample {
            execution: ExecutionId::new("exe-a").unwrap(),
            phase,
            nanos: millis * 1_000_000,
            burst: 0,
        }
    }

    fn configuration() -> ConfigurationFingerprint {
        ConfigurationFingerprint::from_settings([("host", "a")]).unwrap()
    }

    #[test]
    fn every_phase_must_be_measured_and_the_fake_substrate_backs_no_claim() {
        let mut measurements = KillMeasurements::new();
        for phase in [
            StopPhase::RevokeToDeny,
            StopPhase::ChannelClose,
            StopPhase::VmStop,
        ] {
            measurements.record(sample(phase, 100));
        }
        assert_eq!(
            measurement_citations(
                &measurements,
                configuration(),
                RunSubstrate::FakeTimeControlled
            )
            .err(),
            Some(ClaimRefusal::NotMeasured {
                phase: StopPhase::Cleanup
            })
        );
        measurements.record(sample(StopPhase::Cleanup, 5_000));
        let citations = measurement_citations(
            &measurements,
            configuration(),
            RunSubstrate::FakeTimeControlled,
        )
        .unwrap();
        assert_eq!(citations.len(), 4);
        let stop = citations
            .iter()
            .find(|citation| citation.phase == StopPhase::VmStop)
            .unwrap();
        let assessment = stop.assessment.as_ref().unwrap();
        assert_eq!(assessment.within_target, Some(true));
        assert_eq!(
            assessment.claim,
            crate::sandbox::lifecycle::TargetClaim::ObservationUnderTestLoad
        );
        assert!(citations
            .iter()
            .filter(|citation| citation.phase != StopPhase::VmStop)
            .all(|citation| citation.assessment.is_none()));
        assert_eq!(stop.citation.test.as_str(), "vm-p14-vm-stop");
        // The fake substrate is refused by the ledger's own rule (VM-P50).
        assert!(matches!(
            revocation_claim(
                &measurements,
                configuration(),
                RunSubstrate::FakeTimeControlled,
                parts("rev")
            ),
            Err(ClaimRefusal::Ledger(
                LedgerError::FakeSubstrateIsNotEvidence { .. }
            ))
        ));
        let authorized = RunSubstrate::AuthorizedDisposable {
            authorization: Label::new("drill-7").unwrap(),
        };
        let claim = revocation_claim(
            &measurements,
            configuration(),
            authorized.clone(),
            parts("rev"),
        )
        .unwrap();
        assert_eq!(claim.property(), Property::Revocation);
        assert!(matches!(
            claim.support(),
            ClaimSupport::Evidence { citations } if citations.len() == 4
        ));
        // A failure changes the record digest: the citation names what was measured.
        let before =
            measurement_citations(&measurements, configuration(), authorized.clone()).unwrap();
        measurements.record_failure(PhaseFailure {
            execution: ExecutionId::new("exe-b").unwrap(),
            phase: StopPhase::VmStop,
            cause: StopFailureCause::BackendStalled,
        });
        let after = measurement_citations(&measurements, configuration(), authorized).unwrap();
        assert_ne!(before[2].citation.record, after[2].citation.record);
        assert_eq!(before[0].citation.record, after[0].citation.record);
        assert_eq!(
            after[2].assessment.as_ref().unwrap().within_target,
            Some(false)
        );
    }

    #[test]
    fn refusals_are_typed_and_displayed() {
        assert!(ClaimRefusal::FakeBackend {
            backend: BackendKind::Fake
        }
        .to_string()
        .contains("certifies nothing"));
        assert!(ClaimRefusal::NotMeasured {
            phase: StopPhase::Cleanup
        }
        .to_string()
        .contains("cleanup"));
        assert_eq!(
            ClaimRefusal::from(LedgerError::UnknownClaim {
                claim: ClaimId::new("c").unwrap()
            })
            .to_string(),
            "claim c is not in the ledger"
        );
    }
}
