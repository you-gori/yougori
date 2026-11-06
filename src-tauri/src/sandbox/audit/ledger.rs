//! The VM assurance ledger (VM-W52 at line 2502: claims linked to assumptions,
//! configurations, tests and residual risks on CORE-01 evidence identities; every release
//! claim has evidence or an explicit gap; stale evidence invalidates the affected claim;
//! no aggregate probability fabricated from surface counts; no generic secure badge.
//! §8.1 at lines 2258–2264: evidence records, not security certificates; re-evaluate
//! evidence after configuration changes. §1.1–§1.2 at lines 1696–1717 name the
//! assumptions and the claims the design does not make. VM-P50 at line 2652: a skipped
//! test, a stale probe or a guest-only observation cannot become a green claim.)
//!
//! A [`Claim`] names a property of one profile under one configuration, the assumptions
//! it rests on, the residual risks it leaves, and either citations of evidence or an
//! [`ExplicitGap`]. Probe citations are CORE-01 [`EvidenceLink`]s checked against the
//! live registry through the [`EvidenceCheck`] port; test citations are CORE-08 record
//! digests bound to the configuration they ran under; release citations are CORE-08
//! [`ReleaseRequirement`]s, which already refuse evidence that is not Yougori's own
//! measurement. [`AssuranceLedger::status`] is the only judgement the ledger makes, one
//! claim at a time; the [`LedgerSummary`] counts statuses and computes nothing from them.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::foundation::events::EvidenceLink;
use crate::foundation::evidence::{
    Capability, ConfigurationFingerprint, EvidenceRefusal, ProbeRegistry, Requirement, Staleness,
    Subject,
};
use crate::foundation::ids::{Clock, Digest, ExecutionCategory, MonotonicTime};
use crate::foundation::report::{NonNegative, RecordStatistic, ReleaseRequirement, RunSubstrate};

identifier_type!(
    /// One claim of the ledger.
    ClaimId
);
identifier_type!(
    /// One assumption claims rest on.
    AssumptionId
);
identifier_type!(
    /// One residual risk claims leave.
    RiskId
);
identifier_type!(
    /// One test or scenario run, as CORE-08 names it.
    TestId
);
identifier_type!(
    /// The sandbox profile a claim is about, such as the local containment profile.
    ProfileId
);

/// The property a claim is about: one scenario family of §12.2 (lines 2600–2650).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Property {
    VmOnlyExecution,
    MinimalConfiguration,
    HostExposure,
    HypervisorConfinement,
    ExtraGuestRestrictions,
    DefaultEgressDenial,
    DnsPolicy,
    AddressPolicy,
    ProxyBypass,
    ApplicationProtocol,
    IndependentPerimeter,
    CredentialBoundary,
    Delegation,
    Revocation,
    FilesystemBoundary,
    ArtifactPromotion,
    Persistence,
    Lifetime,
    ProcessFailure,
    Resources,
    SnapshotFreshness,
    Audit,
    SupplyChain,
    ResponseAndRecovery,
    EndToEndWorkflow,
}

impl Property {
    /// The §12.2 scenario id.
    pub const fn scenario(self) -> &'static str {
        match self {
            Self::VmOnlyExecution => "VM-P01",
            Self::MinimalConfiguration => "VM-P02",
            Self::HostExposure => "VM-P03",
            Self::HypervisorConfinement => "VM-P04",
            Self::ExtraGuestRestrictions => "VM-P05",
            Self::DefaultEgressDenial => "VM-P06",
            Self::DnsPolicy => "VM-P07",
            Self::AddressPolicy => "VM-P08",
            Self::ProxyBypass => "VM-P09",
            Self::ApplicationProtocol => "VM-P10",
            Self::IndependentPerimeter => "VM-P11",
            Self::CredentialBoundary => "VM-P12",
            Self::Delegation => "VM-P13",
            Self::Revocation => "VM-P14",
            Self::FilesystemBoundary => "VM-P15",
            Self::ArtifactPromotion => "VM-P16",
            Self::Persistence => "VM-P17",
            Self::Lifetime => "VM-P18",
            Self::ProcessFailure => "VM-P19",
            Self::Resources => "VM-P20",
            Self::SnapshotFreshness => "VM-P21",
            Self::Audit => "VM-P22",
            Self::SupplyChain => "VM-P23",
            Self::ResponseAndRecovery => "VM-P24",
            Self::EndToEndWorkflow => "VM-P25",
        }
    }
}

impl fmt::Display for Property {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.scenario())
    }
}

/// What the local containment profile assumes (§1.1 line 1708).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssumptionKind {
    HostAdministratorTrusted,
    PlatformKernelTrusted,
    HardwareTrusted,
    ControlPlaneImplementationTrusted,
    /// Not assumed by a confidential-computing profile, which needs its own attestation
    /// policy (§1.1 line 1708).
    CloudOperatorTrusted,
}

/// What the design does not claim to prevent (§1.2 lines 1712–1716).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskKind {
    PromptInjection,
    MaliciousDependencies,
    DamagingActionsWithinGrantedAuthority,
    DisclosureThroughAuthorizedOutput,
    SharedHardwareSideChannels,
    /// A probe suite cannot prove no unknown escape exists (§8.1 line 2262).
    UnknownEscape,
    ScannerCannotProveCodeSafe,
    AttestationDoesNotProveBehavior,
    /// Inner-container restrictions are not a mandatory exploit step (§1.2 line 1716).
    InnerContainerNotMandatoryStep,
}

/// A CORE-01 observation cited as evidence: the link that names it exactly, the subject
/// it is about (so it can be re-evaluated) and the age the claim tolerates.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeCitation {
    pub link: EvidenceLink,
    pub subject: Subject,
    pub max_age: Duration,
}

/// A CORE-08 test or scenario record cited as evidence, bound to the configuration it ran
/// under; a changed configuration invalidates it (§8.1 line 2264).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestCitation {
    pub test: TestId,
    /// The digest of the CORE-08 record.
    pub record: Digest,
    pub configuration: ConfigurationFingerprint,
    pub substrate: RunSubstrate,
}

/// A CORE-08 release requirement cited as evidence. Built only from a
/// [`ReleaseRequirement`], which binds its threshold to a Yougori measurement; it is
/// never read back.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ReleaseCitation {
    statistic: RecordStatistic,
    threshold: NonNegative,
    evidence: Digest,
}

impl ReleaseCitation {
    pub fn of(requirement: &ReleaseRequirement) -> Self {
        Self {
            statistic: requirement.statistic(),
            threshold: requirement.threshold(),
            evidence: requirement.evidence(),
        }
    }

    pub fn statistic(&self) -> RecordStatistic {
        self.statistic
    }

    pub fn threshold(&self) -> NonNegative {
        self.threshold
    }

    pub fn evidence(&self) -> Digest {
        self.evidence
    }
}

/// One piece of evidence a claim cites.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Citation {
    Probe(ProbeCitation),
    Test(TestCitation),
    Release(ReleaseCitation),
}

/// Why a claim has no evidence yet (VM-W52 "an explicit gap"; VM-P50).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapReason {
    /// The check was not run: "not tested", never a pass.
    NotTested,
    /// The hardware the check needs was unavailable: "not tested", never a pass.
    HardwareUnavailable,
    /// A known blind spot of the probe suite (§8.1 line 2262).
    BlindSpot,
    /// Only a guest report exists, which cannot certify host enforcement.
    GuestOnlyObservation,
    /// Evidence is being produced.
    EvidencePending,
}

impl fmt::Display for GapReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotTested => "not tested",
            Self::HardwareUnavailable => "hardware unavailable, so not tested",
            Self::BlindSpot => "a known blind spot of the probe suite",
            Self::GuestOnlyObservation => "only a guest-reported observation exists",
            Self::EvidencePending => "evidence pending",
        })
    }
}

/// A gap stated instead of evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExplicitGap {
    pub reason: GapReason,
}

/// What backs a claim: evidence, or an explicit gap. Never neither.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "support", rename_all = "snake_case")]
pub enum ClaimSupport {
    Evidence { citations: Vec<Citation> },
    Gap { gap: ExplicitGap },
}

/// Why the ledger refused a claim, an assumption or a risk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerError {
    /// Evidence support with no citation: a claim is backed by evidence or states a gap.
    NoEvidence {
        claim: ClaimId,
    },
    NoAssumptions {
        claim: ClaimId,
    },
    NoResidualRisks {
        claim: ClaimId,
    },
    /// A test on the fake, time-controlled substrate backs no claim (S12 G0).
    FakeSubstrateIsNotEvidence {
        claim: ClaimId,
        test: TestId,
    },
    /// The cited link and subject disagree.
    CitationSubjectMismatch {
        claim: ClaimId,
    },
    /// The cited observation comes from a weaker source than the capability ever accepts,
    /// such as a guest report for a host-only capability (VM-P50).
    SourceTooWeak {
        claim: ClaimId,
        capability: Capability,
    },
    UnknownAssumption {
        assumption: AssumptionId,
    },
    UnknownRisk {
        risk: RiskId,
    },
    UnknownClaim {
        claim: ClaimId,
    },
    DuplicateClaim {
        claim: ClaimId,
    },
    DuplicateAssumption {
        assumption: AssumptionId,
    },
    DuplicateRisk {
        risk: RiskId,
    },
}

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoEvidence { claim } => write!(
                f,
                "claim {claim} cites no evidence; cite evidence or state an explicit gap"
            ),
            Self::NoAssumptions { claim } => {
                write!(f, "claim {claim} names no assumption it rests on")
            }
            Self::NoResidualRisks { claim } => {
                write!(f, "claim {claim} names no residual risk it leaves")
            }
            Self::FakeSubstrateIsNotEvidence { claim, test } => write!(
                f,
                "claim {claim} cites test {test}, which ran on the fake substrate and backs no \
                 claim"
            ),
            Self::CitationSubjectMismatch { claim } => write!(
                f,
                "claim {claim} cites evidence whose link and subject disagree"
            ),
            Self::SourceTooWeak { claim, capability } => write!(
                f,
                "claim {claim} cites a {capability} observation from a source that capability \
                 never accepts"
            ),
            Self::UnknownAssumption { assumption } => {
                write!(f, "assumption {assumption} is not in the ledger")
            }
            Self::UnknownRisk { risk } => write!(f, "risk {risk} is not in the ledger"),
            Self::UnknownClaim { claim } => write!(f, "claim {claim} is not in the ledger"),
            Self::DuplicateClaim { claim } => write!(f, "claim {claim} is already in the ledger"),
            Self::DuplicateAssumption { assumption } => {
                write!(f, "assumption {assumption} is already in the ledger")
            }
            Self::DuplicateRisk { risk } => write!(f, "risk {risk} is already in the ledger"),
        }
    }
}

impl std::error::Error for LedgerError {}

/// One claim: a property of one profile under one configuration, what it rests on, what
/// it leaves, and what backs it. Built only through [`Claim::new`]; written for reports
/// and never read back.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Claim {
    id: ClaimId,
    property: Property,
    category: ExecutionCategory,
    profile: ProfileId,
    configuration: ConfigurationFingerprint,
    assumptions: BTreeSet<AssumptionId>,
    residual_risks: BTreeSet<RiskId>,
    support: ClaimSupport,
}

impl Claim {
    /// Refuses a claim with evidence support but no citation, with no assumption or no
    /// residual risk, with a test citation from the fake substrate, or with a probe
    /// citation whose link does not name its subject or whose source the capability never
    /// accepts.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: ClaimId,
        property: Property,
        category: ExecutionCategory,
        profile: ProfileId,
        configuration: ConfigurationFingerprint,
        assumptions: BTreeSet<AssumptionId>,
        residual_risks: BTreeSet<RiskId>,
        support: ClaimSupport,
    ) -> Result<Self, LedgerError> {
        if assumptions.is_empty() {
            return Err(LedgerError::NoAssumptions { claim: id });
        }
        if residual_risks.is_empty() {
            return Err(LedgerError::NoResidualRisks { claim: id });
        }
        if let ClaimSupport::Evidence { citations } = &support {
            if citations.is_empty() {
                return Err(LedgerError::NoEvidence { claim: id });
            }
            for citation in citations {
                match citation {
                    Citation::Test(test) => {
                        if test.substrate == RunSubstrate::FakeTimeControlled {
                            return Err(LedgerError::FakeSubstrateIsNotEvidence {
                                claim: id,
                                test: test.test.clone(),
                            });
                        }
                    }
                    Citation::Probe(probe) => {
                        if probe.link.subject != probe.subject.identity()
                            || probe.link.capability.subject_kind() != probe.subject.kind()
                        {
                            return Err(LedgerError::CitationSubjectMismatch { claim: id });
                        }
                        if !probe
                            .link
                            .source
                            .satisfies(probe.link.capability.weakest_source())
                        {
                            return Err(LedgerError::SourceTooWeak {
                                claim: id,
                                capability: probe.link.capability,
                            });
                        }
                    }
                    Citation::Release(_) => {}
                }
            }
        }
        Ok(Self {
            id,
            property,
            category,
            profile,
            configuration,
            assumptions,
            residual_risks,
            support,
        })
    }

    pub fn id(&self) -> &ClaimId {
        &self.id
    }

    pub fn property(&self) -> Property {
        self.property
    }

    pub fn category(&self) -> ExecutionCategory {
        self.category
    }

    pub fn profile(&self) -> &ProfileId {
        &self.profile
    }

    pub fn configuration(&self) -> ConfigurationFingerprint {
        self.configuration
    }

    pub fn assumptions(&self) -> &BTreeSet<AssumptionId> {
        &self.assumptions
    }

    pub fn residual_risks(&self) -> &BTreeSet<RiskId> {
        &self.residual_risks
    }

    pub fn support(&self) -> &ClaimSupport {
        &self.support
    }
}

/// What checking one probe citation against live evidence found.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum CitationVerdict {
    /// The cited observation is the latest, satisfies the requirement and is fresh until
    /// `fresh_until` on the registry's clock.
    Fresh {
        fresh_until: MonotonicTime,
    },
    Refused {
        refusal: EvidenceRefusal,
    },
    /// A later observation replaced the cited one; the claim must cite it anew.
    Superseded {
        latest: EvidenceLink,
    },
}

/// The port through which the ledger asks the live evidence about a citation. The
/// CORE-01 [`ProbeRegistry`] implements it.
pub trait EvidenceCheck {
    /// Evaluates the cited observation as a requirement under `configuration`, the
    /// fingerprint in force now.
    fn check(
        &self,
        citation: &ProbeCitation,
        configuration: ConfigurationFingerprint,
    ) -> CitationVerdict;
}

impl<C: Clock> EvidenceCheck for ProbeRegistry<C> {
    fn check(
        &self,
        citation: &ProbeCitation,
        configuration: ConfigurationFingerprint,
    ) -> CitationVerdict {
        let link = citation.link;
        let requirement = Requirement::new(
            link.capability,
            citation.subject.clone(),
            link.source,
            citation.max_age,
            configuration,
        );
        match self.evaluate(&requirement) {
            Err(refusal) => CitationVerdict::Refused { refusal },
            Ok(satisfied) => match self.latest(link.capability, &citation.subject) {
                Some(latest) if link.names(latest) => CitationVerdict::Fresh {
                    fresh_until: satisfied.fresh_until(),
                },
                Some(latest) => CitationVerdict::Superseded {
                    latest: EvidenceLink::of(latest),
                },
                None => CitationVerdict::Refused {
                    refusal: EvidenceRefusal::Missing {
                        capability: link.capability,
                    },
                },
            },
        }
    }
}

/// Why a claim is not supported now.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum Invalidation {
    /// The claim was made under another configuration than the one in force.
    ClaimConfigurationChanged {
        claimed_under: ConfigurationFingerprint,
        current: ConfigurationFingerprint,
    },
    /// A cited test ran under another configuration than the one in force.
    TestConfigurationChanged {
        test: TestId,
        tested_under: ConfigurationFingerprint,
        current: ConfigurationFingerprint,
    },
    /// A cited observation is no longer fresh.
    Stale {
        capability: Capability,
        staleness: Staleness,
    },
    /// A cited observation was made under another configuration than the one in force.
    EvidenceConfigurationChanged {
        capability: Capability,
        observed_under: ConfigurationFingerprint,
        current: ConfigurationFingerprint,
    },
    /// The live evidence refuses the cited observation for another reason.
    Refused { refusal: EvidenceRefusal },
    /// A later observation replaced the cited one.
    Superseded {
        cited: EvidenceLink,
        latest: EvidenceLink,
    },
}

impl fmt::Display for Invalidation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClaimConfigurationChanged { .. } => {
                f.write_str("the configuration changed since the claim was made")
            }
            Self::TestConfigurationChanged { test, .. } => {
                write!(f, "the configuration changed since test {test} ran")
            }
            Self::Stale {
                capability,
                staleness,
            } => write!(f, "the {capability} evidence is stale: {staleness:?}"),
            Self::EvidenceConfigurationChanged { capability, .. } => write!(
                f,
                "the configuration changed since {capability} was observed"
            ),
            Self::Refused { refusal } => write!(f, "{refusal}"),
            Self::Superseded { latest, .. } => write!(
                f,
                "a later {} observation replaced the cited one",
                latest.capability
            ),
        }
    }
}

/// The status of one claim now. Written for reports; never read back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ClaimStatus {
    /// Every citation holds; `fresh_until` is the earliest moment a probe citation goes
    /// stale, when the claim cites one.
    Supported {
        citations: u64,
        fresh_until: Option<MonotonicTime>,
    },
    /// The claim states a gap instead of evidence.
    Gap {
        reason: GapReason,
    },
    Invalidated {
        reason: Invalidation,
    },
}

impl fmt::Display for ClaimStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Supported {
                citations,
                fresh_until: Some(until),
            } => write!(
                f,
                "supported by {citations} citations, fresh until {} ns",
                until.as_nanos()
            ),
            Self::Supported {
                citations,
                fresh_until: None,
            } => write!(f, "supported by {citations} citations"),
            Self::Gap { reason } => write!(f, "explicit gap: {reason}"),
            Self::Invalidated { reason } => write!(f, "invalidated: {reason}"),
        }
    }
}

/// One line of the summary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ClaimEntry {
    pub claim: ClaimId,
    pub property: Property,
    pub status: ClaimStatus,
}

/// The statuses of every claim, counted. The counts are counts: nothing here weighs,
/// multiplies or divides them, and no aggregate probability or score exists (VM-W52 "no
/// wall multipliers or generic secure badge"; "no aggregate probability fabricated from
/// surface counts").
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LedgerSummary {
    pub claims: u64,
    pub supported: u64,
    pub gaps: u64,
    pub invalidated: u64,
    pub entries: Vec<ClaimEntry>,
}

impl fmt::Display for LedgerSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "{} claims: {} supported, {} with an explicit gap, {} invalidated",
            self.claims, self.supported, self.gaps, self.invalidated
        )?;
        for entry in &self.entries {
            writeln!(f, "{} {}: {}", entry.property, entry.claim, entry.status)?;
        }
        Ok(())
    }
}

/// The assurance ledger of one deployment (VM-W52).
#[derive(Clone, Debug)]
pub struct AssuranceLedger {
    configuration: ConfigurationFingerprint,
    assumptions: BTreeMap<AssumptionId, AssumptionKind>,
    risks: BTreeMap<RiskId, RiskKind>,
    claims: BTreeMap<ClaimId, Claim>,
}

impl AssuranceLedger {
    /// A ledger under the configuration in force.
    pub fn new(configuration: ConfigurationFingerprint) -> Self {
        Self {
            configuration,
            assumptions: BTreeMap::new(),
            risks: BTreeMap::new(),
            claims: BTreeMap::new(),
        }
    }

    pub fn configuration(&self) -> ConfigurationFingerprint {
        self.configuration
    }

    /// Records that the configuration changed. Claims made under the old one are
    /// invalidated from here on; returns how many.
    pub fn set_configuration(&mut self, configuration: ConfigurationFingerprint) -> u64 {
        self.configuration = configuration;
        self.claims
            .values()
            .filter(|claim| claim.configuration != configuration)
            .count()
            .try_into()
            .unwrap_or(u64::MAX)
    }

    pub fn add_assumption(
        &mut self,
        id: AssumptionId,
        kind: AssumptionKind,
    ) -> Result<(), LedgerError> {
        if self.assumptions.contains_key(&id) {
            return Err(LedgerError::DuplicateAssumption { assumption: id });
        }
        self.assumptions.insert(id, kind);
        Ok(())
    }

    pub fn add_risk(&mut self, id: RiskId, kind: RiskKind) -> Result<(), LedgerError> {
        if self.risks.contains_key(&id) {
            return Err(LedgerError::DuplicateRisk { risk: id });
        }
        self.risks.insert(id, kind);
        Ok(())
    }

    /// Adds a claim whose assumptions and risks the ledger knows.
    pub fn add_claim(&mut self, claim: Claim) -> Result<(), LedgerError> {
        if self.claims.contains_key(&claim.id) {
            return Err(LedgerError::DuplicateClaim { claim: claim.id });
        }
        if let Some(assumption) = claim
            .assumptions
            .iter()
            .find(|assumption| !self.assumptions.contains_key(*assumption))
        {
            return Err(LedgerError::UnknownAssumption {
                assumption: assumption.clone(),
            });
        }
        if let Some(risk) = claim
            .residual_risks
            .iter()
            .find(|risk| !self.risks.contains_key(*risk))
        {
            return Err(LedgerError::UnknownRisk { risk: risk.clone() });
        }
        self.claims.insert(claim.id.clone(), claim);
        Ok(())
    }

    pub fn claim(&self, id: &ClaimId) -> Option<&Claim> {
        self.claims.get(id)
    }

    pub fn claims(&self) -> impl Iterator<Item = &Claim> {
        self.claims.values()
    }

    pub fn assumptions(&self) -> &BTreeMap<AssumptionId, AssumptionKind> {
        &self.assumptions
    }

    pub fn risks(&self) -> &BTreeMap<RiskId, RiskKind> {
        &self.risks
    }

    /// The status of one claim now: invalidated when the configuration changed since the
    /// claim or a cited test, when a cited observation is stale, superseded, observed
    /// under another configuration or refused; a gap when the claim states one; supported
    /// otherwise. The first citation that fails decides.
    pub fn status(
        &self,
        id: &ClaimId,
        evidence: &dyn EvidenceCheck,
    ) -> Result<ClaimStatus, LedgerError> {
        let claim = self
            .claims
            .get(id)
            .ok_or_else(|| LedgerError::UnknownClaim { claim: id.clone() })?;
        if claim.configuration != self.configuration {
            return Ok(ClaimStatus::Invalidated {
                reason: Invalidation::ClaimConfigurationChanged {
                    claimed_under: claim.configuration,
                    current: self.configuration,
                },
            });
        }
        let citations = match &claim.support {
            ClaimSupport::Gap { gap } => return Ok(ClaimStatus::Gap { reason: gap.reason }),
            ClaimSupport::Evidence { citations } => citations,
        };
        let mut fresh_until: Option<MonotonicTime> = None;
        for citation in citations {
            match citation {
                Citation::Release(_) => {}
                Citation::Test(test) => {
                    if test.configuration != self.configuration {
                        return Ok(ClaimStatus::Invalidated {
                            reason: Invalidation::TestConfigurationChanged {
                                test: test.test.clone(),
                                tested_under: test.configuration,
                                current: self.configuration,
                            },
                        });
                    }
                }
                Citation::Probe(probe) => match evidence.check(probe, self.configuration) {
                    CitationVerdict::Fresh { fresh_until: until } => {
                        fresh_until =
                            Some(fresh_until.map_or(until, |earliest| earliest.min(until)));
                    }
                    CitationVerdict::Superseded { latest } => {
                        return Ok(ClaimStatus::Invalidated {
                            reason: Invalidation::Superseded {
                                cited: probe.link,
                                latest,
                            },
                        })
                    }
                    CitationVerdict::Refused { refusal } => {
                        let reason = match refusal {
                            EvidenceRefusal::Stale {
                                capability,
                                staleness,
                            } => Invalidation::Stale {
                                capability,
                                staleness,
                            },
                            EvidenceRefusal::FingerprintChanged {
                                capability,
                                observed_under,
                                current,
                            } => Invalidation::EvidenceConfigurationChanged {
                                capability,
                                observed_under,
                                current,
                            },
                            refusal => Invalidation::Refused { refusal },
                        };
                        return Ok(ClaimStatus::Invalidated { reason });
                    }
                },
            }
        }
        Ok(ClaimStatus::Supported {
            citations: u64::try_from(citations.len()).unwrap_or(u64::MAX),
            fresh_until,
        })
    }

    /// Every claim's status, in claim id order.
    pub fn summary(&self, evidence: &dyn EvidenceCheck) -> LedgerSummary {
        let mut summary = LedgerSummary {
            claims: 0,
            supported: 0,
            gaps: 0,
            invalidated: 0,
            entries: Vec::new(),
        };
        for claim in self.claims.values() {
            let Ok(status) = self.status(&claim.id, evidence) else {
                continue;
            };
            summary.claims = summary.claims.saturating_add(1);
            match status {
                ClaimStatus::Supported { .. } => {
                    summary.supported = summary.supported.saturating_add(1);
                }
                ClaimStatus::Gap { .. } => summary.gaps = summary.gaps.saturating_add(1),
                ClaimStatus::Invalidated { .. } => {
                    summary.invalidated = summary.invalidated.saturating_add(1);
                }
            }
            summary.entries.push(ClaimEntry {
                claim: claim.id.clone(),
                property: claim.property,
                status,
            });
        }
        summary
    }
}
