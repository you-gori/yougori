//! Which CORE-01 capability each §17 controlled check feeds (S2 CORE-01 row, line 210;
//! VM-W09, line 2594; §8.1, lines 2433–2439; §17, lines 3145–3188).
//!
//! Every check has exactly one entry, in table order: the capability its host-observed
//! parts feed, with exactly those parts, or no capability, with the capabilities that
//! already state its fact and the reason. A guest-reported part never feeds a capability
//! (§8.1 line 2437; VM-W09: a lying guest cannot satisfy host-only requirements), so a
//! guest-reported check (VM-CP-05, VM-CP-09, VM-CP-21) feeds one only through its host
//! corroboration. The adapters of [`super::core01`] run exactly the parts listed here.

use serde::Serialize;

use super::catalog::{CheckId, CorroboratingFact, Part};
use crate::foundation::evidence::Capability;

/// What a check is in CORE-01.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "coverage", rename_all = "snake_case")]
pub enum Core01Coverage {
    /// These host-observed parts of the check feed `capability`.
    Capability {
        capability: Capability,
        parts: &'static [Part],
    },
    /// The check feeds no host CORE-01 capability: `covered_by` names the capabilities
    /// that already state its fact (empty when none does), and `reason` says why.
    NoCapability {
        covered_by: &'static [Capability],
        reason: &'static str,
    },
}

/// The entry of one check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct CheckCoverage {
    pub check: CheckId,
    pub coverage: Core01Coverage,
}

/// Every check's entry, in table order.
pub fn core01_coverage() -> &'static [CheckCoverage] {
    &COVERAGE
}

/// The entry of `check`. The map is in row order and `CheckId` is a row number by
/// construction; the coverage test checks both.
pub fn coverage_of(check: CheckId) -> &'static Core01Coverage {
    &COVERAGE[usize::from(check.number().clamp(CheckId::FIRST, CheckId::LAST) - 1)].coverage
}

/// The checks that feed `capability`, in table order, each with the host parts that feed
/// it.
pub fn checks_for(capability: Capability) -> impl Iterator<Item = (CheckId, &'static [Part])> {
    COVERAGE
        .iter()
        .filter_map(move |entry| match entry.coverage {
            Core01Coverage::Capability {
                capability: fed,
                parts,
            } if fed == capability => Some((entry.check, parts)),
            _ => None,
        })
}

const PRIMARY: &[Part] = &[Part::Primary];

const fn feeds(number: u8, capability: Capability, parts: &'static [Part]) -> CheckCoverage {
    CheckCoverage {
        check: CheckId::of(number),
        coverage: Core01Coverage::Capability { capability, parts },
    }
}

const fn none(number: u8, reason: &'static str) -> CheckCoverage {
    covered(number, &[], reason)
}

const fn covered(
    number: u8,
    covered_by: &'static [Capability],
    reason: &'static str,
) -> CheckCoverage {
    CheckCoverage {
        check: CheckId::of(number),
        coverage: Core01Coverage::NoCapability { covered_by, reason },
    }
}

/// Why a test of Yougori's own host code is not a capability.
const OWN_CODE: &str = "It tests Yougori's own host code on a corpus or a fake provider; the \
    result belongs to the build, not to this host or one sandbox, and the boundary report \
    judges it on every run.";

use Capability::{
    BootedImageMatchesManifest, CloneIdentityReset, CredentialAbsentFromScannedLocations,
    DestinationPolicyEnforced, DeviceAssignmentIsolated, HypervisorAvailable,
    HypervisorConfigurationMatches, HypervisorConfined, NoGuestNetworkDevice,
    PerimeterRuleEnforced, RuntimeCategory,
};

/// The map, in row order (§17 lines 3151–3185).
static COVERAGE: [CheckCoverage; 35] = [
    feeds(1, HypervisorAvailable, PRIMARY),
    feeds(2, HypervisorConfigurationMatches, PRIMARY),
    feeds(3, HypervisorConfigurationMatches, PRIMARY),
    feeds(4, HypervisorConfined, PRIMARY),
    feeds(
        5,
        BootedImageMatchesManifest,
        &[
            Part::Corroboration {
                fact: CorroboratingFact::BootedRootImage,
            },
            Part::Corroboration {
                fact: CorroboratingFact::KernelBuildRecord,
            },
        ],
    ),
    none(
        6,
        "The guest makes the connections and a controlled listener reports them, so the check \
         exercises one sandbox's whole route on one run, and the boundary report judges it. \
         The host facts it rests on are DestinationPolicyEnforced (VM-CP-07, VM-CP-08) and \
         PerimeterRuleEnforced (VM-CP-11).",
    ),
    feeds(7, DestinationPolicyEnforced, PRIMARY),
    feeds(8, DestinationPolicyEnforced, PRIMARY),
    feeds(
        9,
        NoGuestNetworkDevice,
        &[Part::Corroboration {
            fact: CorroboratingFact::NoGuestNetworkDevice,
        }],
    ),
    none(10, OWN_CODE),
    feeds(11, PerimeterRuleEnforced, PRIMARY),
    feeds(12, CredentialAbsentFromScannedLocations, PRIMARY),
    none(13, OWN_CODE),
    none(
        14,
        "A revocation drill that records five times and their percentiles against an \
         engineering target, not a guarantee (§6.5): a measurement, not a capability.",
    ),
    none(15, OWN_CODE),
    none(16, OWN_CODE),
    feeds(17, BootedImageMatchesManifest, PRIMARY),
    none(18, OWN_CODE),
    none(19, OWN_CODE),
    none(
        20,
        "A stress drill driven from inside the guest whose result is measured per run; the \
         resource controls it relies on are part of HypervisorConfined (VM-CP-04).",
    ),
    feeds(
        21,
        CloneIdentityReset,
        &[
            Part::Corroboration {
                fact: CorroboratingFact::CloneIdentities,
            },
            Part::Corroboration {
                fact: CorroboratingFact::PreSnapshotApprovalRefused,
            },
        ],
    ),
    none(22, OWN_CODE),
    feeds(23, BootedImageMatchesManifest, PRIMARY),
    none(
        24,
        "An end-to-end workflow on the authorized disposable environment (§12.1 Tier 2), \
         required for a release; it observes no host fact.",
    ),
    none(
        25,
        "It tests the link parser on a mutation corpus, and that a forged guest report \
         satisfies no host-only requirement, which CORE-01's source floors enforce for every \
         capability.",
    ),
    none(26, OWN_CODE),
    none(27, OWN_CODE),
    none(28, OWN_CODE),
    none(
        29,
        "It concerns two sandboxes, the grant between them and their caches and volumes on one \
         run; the boundary report judges it.",
    ),
    none(30, OWN_CODE),
    feeds(31, DeviceAssignmentIsolated, PRIMARY),
    none(
        32,
        "It tests lease expiry under a simulated partition and the attestation verifier on \
         fixtures; no remote or confidential platform is observed here.",
    ),
    covered(
        33,
        &[RuntimeCategory, HypervisorAvailable],
        "With acceleration unavailable, HypervisorAvailable (VM-CP-01) is unsupported, and \
         RuntimeCategory admits no native, emulated or container runtime as a VM sandbox; \
         together they state this check's fact.",
    ),
    none(
        34,
        "A research-tier comparison with the VM-N3 model, or a counterexample trace; it \
         observes no host fact.",
    ),
    none(
        35,
        "It tests that host policy governs a template's request and that a skipped test reads \
         as not tested; CORE-01 itself refuses unknown schema versions and never passes an \
         unknown result.",
    ),
];
