//! Novelty records for VM-N1 and VM-N4 (VM part §9.5, lines 2399–2401): the closest
//! work, the precise difference, assumptions, prototype and strongest baseline. Targeted
//! checks only; this is not an exhaustive novelty search, and no record can say more
//! than "inconclusive" while its only evidence is a fake-substrate comparison.

use serde::Serialize;

use super::compare::ComparisonRecord;

/// What the evidence so far supports. There is deliberately no "novel" or "proven"
/// variant: originality is claimed only after reading the closest work fully (§9.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimResult {
    NotEvaluated,
    /// Compared on fakes only: neither security nor performance is shown.
    InconclusiveOnFakes,
}

/// One §9.5 record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NoveltyRecord {
    pub candidate: &'static str,
    pub closest_work: Vec<&'static str>,
    pub difference: &'static str,
    pub assumptions: Vec<&'static str>,
    pub prototype: &'static str,
    pub strongest_baseline: &'static str,
    pub result: ClaimResult,
}

/// The VM-N1 and VM-N4 records. A comparison record, which is always fake-substrate,
/// moves the result only to [`ClaimResult::InconclusiveOnFakes`].
pub fn novelty_records(comparison: Option<&ComparisonRecord>) -> Vec<NoveltyRecord> {
    let result = match comparison {
        Some(record) if record.provenance().is_fake_substrate() => ClaimResult::InconclusiveOnFakes,
        _ => ClaimResult::NotEvaluated,
    };
    vec![
        NoveltyRecord {
            candidate: "VM-N1",
            closest_work: vec![
                "CaMeL (arXiv 2503.18813): separates control and data flow and applies \
                 capability policy to untrusted values inside one agent interpreter",
                "Qubes OS: compartmentalized services and Split GPG, with qubes assigned by the \
                 user",
            ],
            difference: "compiles a labelled workflow DAG into VM compartments under an \
                         authority-conflict relation, choosing the partition and order by VM \
                         startup/retention, transfer, delay and approval cost, with explicit \
                         release contracts, history-aware later grants and an explanation for \
                         every partition and refusal",
            assumptions: vec![
                "labels come from trusted policy and explicit provenance",
                "the VM boundary holds and the modelled authorities are the only channels",
                "costs and attacks are modelled, not measured",
            ],
            prototype: "Tier 0 library: rules-based compiler, exhaustive oracle up to 7 steps, \
                        model-6 enumeration up to 3 steps, run-time history checks",
            strongest_baseline: "manually separated VMs, each with exactly its step's \
                                 authorities",
            result,
        },
        NoveltyRecord {
            candidate: "VM-N4",
            closest_work: vec![
                "offline package mirrors and lockfile-pinned, hash-checked installs",
                "content-addressed stores such as OCI digests and Nix store paths",
            ],
            difference: "binds a manifest compiled before private inputs enter to one compute \
                         VM's scope and execution, refuses names, URLs, queries and redirects \
                         from the private VM, enforces one scope for cache hits and misses, \
                         treats a private-derived manifest as an authorized metadata release, \
                         and classifies lazy fetches as a metadata channel",
            assumptions: vec![
                "the fetch service and catalog are trusted and separate from the compute VM",
                "publisher trust per artifact class is configured correctly",
                "registries are fakes; compatibility and rebuild time are not measured",
            ],
            prototype: "Tier 0 library on the CORE-02 catalog with a fake registry",
            strongest_baseline: "an offline mirror prefetched from a lockfile without per-VM \
                                 scope binding",
            result,
        },
    ]
}
