//! Whether a backend grows its KV in increments, from CORE-01 evidence (G06 of
//! docs/combined-plan-leftover-tasks.md: "a CORE-01 KV-growth capability (the runner
//! declares it today)"; GPU-W10 of docs/combined-gpu-memory-and-vm-sandbox-plan.md, line
//! 1305: "backend-supported dynamic KV growth and admission limits").
//!
//! The runner adapter still declares what one token of KV takes on its backend
//! ([`KvLayout`]). Whether the backend maps its pool in increments, and how large they
//! are, is CORE-01 `KvGrowth` evidence about the exact runtime: fresh, at least a live
//! report from the runtime (the capability's floor), observed under the configuration in
//! force and naming the runtime's own backend release, all by CORE-01's own rules. Without
//! such evidence, whether missing, stale, from another configuration, inconclusive or
//! unsupported, the pool is held whole from the start, as for a backend that cannot grow
//! it: that only ever reserves more, never less, so a missing observation never lets the
//! backend write past what the ledger holds for it.

use crate::foundation::evidence::{
    Capability, ConfigurationFingerprint, EvidencePolicy, EvidenceRefusal, ProbeRegistry,
    Requirement, RuntimeSubject, Subject, SupportDetail, UnknownReason,
};
use crate::foundation::ids::{Clock, MonotonicTime};

use super::kv::{KvGrowth, KvLayout, KvSpec};

/// How a runtime's backend fills its KV pool, as CORE-01 evidence shows it. Made only by
/// [`evidenced_kv_growth`], so increments are never assumed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KvGrowthEvidence {
    growth: KvGrowth,
    fresh_until: Option<MonotonicTime>,
    held_whole: Option<EvidenceRefusal>,
}

impl KvGrowthEvidence {
    /// Increments of the evidenced size, or the whole pool.
    pub fn growth(&self) -> KvGrowth {
        self.growth
    }

    /// Until when, on the registry's clock, the evidence of growth may be relied on; `None`
    /// when the pool is held whole.
    pub fn fresh_until(&self) -> Option<MonotonicTime> {
        self.fresh_until
    }

    /// Why the pool is held whole: CORE-01's refusal, which names its remedy. `None` when
    /// fresh evidence shows growth.
    pub fn held_whole_because(&self) -> Option<&EvidenceRefusal> {
        self.held_whole.as_ref()
    }

    /// The layout an activation runs with: the runner's bytes per token, and the growth
    /// the evidence shows, whatever the runner declared about growth.
    pub fn layout(&self, declared: KvLayout) -> KvLayout {
        KvLayout {
            bytes_per_token: declared.bytes_per_token,
            growth: self.growth,
        }
    }

    /// The KV of an activation reserving `pool_bytes`, with [`KvGrowthEvidence::layout`].
    pub fn spec(&self, declared: KvLayout, pool_bytes: u64) -> KvSpec {
        KvSpec::with_layout(self.layout(declared), pool_bytes)
    }
}

/// What CORE-01 shows about KV growth on `runtime` under `configuration`, judged by
/// `policy`: increments of the reported size when fresh `KvGrowth` evidence is supported
/// for the runtime's own backend release, the whole pool otherwise, with the refusal that
/// says why.
pub fn evidenced_kv_growth<C: Clock>(
    registry: &ProbeRegistry<C>,
    runtime: &RuntimeSubject,
    configuration: ConfigurationFingerprint,
    policy: EvidencePolicy,
) -> KvGrowthEvidence {
    let requirement = Requirement::new(
        Capability::KvGrowth,
        Subject::Runtime(runtime.clone()),
        policy.minimum_source,
        policy.max_age,
        configuration,
    );
    let whole = |refusal| KvGrowthEvidence {
        growth: KvGrowth::Fixed,
        fresh_until: None,
        held_whole: Some(refusal),
    };
    match registry.evaluate(&requirement) {
        Ok(satisfied) => match satisfied.detail() {
            SupportDetail::KvGrowth {
                increment_bytes, ..
            } => KvGrowthEvidence {
                growth: KvGrowth::Increments {
                    increment_bytes: increment_bytes.get(),
                },
                fresh_until: Some(satisfied.fresh_until()),
                held_whole: None,
            },
            // CORE-01 records a detail that does not fit its capability as unknown.
            _ => whole(EvidenceRefusal::Unknown {
                capability: Capability::KvGrowth,
                reason: UnknownReason::InconsistentReport,
            }),
        },
        Err(refusal) => whole(refusal),
    }
}
