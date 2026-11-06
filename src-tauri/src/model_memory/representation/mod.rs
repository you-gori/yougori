//! Exact differential materialization, representation selection and adaptive policy:
//! GPU §4.2, §4.9, §4.10 (as a gated non-goal) and §4.12 of
//! docs/combined-gpu-memory-and-vm-sandbox-plan.md, with GPU-W08 and GPU-W12.
//!
//! - [`differential`]: the required decoded extent set R, the compatible resident set A,
//!   a load of only R minus A verified against the target manifest, sharing measured at
//!   tensor and extent granularity, and the full-loader cutoff (§4.2).
//! - [`delta`]: XOR delta versions against a pinned base with bit-exact reconstruction,
//!   a bounded depth, required base availability and a computed abandonment decision
//!   (§4.2 line 679; GPU-W12).
//! - [`codec`]: zstd, the existing lossless codec, on real bytes: bounded decoding
//!   through the manifest's decoder port, frame headers checked before any decoder
//!   allocates, and raw escape blocks (§4.9 line 746; GPU-T34, GPU-T35).
//! - [`selection`]: raw or compressed transfer per artifact range from link, decoder,
//!   scratch, interference and source availability (§4.9), with the DFloat11 and
//!   ZipNN/nvCOMP comparisons recorded as unavailable.
//! - [`entropy`]: the specification gate of the later custom entropy-decoder branch
//!   (§4.9 line 748).
//! - [`policy`]: hand-coded policies, a shadow evaluator and a constrained contextual
//!   bandit over one knob (§4.12).
//! - [`evidence`]: simulated trials as fake-substrate CORE-08 records and comparison
//!   reports (rollout decision "T12 → T02").
//! - [`claims`]: claim records and their computed outcomes (§4.17).
//!
//! Everything here is pure, synchronous and deterministic: time comes from
//! [`crate::foundation::ids::Clock`], randomness only from the seeded
//! [`crate::model_memory::bench::rng::SeededRng`]. The manifest, its codec identities and
//! extent trees come from [`crate::model_memory::manifest`], the compression cost model
//! from [`crate::model_memory::math::compression`] and the amortization rule from
//! [`crate::foundation::catalog::ImportAmortization`]; none is redefined here.
//!
//! # Gated non-goals
//!
//! - §4.10, compute directly from compressed weights ([`COMPRESSED_COMPUTE`]): fused
//!   decode-GEMM needs GPU kernels, architecture-specific correctness fixtures and
//!   hardware measurements of occupancy, spills, numerics and tokens/s. Nothing here
//!   decodes inside a kernel or claims a capacity or latency gain.
//! - The custom entropy decoder ([`entropy::CUSTOM_ENTROPY_DECODER`]): line 748's
//!   obligations (bitstream length bounds, real per-lane offsets, endianness, incomplete
//!   blocks, maximum code length, checksums, every BF16 bit pattern) are the gate,
//!   checked by [`entropy::check_specification`]. The codec in use round-trips all
//!   65,536 BF16 patterns, NaN, infinities, subnormals and signed zeros included.
//!
//! # Claim record
//!
//! Every result below comes from simulated runs on the fake substrate, recorded through
//! `foundation::report` with fake-substrate provenance; none backs a performance,
//! improvement or release claim, and hardware-dependent quantities (decoder
//! interference, energy, real memory peaks) are "not measured". The outcomes are
//! computed by [`claims::ClaimRecord::decide`] and asserted by the module's tests.
//!
//! **§4.2 exact differential materialization** ([`claims::DIFFERENTIAL_CLAIM`]).
//! Contribution: a switch loads only target extents no compatible resident copy holds,
//! verifies every extent against the target manifest, and keeps the full loader when
//! indexing and hashing cost at least the transfer saved. Closest prior work: DeltaZip.
//! Difference tested: exact reuse keyed by decoded content keys, no assumed sparse
//! delta, with a full-loader cutoff. Assumptions: equal content keys mean equal bytes;
//! reuse only in the consumer's trust scope and device; index cost charged when the
//! index is missing. Smallest counterexample: two checkpoints whose identical tensors
//! sit one byte apart share no file-aligned extent. Baseline: the full loader. Result:
//! **inconclusive** — it wins for the adapter and checkpoint families and ties for
//! unrelated dense fine-tunes and shifted layouts, where the cutoff keeps the full
//! loader.
//!
//! **§4.2 XOR delta chains** ([`claims::DELTA_CLAIM`]). Contribution: versions stored as
//! the zstd-encoded XOR with a pinned base save storage without slowing cold recovery.
//! Closest prior work: DeltaZip. Difference tested: a lossless XOR delta with a
//! general-purpose codec against independent compression of the same version.
//! Assumptions: equal lengths and aligned tensors; base pinned and readable; cold
//! recovery reads the base and every delta. Smallest counterexample: an unrelated model
//! of equal length, whose XOR is as random as itself. Baseline: independent zstd.
//! Result: **rejected** — the dense fine-tune's delta is smaller, but a cold recovery
//! must also read and decode the base, so it is slower on every storage profile tried,
//! and the unrelated version saves nothing.
//!
//! **§4.9 representation selection** ([`claims::SELECTION_CLAIM`]). Contribution: a
//! per-range raw or zstd choice from current link, decoder, scratch, interference and
//! source state never loses to the better uniform choice under the same model, with raw
//! escape blocks. Closest prior work: DFloat11. Difference tested: per-range selection
//! with an existing lossless codec instead of one exponent-coded format. Assumptions:
//! independently decodable ranges; current rate estimates; compressed forms only where
//! prepared. Smallest counterexample: a decoder slower than its estimate. Baseline: the
//! better of all-raw and all-compressed. Result: **inconclusive** — it wins where the
//! decoder limits (0.80 ms against 0.92 ms all-raw on the simulated NVMe path) and ties
//! elsewhere: all-compressed on a cold remote link, all-raw from a GPU peer and under a
//! tight foreground budget. DFloat11 and ZipNN/nvCOMP are unavailable.
//!
//! **§4.12 adaptive policy** ([`claims::POLICY_CLAIM`]). Contribution: a constrained
//! contextual bandit over one knob, guarded by p99 and reserve bounds and a revert on
//! shift, matches or beats the best fixed policy per workload. Closest prior work:
//! contextual bandits for systems configuration tuning. Difference tested: a bandit over
//! a closed set of safe knob values against the best fixed policy and a hand-coded rule.
//! Assumptions: stationary outcomes between shifts; admitted arms safe when chosen;
//! every outcome observed. Smallest counterexample: a stationary single-context
//! workload. Baseline: the best fixed policy, or the hand-coded rule when stronger.
//! Result: **narrowed** — exploration regret loses to the best fixed arm on a stationary
//! single-context workload; it wins only on the mixed-context workload.

pub mod claims;
pub mod codec;
pub mod delta;
pub mod differential;
pub mod entropy;
pub mod evidence;
pub mod policy;
pub mod selection;

#[cfg(test)]
mod tests;

use crate::model_memory::manifest::GatedNonGoal;

/// §4.10 is not built: fused decode-GEMM needs GPU kernels and hardware measurements
/// (plan lines 752–758; GPU-W08 "Evaluate selective fused MLP decode/GEMM separately
/// from the loader").
pub const COMPRESSED_COMPUTE: GatedNonGoal = GatedNonGoal {
    name: "compute directly from compressed weights (fused decode-GEMM)",
    clause: "GPU §4.10 (plan lines 752-758); GPU-W08",
    gate: "architecture-specific correctness fixtures and GPU measurements of raw GEMM, \
           decode-then-GEMM and fused decode-GEMM, with capacity and latency reported \
           separately",
};

pub use claims::{ClaimOutcome, ClaimRecord, ClaimText, Verdict, WorkloadComparison};
pub use codec::{decode_bounded, encode, prepare_file, EscapePolicy, ZstdDecoder};
pub use delta::{DeltaDecision, DeltaLimits, DeltaStore, Parent};
pub use differential::{
    choose_loader, full_load, materialize, measure_sharing, plan, Consumer, DifferentialPlan,
    FamilyRelation, LoaderChoice, RequiredSet, ResidentExtent, ResidentRead, ReusedExtent,
};
pub use policy::{ArmSet, ConstrainedBandit, HandCodedPolicy, KnobValue, RequestedChange};
pub use selection::{select, select_exhaustive, Conditions, RangeCandidate, Representation};
