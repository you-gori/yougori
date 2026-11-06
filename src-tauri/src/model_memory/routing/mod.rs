//! P14: GPU §4.6 joint routing and placement, §4.7 topology-aware replication and §4.8
//! temporary distributed execution, with the GPU-W09 items they need
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md lines 707–739 and 1109–1125).
//!
//! - [`estimate`]: `finish_at_node = queue + state_preparation_critical_path +
//!   request_compute + client/network_tail` with uncertainty and a stale-report penalty
//!   (§4.6, lines 713–716).
//! - [`joint`]: the §4.6 router. Only authorized endpoints for the exact requested model
//!   are compared; resident state is used only through the identity layer's advertisement
//!   recheck and scoped grants; session stickiness, data locality, egress, donor impact
//!   and user placement restrictions are priced or enforced; token reconstruction and raw
//!   KV transfer are separate mechanisms; a hysteresis threshold prevents oscillation.
//! - [`runners`]: the two simulated runners of line 718 and the policies compared.
//! - [`replication`]: star, chain, binomial tree and multiple independent sources over
//!   the measured topology (§4.7), timed with the GPU §2.2 bound and the GPU §2.5
//!   multi-source planner, with communicator reuse, donor HBM pressure, readiness order,
//!   bounded failure recovery and gated FlashBoot, RDMA, paid-hardware and driver paths.
//! - [`distributed`] and [`epochs`]: complementary-layer pipelines while replicas load
//!   (§4.8), with activation traffic, latency, microbatch fill, temporary KV placement and
//!   plan epochs that keep every in-flight request on its original plan.
//! - [`advertisements`] and [`recovery`]: GPU-W09 expiring residency advertisements with
//!   stale-source fallback, and partial-rank recovery as bounded re-planning.
//! - [`evidence`], [`claims`], [`fixtures`] and [`experiments`]: every simulated result is
//!   a CORE-08 record on the fake substrate, compared against the ordinary workflow and
//!   the strongest compatible baseline, and each experiment ends with a §4.17 claim record
//!   whose result is computed, never supplied.
//!
//! Pure, synchronous and deterministic: time comes from the shared clock, variation from
//! the bench's seeded generator, and no process, network, GPU or file is touched. Grants
//! stand on a CORE-02 catalog and KV-scope enforcement on CORE-01 evidence supplied by the
//! caller. Nothing here measures hardware; every hardware result is not measured.
//!
//! # Claim record: §4.6 joint routing and placement
//!
//! 1. Contribution: a router for one exact requested model that ranks only authorized
//!    endpoints by `finish_at_node` with uncertainty and a stale-report penalty, prices a
//!    session move only by a mechanism the destination supports, adds data locality,
//!    egress and donor impact, honours placement restrictions and keeps hysteresis.
//! 2. Closest prior work: ServerlessLLM (OSDI 2024): locality-aware server selection by
//!    estimated model loading time, and live migration that sends tokens and recomputes
//!    the KV cache at the destination.
//! 3. Difference tested: the request's own queue, compute and client tail with
//!    uncertainty, stale-report penalties and hysteresis, and per-mechanism session moves.
//! 4. Assumptions: reports younger than the maximum age bound the real queue; estimates
//!    respect the §2.2 bound; rechecked records and grants are current. Smallest
//!    counterexample: a 1 s old report from an idle endpoint hides a burst admitted since,
//!    so the router picks it and finishes later than at the ready endpoint.
//! 5. Comparison: two simulated runners, three regimes, five seeded trials per policy,
//!    p95 time to first token, fake substrate; baselines route-to-ready and a
//!    ServerlessLLM-style startup-time policy with token-reconstruction migration.
//! 6. Result (computed by [`experiments::joint_routing_experiment`]): narrowed. The
//!    hysteresis keeps the last request of a burst on the overloaded ready runner, so the
//!    router loses that regime to the startup-time baseline by about 5%; in the
//!    briefly-busy and long-context-session regimes it ties the best baseline (route to
//!    ready) and beats the startup-time baseline. Inconclusive within the kept regimes:
//!    no hardware measurement and no literature comparison.
//!
//! # Claim record: §4.7 topology-aware replication
//!
//! 1. Contribution: replication that plans star, chain, binomial tree and multiple
//!    independent sources over the measured topology, with setup, shared links and cuts
//!    counted once, donor HBM pressure and serving impact and readiness order, picks the
//!    best feasible schedule, and recovers failed nodes by bounded re-planning.
//! 2. Closest prior work: FlashBoot (arXiv 2608.08482), a large immutable arena path on
//!    compatible rack-scale hardware; its code availability is future work (line 728).
//! 3. Difference tested: a choice among shapes on commodity measured links with donor
//!    load, communicator reuse and failure recovery as inputs, instead of one fixed path.
//! 4. Assumptions: measured bandwidth holds under concurrent streams and every shared
//!    link is declared; chunks delivered before a failure stay verified. Smallest
//!    counterexample: two targets behind an undeclared switch uplink make a star look
//!    twice as fast as the uplink allows.
//! 5. Comparison: four regimes, five seeded trials, p95 time to first token of each
//!    target's first request; baselines: every target downloading from the origin, and a
//!    fixed pipelined chain (the NCCL-style broadcast).
//! 6. Result (computed by [`experiments::replication_experiment`]): inconclusive. It ties
//!    the chain on a symmetric LAN, wins with a fat donor (star) and with one
//!    unsplittable extent for seven targets (binomial tree), and ties with three
//!    independent donors: the §2.5 planner holds each source's share fixed, so 7 of 20
//!    chunks on one source set 8.4 s against the chain's 8.8 s, inside the 5% tie band.
//!    FlashBoot, RDMA, paid hardware and driver changes stay gated and unmeasured.
//!
//! # Claim record: §4.8 temporary distributed execution
//!
//! 1. Contribution: serving from complementary layers on several nodes while replicas
//!    load, with activation traffic, link latency, microbatch fill and temporary KV
//!    modelled, and plan epochs so requests finish on the plan they were admitted to.
//! 2. Closest prior work: λScale (arXiv 2502.09922), execute-while-load across nodes
//!    during serverless scale-out over RDMA.
//! 3. Difference tested: a commodity-LAN cost model with an epoch-coordinated transition,
//!    compared with waiting for replicas and with routing to the donor.
//! 4. Assumptions: each boundary carries hidden size × activation bytes per token; link
//!    figures hold for the window; temporary KV fits. Smallest counterexample: on a
//!    50 Mb/s link 8,192-token prompts make the pipeline's prefill outlast the 3 s wait.
//! 5. Comparison: three regimes, five seeded trials, p95 time to first token; baselines
//!    wait-for-replicas and route-to-donor, the better of them per regime.
//! 6. Result (computed by [`experiments::distributed_experiment`]): narrowed to a fast LAN
//!    with an overloaded donor, where it wins; it loses on the slow link (communication
//!    erases the benefit) and to an idle donor. Inconclusive within the kept regime.

pub mod advertisements;
pub mod claims;
pub mod distributed;
pub mod epochs;
pub mod error;
pub mod estimate;
pub mod evidence;
pub mod experiments;
pub mod fixtures;
pub mod joint;
mod numbers;
pub mod recovery;
pub mod replication;
pub mod runners;

#[cfg(test)]
mod tests;

pub use error::RoutingError;
