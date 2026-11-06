//! Shared test values: a synthetic profile, labels, rules and a manual clock. The numbers
//! are illustrative parameters of a fake, not measurements of any engine.

use std::sync::Arc;

use super::corpus::{render_fresh, ColdTestNonce, Corpus, RenderedRequest};
use super::profile::{
    FakeHost, ModelSpec, ModelTimings, ProcessFootprint, RunnerMode, RunnerProfile, RunnerTimings,
    ServingCosts,
};
use super::resources::ResourceSnapshot;
use super::rng::Variation;
use super::runner::{FakeRunner, RequestPlan, RetryPolicy, Script, UserScript};
use crate::foundation::evidence::{Backend, BackendModeRules, BackendRelease};
use crate::foundation::ids::{ExecutionCategory, ExecutionId, ManualClock, MonotonicTime};
use crate::foundation::report::Label;
use crate::foundation::report::{ArrivalMode, BenchId, LoadDescription, NoncePlacement};

pub(crate) const MILLIS: u64 = 1_000_000;

pub(crate) fn label(value: &str) -> Label {
    Label::new(value).unwrap()
}

pub(crate) fn release(version: &str) -> BackendRelease {
    BackendRelease::new(Backend::Vllm, version).unwrap()
}

pub(crate) fn rules() -> BackendModeRules {
    BackendModeRules::recorded()
}

/// A manual clock that starts at 1 s.
pub(crate) fn clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(MonotonicTime::from_nanos(1_000_000_000)))
}

pub(crate) fn execution() -> ExecutionId {
    ExecutionId::new("exe-bench-t12").unwrap()
}

fn model(
    name: &str,
    weights_bytes: u64,
    kv_bytes_per_token: u64,
    timings: ModelTimings,
) -> ModelSpec {
    ModelSpec {
        name: label(name),
        weights_bytes,
        kv_bytes_per_token,
        layer_groups: 4,
        cuda_graphs: 8,
        communicators: 1,
        weight_allocations: 4,
        weight_dtype: label("bf16"),
        quantization: label("none"),
        kv_cache_dtype: label("bf16"),
        timings,
    }
}

/// Two models, A (8 GB) and B (6 GB), on a 24 GB GPU with 7 GB/s storage, 100 GB/s host
/// memory channels and 25 GB/s each way over PCIe. Every duration is above its GPU §2.2
/// bound; there is no variation, leak or corruption.
pub(crate) fn profile(mode: RunnerMode) -> RunnerProfile {
    RunnerProfile {
        mode,
        release: release("0.31.0"),
        category: ExecutionCategory::SharedKernelGpuRuntime,
        models: vec![
            model(
                "model-a",
                8_000_000_000,
                131_072,
                ModelTimings {
                    cold_load_nanos: 1_500 * MILLIS,
                    warm_load_nanos: 400 * MILLIS,
                    host_read_nanos: 1_200 * MILLIS,
                    sleep_nanos: 350 * MILLIS,
                    wake_nanos: 350 * MILLIS,
                    unload_nanos: 50 * MILLIS,
                    graph_capture_nanos: 300 * MILLIS,
                },
            ),
            model(
                "model-b",
                6_000_000_000,
                98_304,
                ModelTimings {
                    cold_load_nanos: 1_000 * MILLIS,
                    warm_load_nanos: 300 * MILLIS,
                    host_read_nanos: 900 * MILLIS,
                    sleep_nanos: 250 * MILLIS,
                    wake_nanos: 250 * MILLIS,
                    unload_nanos: 40 * MILLIS,
                    graph_capture_nanos: 250 * MILLIS,
                },
            ),
        ],
        runner: RunnerTimings {
            engine_startup_nanos: 2_000 * MILLIS,
            process_exit_nanos: 100 * MILLIS,
            hot_dispatch_nanos: 2 * MILLIS,
        },
        footprint: ProcessFootprint {
            context_vram_bytes: 500_000_000,
            rss_bytes: 2_000_000_000,
            file_descriptors: 64,
            kv_pool_allocations: 1,
        },
        serving: ServingCosts {
            max_num_seqs: 16,
            max_queue_depth: 256,
            prefill_nanos_per_token: 20_000,
            decode_step_base_nanos: 10 * MILLIS,
            decode_step_per_sequence_nanos: 200_000,
            decode_nanos_per_kibitoken_context: 50_000,
            prefix_caching: true,
        },
        host: FakeHost {
            vram_capacity_bytes: 24_000_000_000,
            pinned_host_capacity_bytes: 32_000_000_000,
            host_memory_bytes: 64_000_000_000,
            storage_read_bytes_per_second: 7e9,
            host_memory_bytes_per_second: 100e9,
            host_to_device_bytes_per_second: 25e9,
            device_to_host_bytes_per_second: 25e9,
        },
        leak_per_switch: ResourceSnapshot::ZERO,
        corrupt_state_after_switches: None,
        execute_while_load: false,
        deterministic_outputs: true,
        variation: Variation::NONE,
    }
}

/// Long enough never to bind unless a test sets it.
pub(crate) const GENEROUS_NANOS: u64 = 3_600 * 1_000 * MILLIS;

/// A fresh-prefill rendering of the tool fixture with nonce `nonce`.
pub(crate) fn request(nonce: u64) -> RenderedRequest {
    let corpus = Corpus::fast01().unwrap();
    let fixture = corpus.get("fast01-tool-run-tests").unwrap();
    render_fresh(
        fixture,
        ColdTestNonce::new(nonce, NoncePlacement::PromptPrefix),
    )
    .unwrap()
}

/// A request with generous deadlines, no gap and no switch.
pub(crate) fn plan(variant: &str, model: &str, nonce: u64, tokens: u32) -> RequestPlan {
    RequestPlan {
        variant: label(variant),
        model: label(model),
        request: request(nonce),
        max_output_tokens: tokens,
        deadline_nanos: GENEROUS_NANOS,
        timeout_nanos: GENEROUS_NANOS,
        gap_before_nanos: 0,
        switch_from_previous: false,
        burst: 0,
        check_response: false,
    }
}

/// One user sending `requests` in order from the clock's current time.
pub(crate) fn one_user(runner: &FakeRunner, bench: BenchId, requests: Vec<RequestPlan>) -> Script {
    Script {
        bench,
        load: LoadDescription {
            concurrent_requests: 1,
            arrival: ArrivalMode::Sequential,
        },
        users: vec![UserScript {
            start_at: crate::foundation::ids::Clock::now(runner.clock().as_ref()),
            requests,
            retry: RetryPolicy::NONE,
        }],
        recycle_after_switches: None,
    }
}

/// A fresh runner over `profile` with the recorded rules.
pub(crate) fn runner(profile: RunnerProfile, seed: u64) -> FakeRunner {
    FakeRunner::new(profile, rules(), clock(), seed, execution()).unwrap()
}
