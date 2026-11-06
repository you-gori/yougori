//! The fake runner's parameters (S10 line 183: retained process, version-supported
//! sleep, verified reload and full process restart; T12: "Durations and resource effects
//! are parameters"). Every duration that moves bytes is checked against the GPU §2.2
//! physical lower bound, so a fake cannot be faster than its own links allow.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::resources::ResourceSnapshot;
use super::rng::Variation;
use super::BenchError;
use crate::foundation::evidence::{BackendRelease, Optimization};
use crate::foundation::ids::{digest, Digest, ExecutionCategory};
use crate::foundation::report::Label;
use crate::model_memory::math::bounds::{
    transfer_lower_bound, BandwidthRating, BoundsError, LowerBound, ResourceTable, TransferDemand,
};
use crate::model_memory::math::ResourceId;

/// Domain of [`RunnerProfile::build_digest`], the S8 runner build identity of a fake.
pub const RUNNER_BUILD_DOMAIN: &str = "yougori/bench/fake-runner/v1";

/// Nanoseconds in a second.
pub const NANOS_PER_SECOND: u64 = 1_000_000_000;

/// The four stable baseline modes S10 compares (line 183). CUDA checkpoint is not one of
/// them: it is a capability-gated experiment, not a park operation (S7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunnerMode {
    /// Every model keeps its own resident process; a switch is a dispatch.
    RetainedProcess,
    /// The parked model sleeps (weights offloaded to pinned host memory) and the next
    /// one wakes; only on a release recorded as supporting sleep (S7).
    VersionSupportedSleep,
    /// One running process unloads the parked model and loads the next, verified.
    VerifiedReload,
    /// The parked model's process exits and a new process loads the next.
    FullProcessRestart,
}

impl RunnerMode {
    pub const ALL: [Self; 4] = [
        Self::RetainedProcess,
        Self::VersionSupportedSleep,
        Self::VerifiedReload,
        Self::FullProcessRestart,
    ];

    /// A label-safe name.
    pub const fn slug(self) -> &'static str {
        match self {
            Self::RetainedProcess => "retained-process",
            Self::VersionSupportedSleep => "version-supported-sleep",
            Self::VerifiedReload => "verified-reload",
            Self::FullProcessRestart => "full-process-restart",
        }
    }

    /// The backend modes this runner mode needs a recorded release for (S7
    /// "version-supported sleep"; CORE-01 backend-mode rules).
    pub fn backend_modes(self) -> BTreeSet<Optimization> {
        match self {
            Self::VersionSupportedSleep => BTreeSet::from([Optimization::SleepWeightOffload]),
            _ => BTreeSet::new(),
        }
    }
}

/// Durations of one model's operations, in nanoseconds of the fake clock.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelTimings {
    /// Verified load from storage into the GPU (§2.1 weight availability, cold).
    pub cold_load_nanos: u64,
    /// Verified load from a host copy: the page cache or a zero-copy preload.
    pub warm_load_nanos: u64,
    /// Reading the weights into host memory: warming the page cache or preloading.
    pub host_read_nanos: u64,
    /// Offloading the weights to pinned host memory (version-supported sleep).
    pub sleep_nanos: u64,
    /// Moving them back from pinned host memory (wake).
    pub wake_nanos: u64,
    /// Releasing the weights and KV inside a running process.
    pub unload_nanos: u64,
    /// CUDA graph capture after the weights are usable; zero when eager.
    pub graph_capture_nanos: u64,
}

/// One fake model and its resource effects.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelSpec {
    pub name: Label,
    pub weights_bytes: u64,
    pub kv_bytes_per_token: u64,
    /// Layer groups loaded in order, for the GPU §2.6 first-token recurrence.
    pub layer_groups: u32,
    /// CUDA graphs held while resident; zero when eager.
    pub cuda_graphs: u64,
    pub communicators: u64,
    /// Physical allocation references the resident weights hold.
    pub weight_allocations: u64,
    pub weight_dtype: Label,
    pub quantization: Label,
    pub kv_cache_dtype: Label,
    pub timings: ModelTimings,
}

/// What each engine process holds whatever model it serves.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessFootprint {
    /// The CUDA context and allocator pools; a sleeping process keeps them (S10: a
    /// paused process does not free its GPU allocations).
    pub context_vram_bytes: u64,
    pub rss_bytes: u64,
    pub file_descriptors: u64,
    /// Allocation references of the KV pool while a model is resident.
    pub kv_pool_allocations: u64,
}

/// Durations that do not depend on the model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerTimings {
    /// Process launch to runtime initialised, independently of weights (§2.1).
    pub engine_startup_nanos: u64,
    pub process_exit_nanos: u64,
    /// Routing a request to a resident model.
    pub hot_dispatch_nanos: u64,
}

/// Continuous-batching serving costs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServingCosts {
    /// Sequences decoded together; more wait in the queue.
    pub max_num_seqs: u32,
    /// Waiting requests beyond this are rejected.
    pub max_queue_depth: u32,
    pub prefill_nanos_per_token: u64,
    pub decode_step_base_nanos: u64,
    pub decode_step_per_sequence_nanos: u64,
    /// Extra decode time per step for each 1,024 tokens of context in the batch.
    pub decode_nanos_per_kibitoken_context: u64,
    /// Reuse of a cached prompt prefix (FAST-01 warm prefix).
    pub prefix_caching: bool,
}

/// The simulated host: capacities and the measured usable directional bandwidths of its
/// links (GPU §2.2 `B_e`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FakeHost {
    pub vram_capacity_bytes: u64,
    pub pinned_host_capacity_bytes: u64,
    pub host_memory_bytes: u64,
    pub storage_read_bytes_per_second: f64,
    pub host_memory_bytes_per_second: f64,
    pub host_to_device_bytes_per_second: f64,
    pub device_to_host_bytes_per_second: f64,
}

/// Every parameter of one fake runner.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerProfile {
    pub mode: RunnerMode,
    /// The exact backend release whose mode rules apply (CORE-01).
    pub release: BackendRelease,
    /// The VM-D4–VM-D6 label the serving runtime keeps (S12).
    pub category: ExecutionCategory,
    pub models: Vec<ModelSpec>,
    pub runner: RunnerTimings,
    pub footprint: ProcessFootprint,
    pub serving: ServingCosts,
    pub host: FakeHost,
    /// Growth left behind by every switch: zero for a clean fake.
    pub leak_per_switch: ResourceSnapshot,
    /// After this many switches without a recycle, responses are corrupted.
    pub corrupt_state_after_switches: Option<u64>,
    /// Execute while loading (GPU §2.6); needs eager mode.
    pub execute_while_load: bool,
    /// Whether the same request always yields the same response.
    pub deterministic_outputs: bool,
    pub variation: Variation,
}

/// The GPU §2.2 lower bounds of one model's byte-moving operations.
#[derive(Clone, Debug, PartialEq)]
pub struct OperationBounds {
    pub cold_load: LowerBound,
    pub warm_load: LowerBound,
    pub host_read: LowerBound,
    pub sleep: LowerBound,
    pub wake: LowerBound,
}

const STORAGE: &str = "storage:read";
const HOST_MEMORY: &str = "host:memory-channels";
const HOST_TO_DEVICE: &str = "pcie:host-to-device";
const DEVICE_TO_HOST: &str = "pcie:device-to-host";

fn demand(bytes: u64, resources: &[&str]) -> Result<TransferDemand, BenchError> {
    Ok(TransferDemand {
        bytes,
        resources: resources
            .iter()
            .map(|name| ResourceId::new(*name))
            .collect::<Result<_, _>>()?,
    })
}

/// Nanoseconds as seconds.
pub fn seconds(nanos: u64) -> f64 {
    nanos as f64 / NANOS_PER_SECOND as f64
}

impl RunnerProfile {
    /// Refuses a profile the fake could not honestly simulate: an unlabelled serving
    /// category (S12), empty or repeated models, zero capacities or step times, execute
    /// while load without eager mode (GPU §2.6), a model larger than the GPU, and any
    /// duration below the GPU §2.2 lower bound for the bytes it moves.
    pub fn validate(&self) -> Result<(), BenchError> {
        if self.category.is_vm_sandbox() {
            return Err(BenchError::ServingCategoryNotLabelled);
        }
        if self.models.is_empty() {
            return Err(BenchError::InvalidParameter {
                field: "models",
                reason: "at least one model",
            });
        }
        let mut names = BTreeSet::new();
        for model in &self.models {
            if !names.insert(&model.name) {
                return Err(BenchError::DuplicateModel {
                    model: model.name.to_string(),
                });
            }
        }
        let positive = [
            ("max_num_seqs", u64::from(self.serving.max_num_seqs)),
            (
                "decode_step_base_nanos",
                self.serving.decode_step_base_nanos,
            ),
            ("vram_capacity_bytes", self.host.vram_capacity_bytes),
            (
                "pinned_host_capacity_bytes",
                self.host.pinned_host_capacity_bytes,
            ),
            ("host_memory_bytes", self.host.host_memory_bytes),
        ];
        if let Some((field, _)) = positive.iter().find(|(_, value)| *value == 0) {
            return Err(BenchError::InvalidParameter {
                field,
                reason: "must be more than zero",
            });
        }
        for model in &self.models {
            if model.weights_bytes == 0 || model.layer_groups == 0 {
                return Err(BenchError::InvalidParameter {
                    field: "models",
                    reason: "weights and layer groups must be more than zero",
                });
            }
            let alone = model
                .weights_bytes
                .saturating_add(self.footprint.context_vram_bytes);
            if alone > self.host.vram_capacity_bytes {
                return Err(BenchError::Capacity {
                    resource: "vram",
                    required_bytes: alone,
                    available_bytes: self.host.vram_capacity_bytes,
                });
            }
            if self.execute_while_load
                && (model.timings.graph_capture_nanos > 0 || model.cuda_graphs > 0)
            {
                return Err(BenchError::InvalidParameter {
                    field: "execute_while_load",
                    reason:
                        "graph capture needs every weight, so execute while load needs eager mode",
                });
            }
            self.check_bounds(model)?;
        }
        Ok(())
    }

    fn check_bounds(&self, model: &ModelSpec) -> Result<(), BenchError> {
        let bounds = self.lower_bounds(model)?;
        let timings = &model.timings;
        let mut checks = vec![
            ("cold load", &bounds.cold_load, timings.cold_load_nanos),
            ("warm load", &bounds.warm_load, timings.warm_load_nanos),
            ("host read", &bounds.host_read, timings.host_read_nanos),
        ];
        if self.mode == RunnerMode::VersionSupportedSleep {
            checks.push(("sleep", &bounds.sleep, timings.sleep_nanos));
            checks.push(("wake", &bounds.wake, timings.wake_nanos));
        }
        for (operation, bound, nanos) in checks {
            match bound.check_claim(seconds(nanos)) {
                Ok(()) => {}
                Err(BoundsError::BelowLowerBound {
                    claimed_seconds,
                    lower_bound_seconds,
                }) => {
                    return Err(BenchError::BelowPhysicalBound {
                        model: model.name.to_string(),
                        operation,
                        claimed_seconds,
                        lower_bound_seconds,
                    })
                }
                Err(other) => return Err(other.into()),
            }
        }
        Ok(())
    }

    /// The GPU §2.2 bound of each byte-moving operation of `model`. Reads, verification
    /// and copies that cross the host memory channels add their bytes there, counted once
    /// per resource (§2.2 "Shared resources count once").
    pub fn lower_bounds(&self, model: &ModelSpec) -> Result<OperationBounds, BenchError> {
        let mut table = ResourceTable::new();
        for (name, bandwidth) in [
            (STORAGE, self.host.storage_read_bytes_per_second),
            (HOST_MEMORY, self.host.host_memory_bytes_per_second),
            (HOST_TO_DEVICE, self.host.host_to_device_bytes_per_second),
            (DEVICE_TO_HOST, self.host.device_to_host_bytes_per_second),
        ] {
            table.add(
                ResourceId::new(name)?,
                BandwidthRating::measured_directional(bandwidth)?,
            )?;
        }
        let bytes = model.weights_bytes;
        let bound = |demands: Vec<TransferDemand>| transfer_lower_bound(&table, &demands, 0.0);
        Ok(OperationBounds {
            // Storage into host memory, a verification read, then the copy to the GPU.
            cold_load: bound(vec![
                demand(bytes, &[STORAGE, HOST_MEMORY])?,
                demand(bytes, &[HOST_MEMORY])?,
                demand(bytes, &[HOST_MEMORY, HOST_TO_DEVICE])?,
            ])?,
            // A verification read of the host copy, then the copy to the GPU.
            warm_load: bound(vec![
                demand(bytes, &[HOST_MEMORY])?,
                demand(bytes, &[HOST_MEMORY, HOST_TO_DEVICE])?,
            ])?,
            host_read: bound(vec![demand(bytes, &[STORAGE, HOST_MEMORY])?])?,
            sleep: bound(vec![demand(bytes, &[DEVICE_TO_HOST, HOST_MEMORY])?])?,
            wake: bound(vec![demand(bytes, &[HOST_MEMORY, HOST_TO_DEVICE])?])?,
        })
    }

    /// The model named `name`.
    pub fn model(&self, name: &Label) -> Result<&ModelSpec, BenchError> {
        self.models
            .iter()
            .find(|model| &model.name == name)
            .ok_or_else(|| BenchError::UnknownModel {
                model: name.to_string(),
            })
    }

    /// The S8 runner build identity of this fake: a digest of every parameter, so any
    /// changed parameter is a different build.
    pub fn build_digest(&self) -> Result<Digest, BenchError> {
        let bytes = serde_json::to_vec(self).map_err(|_| BenchError::Encoding)?;
        Ok(digest(RUNNER_BUILD_DOMAIN, &[&bytes]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model_memory::bench::test_support::{label, profile};

    /// GPU §2.2 illustration: 14 decimal GB over a 25 GB/s host-to-device path and from a
    /// 7 GB/s storage source.
    fn fourteen_gigabyte_profile(mode: RunnerMode) -> RunnerProfile {
        let mut profile = profile(mode);
        profile.host.vram_capacity_bytes = 40_000_000_000;
        profile.host.storage_read_bytes_per_second = 7e9;
        profile.host.host_to_device_bytes_per_second = 25e9;
        profile.host.device_to_host_bytes_per_second = 25e9;
        profile.host.host_memory_bytes_per_second = 200e9;
        let model = &mut profile.models[0];
        model.weights_bytes = 14_000_000_000;
        model.timings.cold_load_nanos = 2_000_000_000;
        model.timings.warm_load_nanos = 560_000_000;
        model.timings.host_read_nanos = 2_000_000_000;
        model.timings.sleep_nanos = 560_000_000;
        model.timings.wake_nanos = 560_000_000;
        profile
    }

    #[test]
    fn the_worked_bounds_are_point_five_six_and_two_seconds() {
        let profile = fourteen_gigabyte_profile(RunnerMode::VerifiedReload);
        let bounds = profile.lower_bounds(&profile.models[0]).unwrap();
        assert_eq!(bounds.warm_load.lower_bound_seconds, 0.56);
        assert_eq!(bounds.cold_load.lower_bound_seconds, 2.0);
        assert_eq!(bounds.wake.lower_bound_seconds, 0.56);
        // Exactly at the bound is accepted.
        profile.validate().unwrap();
    }

    #[test]
    fn a_reload_in_forty_milliseconds_is_refused() {
        // §2.2: "it cannot move the same missing bytes in 40 ms".
        let mut profile = fourteen_gigabyte_profile(RunnerMode::VerifiedReload);
        profile.models[0].timings.warm_load_nanos = 40_000_000;
        match profile.validate() {
            Err(BenchError::BelowPhysicalBound {
                operation,
                claimed_seconds,
                lower_bound_seconds,
                ..
            }) => {
                assert_eq!(operation, "warm load");
                assert_eq!(claimed_seconds, 0.04);
                assert_eq!(lower_bound_seconds, 0.56);
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        let mut cold = fourteen_gigabyte_profile(RunnerMode::FullProcessRestart);
        cold.models[0].timings.cold_load_nanos = 1_999_999_999;
        assert!(matches!(
            cold.validate(),
            Err(BenchError::BelowPhysicalBound {
                operation: "cold load",
                ..
            })
        ));
    }

    #[test]
    fn shared_host_memory_counts_every_crossing_once() {
        // With slow host memory channels, the three crossings of a cold load add up there.
        let mut profile = fourteen_gigabyte_profile(RunnerMode::FullProcessRestart);
        profile.host.host_memory_bytes_per_second = 14e9;
        let bounds = profile.lower_bounds(&profile.models[0]).unwrap();
        assert_eq!(bounds.cold_load.lower_bound_seconds, 3.0);
        assert_eq!(bounds.warm_load.lower_bound_seconds, 2.0);
    }

    #[test]
    fn sleep_and_wake_are_checked_only_where_the_mode_uses_them() {
        let mut retained = fourteen_gigabyte_profile(RunnerMode::RetainedProcess);
        retained.models[0].timings.wake_nanos = 0;
        retained.validate().unwrap();
        let mut sleep = fourteen_gigabyte_profile(RunnerMode::VersionSupportedSleep);
        sleep.models[0].timings.wake_nanos = 100_000_000;
        assert!(matches!(
            sleep.validate(),
            Err(BenchError::BelowPhysicalBound {
                operation: "wake",
                ..
            })
        ));
    }

    #[test]
    fn a_serving_fake_keeps_its_vm_d4_to_d6_label() {
        let mut profile = profile(RunnerMode::RetainedProcess);
        profile.category = ExecutionCategory::VmSandbox;
        assert_eq!(
            profile.validate(),
            Err(BenchError::ServingCategoryNotLabelled)
        );
        for category in [
            ExecutionCategory::SharedKernelGpuRuntime,
            ExecutionCategory::ProviderContainerRuntime,
            ExecutionCategory::HostProcessModelRuntime,
        ] {
            profile.category = category;
            profile.validate().unwrap();
        }
    }

    #[test]
    fn malformed_profiles_are_refused() {
        let mut twice = profile(RunnerMode::VerifiedReload);
        let copy = twice.models[0].clone();
        twice.models.push(copy);
        assert!(matches!(
            twice.validate(),
            Err(BenchError::DuplicateModel { .. })
        ));

        let mut no_step = profile(RunnerMode::VerifiedReload);
        no_step.serving.decode_step_base_nanos = 0;
        assert!(no_step.validate().is_err());

        let mut too_big = profile(RunnerMode::VerifiedReload);
        too_big.host.vram_capacity_bytes = 1_000;
        assert!(matches!(
            too_big.validate(),
            Err(BenchError::Capacity {
                resource: "vram",
                ..
            })
        ));

        let mut overlap = profile(RunnerMode::VerifiedReload);
        overlap.execute_while_load = true;
        assert!(overlap.validate().is_err());

        let mut advertised = profile(RunnerMode::VerifiedReload);
        advertised.host.host_to_device_bytes_per_second = f64::NAN;
        assert!(advertised.validate().is_err());

        assert!(profile(RunnerMode::VerifiedReload)
            .model(&label("no-such-model"))
            .is_err());
    }

    #[test]
    fn cuda_checkpoint_is_not_a_park_mode() {
        // S7: CUDA checkpoint is a capability-gated experiment, not a universal park
        // operation, so none of the four baseline modes relies on it.
        assert_eq!(RunnerMode::ALL.len(), 4);
        for mode in RunnerMode::ALL {
            assert!(!mode.backend_modes().contains(&Optimization::CudaCheckpoint));
        }
    }

    #[test]
    fn any_changed_parameter_is_another_build() {
        let profile = profile(RunnerMode::VerifiedReload);
        let mut changed = profile.clone();
        changed.serving.prefill_nanos_per_token += 1;
        assert_ne!(
            profile.build_digest().unwrap(),
            changed.build_digest().unwrap()
        );
        assert_eq!(
            profile.build_digest().unwrap(),
            profile.clone().build_digest().unwrap()
        );
    }
}
