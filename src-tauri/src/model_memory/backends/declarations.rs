//! The six rows of the backend/mode table as typed declarations (GPU part §3.8), with an
//! integration, capability or experiment gate for every technique (GPU part §1.1).

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::foundation::evidence::{Backend, Optimization};

/// One row of the "Backend/mode" table (GPU part §3.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModeRow {
    /// "Transformers".
    Transformers,
    /// "vLLM retained process".
    VllmRetainedProcess,
    /// "vLLM preloaded weights".
    VllmPreloadedWeights,
    /// "llama.cpp/GGUF".
    LlamaCppGguf,
    /// "SGLang", an optional later backend that evidence's backends do not include yet.
    Sglang,
    /// "CPU/Metal/other": any backend on a platform without CUDA.
    CpuMetalOther,
}

impl ModeRow {
    /// The rows in table order.
    pub const ALL: [Self; 6] = [
        Self::Transformers,
        Self::VllmRetainedProcess,
        Self::VllmPreloadedWeights,
        Self::LlamaCppGguf,
        Self::Sglang,
        Self::CpuMetalOther,
    ];

    /// The evidence backend the row is about. `None` for SGLang, which evidence does not
    /// name, and for CPU/Metal/other, which applies to any backend off CUDA.
    pub const fn backend(self) -> Option<Backend> {
        match self {
            Self::Transformers => Some(Backend::Transformers),
            Self::VllmRetainedProcess | Self::VllmPreloadedWeights => Some(Backend::Vllm),
            Self::LlamaCppGguf => Some(Backend::LlamaCpp),
            Self::Sglang | Self::CpuMetalOther => None,
        }
    }

    /// The row's "Critical boundary" cell.
    pub const fn critical_boundary(self) -> CriticalBoundary {
        match self {
            Self::Transformers => CriticalBoundary::RematerializeBuffersAndPreserveTiedWeights,
            Self::VllmRetainedProcess => CriticalBoundary::NoSessionPreservationAcrossSleep,
            Self::VllmPreloadedWeights => CriticalBoundary::ZeroCopyExcludesSleepOffload,
            Self::LlamaCppGguf => CriticalBoundary::NoGgufConversionToResembleAnotherBackend,
            Self::Sglang => CriticalBoundary::NoSecondDefaultEngineWithoutAttributableBenefit,
            Self::CpuMetalOther => CriticalBoundary::NoSilentCudaAssumption,
        }
    }

    /// The row as the table declares it: its "First implementation" and "Later
    /// experiment" techniques in cell order, and its critical boundary.
    pub fn declaration(self) -> ModeDeclaration {
        let of_stage = |stage: Stage| {
            Technique::ALL
                .into_iter()
                .filter(|technique| technique.row() == self && technique.stage() == stage)
                .collect()
        };
        ModeDeclaration {
            row: self,
            first_implementation: of_stage(Stage::FirstImplementation),
            later_experiment: of_stage(Stage::LaterExperiment),
            critical_boundary: self.critical_boundary(),
        }
    }
}

impl fmt::Display for ModeRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Transformers => "Transformers",
            Self::VllmRetainedProcess => "vLLM retained process",
            Self::VllmPreloadedWeights => "vLLM preloaded weights",
            Self::LlamaCppGguf => "llama.cpp/GGUF",
            Self::Sglang => "SGLang",
            Self::CpuMetalOther => "CPU/Metal/other",
        })
    }
}

/// The table column a technique is declared in (GPU part §3.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// "First implementation".
    FirstImplementation,
    /// "Later experiment".
    LaterExperiment,
}

/// A feature the pinned backend release reports when its capabilities are queried (GPU
/// part §3.8: "where supported"; "Query the pinned backend's capabilities").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PinnedFeature {
    /// Building the model on the meta device before loading it (Transformers, "meta
    /// construction where supported"), for the model the query was made with.
    MetaConstruction,
    /// Keeping the server process between requests (llama.cpp, "persistent process where
    /// supported").
    PersistentProcess,
    /// Waking the weights and the KV cache in separate calls, so a weight reload can run
    /// between them (vLLM wake-up tags).
    StagedWake,
}

impl fmt::Display for PinnedFeature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MetaConstruction => "meta construction",
            Self::PersistentProcess => "a persistent process",
            Self::StagedWake => "staged wake",
        })
    }
}

/// The condition of a capability gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityCondition {
    /// Evidence's loader gate enabled this backend mode on the runtime, which needs a
    /// release with a recorded rule ("version-supported", "supported daemon").
    BackendMode { mode: Optimization },
    /// The pinned release reported the feature when queried ("where supported").
    PinnedFeature { feature: PinnedFeature },
}

/// What decides whether a technique may run (GPU part §1.1: "integration, experiment or
/// capability gate for every technique").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TechniqueGate {
    /// Existing behaviour, or first-implementation work with no further condition.
    Integration,
    /// Runs only where the condition holds for the exact runtime.
    Capability { condition: CapabilityCondition },
    /// A later experiment: off unless approved for the exact release.
    Experiment,
}

/// A technique named in a row's "First implementation" or "Later experiment" cell (GPU
/// part §3.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Technique {
    /// Transformers: "Existing loader baseline".
    ExistingLoaderBaseline,
    /// Transformers: "meta construction where supported".
    MetaConstruction,
    /// Transformers: "bulk indexed load".
    BulkIndexedLoad,
    /// Transformers, later: "Fixed-address arena ... for selected architectures", built on
    /// CUDA VMM (GPU part §3.7).
    FixedAddressArena,
    /// Transformers, later: "explicit dependency groups for selected architectures".
    ExplicitDependencyGroups,
    /// vLLM retained process: "Version-supported sleep/wake".
    VersionSupportedSleepWake,
    /// vLLM retained process: "normal loader".
    NormalLoader,
    /// vLLM retained process, later: "Tuned loaders".
    TunedLoaders,
    /// vLLM retained process, later: "graphs", CUDA graph capture, which today's
    /// `--enforce-eager` turns off (Appendix A.1).
    CudaGraphs,
    /// vLLM retained process, later: "concurrency", which today's `--max-num-seqs 1`
    /// limits (Appendix A.1).
    Concurrency,
    /// vLLM preloaded weights: "Separate version-upgrade pilot using supported daemon".
    PreloadDaemonPilot,
    /// vLLM preloaded weights, later: "Controlled sharing across eligible local
    /// consumers".
    ControlledLocalSharing,
    /// llama.cpp/GGUF: "Existing mmap/prequantized path".
    ExistingMmapPrequantizedPath,
    /// llama.cpp/GGUF: "persistent process where supported".
    PersistentProcess,
    /// llama.cpp/GGUF, later: "Readahead ... tuning".
    ReadaheadTuning,
    /// llama.cpp/GGUF, later: "NUMA ... tuning".
    NumaTuning,
    /// llama.cpp/GGUF, later: "offload tuning".
    OffloadTuning,
    /// SGLang: "Optional later backend using upstream facilities"; an optional engine,
    /// never a default without an attributable benefit (see `EngineRoster`).
    OptionalUpstreamBackend,
    /// SGLang, later: "R-Fork/fabric sharing on compatible machines".
    RForkFabricSharing,
    /// CPU/Metal/other: "Existing supported path".
    ExistingSupportedPath,
    /// CPU/Metal/other: "truthful capability report" (see
    /// `BackendRuntime::capability_report`).
    TruthfulCapabilityReport,
    /// CPU/Metal/other, later: "Backend-specific cache improvements".
    BackendSpecificCacheImprovements,
}

impl Technique {
    /// Every technique, in table order.
    pub const ALL: [Self; 22] = [
        Self::ExistingLoaderBaseline,
        Self::MetaConstruction,
        Self::BulkIndexedLoad,
        Self::FixedAddressArena,
        Self::ExplicitDependencyGroups,
        Self::VersionSupportedSleepWake,
        Self::NormalLoader,
        Self::TunedLoaders,
        Self::CudaGraphs,
        Self::Concurrency,
        Self::PreloadDaemonPilot,
        Self::ControlledLocalSharing,
        Self::ExistingMmapPrequantizedPath,
        Self::PersistentProcess,
        Self::ReadaheadTuning,
        Self::NumaTuning,
        Self::OffloadTuning,
        Self::OptionalUpstreamBackend,
        Self::RForkFabricSharing,
        Self::ExistingSupportedPath,
        Self::TruthfulCapabilityReport,
        Self::BackendSpecificCacheImprovements,
    ];

    /// The row whose cell names the technique.
    pub const fn row(self) -> ModeRow {
        match self {
            Self::ExistingLoaderBaseline
            | Self::MetaConstruction
            | Self::BulkIndexedLoad
            | Self::FixedAddressArena
            | Self::ExplicitDependencyGroups => ModeRow::Transformers,
            Self::VersionSupportedSleepWake
            | Self::NormalLoader
            | Self::TunedLoaders
            | Self::CudaGraphs
            | Self::Concurrency => ModeRow::VllmRetainedProcess,
            Self::PreloadDaemonPilot | Self::ControlledLocalSharing => {
                ModeRow::VllmPreloadedWeights
            }
            Self::ExistingMmapPrequantizedPath
            | Self::PersistentProcess
            | Self::ReadaheadTuning
            | Self::NumaTuning
            | Self::OffloadTuning => ModeRow::LlamaCppGguf,
            Self::OptionalUpstreamBackend | Self::RForkFabricSharing => ModeRow::Sglang,
            Self::ExistingSupportedPath
            | Self::TruthfulCapabilityReport
            | Self::BackendSpecificCacheImprovements => ModeRow::CpuMetalOther,
        }
    }

    /// The column whose cell names the technique.
    pub const fn stage(self) -> Stage {
        match self {
            Self::FixedAddressArena
            | Self::ExplicitDependencyGroups
            | Self::TunedLoaders
            | Self::CudaGraphs
            | Self::Concurrency
            | Self::ControlledLocalSharing
            | Self::ReadaheadTuning
            | Self::NumaTuning
            | Self::OffloadTuning
            | Self::RForkFabricSharing
            | Self::BackendSpecificCacheImprovements => Stage::LaterExperiment,
            Self::ExistingLoaderBaseline
            | Self::MetaConstruction
            | Self::BulkIndexedLoad
            | Self::VersionSupportedSleepWake
            | Self::NormalLoader
            | Self::PreloadDaemonPilot
            | Self::ExistingMmapPrequantizedPath
            | Self::PersistentProcess
            | Self::OptionalUpstreamBackend
            | Self::ExistingSupportedPath
            | Self::TruthfulCapabilityReport => Stage::FirstImplementation,
        }
    }

    /// The technique's gate: every later experiment is an experiment, and every "where
    /// supported", "version-supported" or "supported daemon" technique a capability.
    pub const fn gate(self) -> TechniqueGate {
        match self.stage() {
            Stage::LaterExperiment => TechniqueGate::Experiment,
            Stage::FirstImplementation => match self {
                Self::VersionSupportedSleepWake => TechniqueGate::Capability {
                    condition: CapabilityCondition::BackendMode {
                        mode: Optimization::SleepWeightOffload,
                    },
                },
                Self::PreloadDaemonPilot => TechniqueGate::Capability {
                    condition: CapabilityCondition::BackendMode {
                        mode: Optimization::ZeroCopyPreload,
                    },
                },
                Self::MetaConstruction => TechniqueGate::Capability {
                    condition: CapabilityCondition::PinnedFeature {
                        feature: PinnedFeature::MetaConstruction,
                    },
                },
                Self::PersistentProcess => TechniqueGate::Capability {
                    condition: CapabilityCondition::PinnedFeature {
                        feature: PinnedFeature::PersistentProcess,
                    },
                },
                _ => TechniqueGate::Integration,
            },
        }
    }

    /// Whether the technique is a CUDA mechanism, never assumed on CPU, Metal or other
    /// platforms (GPU part §3.8, CPU/Metal/other row). Sleep and preload are CUDA
    /// mechanisms as their backend modes are (see [`needs_cuda`]); the arena uses CUDA
    /// VMM, graphs are CUDA graphs, and preload sharing and R-Fork/fabric sharing move
    /// CUDA memory between processes or machines.
    pub const fn needs_cuda(self) -> bool {
        matches!(
            self,
            Self::FixedAddressArena
                | Self::VersionSupportedSleepWake
                | Self::CudaGraphs
                | Self::PreloadDaemonPilot
                | Self::ControlledLocalSharing
                | Self::RForkFabricSharing
        )
    }

    /// The user-facing name, worded as the table words it.
    pub const fn name(self) -> &'static str {
        match self {
            Self::ExistingLoaderBaseline => "existing loader baseline",
            Self::MetaConstruction => "meta construction",
            Self::BulkIndexedLoad => "bulk indexed load",
            Self::FixedAddressArena => "fixed-address arena",
            Self::ExplicitDependencyGroups => "explicit dependency groups",
            Self::VersionSupportedSleepWake => "version-supported sleep/wake",
            Self::NormalLoader => "normal loader",
            Self::TunedLoaders => "tuned loaders",
            Self::CudaGraphs => "graphs",
            Self::Concurrency => "concurrency",
            Self::PreloadDaemonPilot => "version-upgrade pilot using the supported daemon",
            Self::ControlledLocalSharing => "controlled sharing across eligible local consumers",
            Self::ExistingMmapPrequantizedPath => "existing mmap/prequantized path",
            Self::PersistentProcess => "persistent process",
            Self::ReadaheadTuning => "readahead tuning",
            Self::NumaTuning => "NUMA tuning",
            Self::OffloadTuning => "offload tuning",
            Self::OptionalUpstreamBackend => "optional later backend using upstream facilities",
            Self::RForkFabricSharing => "R-Fork/fabric sharing",
            Self::ExistingSupportedPath => "existing supported path",
            Self::TruthfulCapabilityReport => "truthful capability report",
            Self::BackendSpecificCacheImprovements => "backend-specific cache improvements",
        }
    }
}

impl fmt::Display for Technique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A row's "Critical boundary" cell (GPU part §3.8). Each names where it is enforced.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CriticalBoundary {
    /// Transformers; enforced by `check_materialization`.
    RematerializeBuffersAndPreserveTiedWeights,
    /// vLLM retained process; enforced by `SleepPlan`, which never advertises sessions.
    NoSessionPreservationAcrossSleep,
    /// vLLM preloaded weights; evidence's documented conflict, checked by
    /// `BackendRuntime` before any sleep or preload.
    ZeroCopyExcludesSleepOffload,
    /// llama.cpp/GGUF; enforced by `GgufConversion::approve`.
    NoGgufConversionToResembleAnotherBackend,
    /// SGLang; enforced by `EngineRoster::add_default`.
    NoSecondDefaultEngineWithoutAttributableBenefit,
    /// CPU/Metal/other; enforced by `BackendRuntime`, whatever the evidence claims.
    NoSilentCudaAssumption,
}

impl CriticalBoundary {
    /// The row the boundary belongs to.
    pub const fn row(self) -> ModeRow {
        match self {
            Self::RematerializeBuffersAndPreserveTiedWeights => ModeRow::Transformers,
            Self::NoSessionPreservationAcrossSleep => ModeRow::VllmRetainedProcess,
            Self::ZeroCopyExcludesSleepOffload => ModeRow::VllmPreloadedWeights,
            Self::NoGgufConversionToResembleAnotherBackend => ModeRow::LlamaCppGguf,
            Self::NoSecondDefaultEngineWithoutAttributableBenefit => ModeRow::Sglang,
            Self::NoSilentCudaAssumption => ModeRow::CpuMetalOther,
        }
    }

    /// The boundary as the table states it.
    pub const fn statement(self) -> &'static str {
        match self {
            Self::RematerializeBuffersAndPreserveTiedWeights => {
                "Rematerialize buffers and preserve tied weights correctly"
            }
            Self::NoSessionPreservationAcrossSleep => {
                "Sleep can discard KV; do not advertise session preservation"
            }
            Self::ZeroCopyExcludesSleepOffload => {
                "Zero-copy mode cannot be combined with sleep weight offloading"
            }
            Self::NoGgufConversionToResembleAnotherBackend => {
                "Do not convert GGUF solely to make it resemble another backend"
            }
            Self::NoSecondDefaultEngineWithoutAttributableBenefit => {
                "Do not add a second default engine without an attributable benefit"
            }
            Self::NoSilentCudaAssumption => "CUDA mechanisms are not silently assumed",
        }
    }
}

impl fmt::Display for CriticalBoundary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.statement())
    }
}

/// One row as the table declares it (GPU part §3.8).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ModeDeclaration {
    pub row: ModeRow,
    pub first_implementation: Vec<Technique>,
    pub later_experiment: Vec<Technique>,
    pub critical_boundary: CriticalBoundary,
}

/// The platform a runtime computes on (GPU part §3.8, CPU/Metal/other row). A runtime
/// whose platform is not known is `Other`, never CUDA.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComputePlatform {
    /// An NVIDIA GPU through CUDA.
    Cuda,
    /// The CPU only.
    Cpu,
    /// Apple Metal, as the native macOS runner uses it.
    Metal,
    /// Any other or unknown platform.
    Other,
}

impl ComputePlatform {
    /// Whether CUDA mechanisms can exist here at all; they still need evidence.
    pub const fn is_cuda(self) -> bool {
        matches!(self, Self::Cuda)
    }
}

impl fmt::Display for ComputePlatform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Cuda => "CUDA",
            Self::Cpu => "CPU",
            Self::Metal => "Metal",
            Self::Other => "a platform without CUDA",
        })
    }
}

/// Whether an evidence optimization is a CUDA mechanism, never assumed on CPU, Metal or
/// other platforms (GPU part §3.8).
///
/// The CUDA IPC families, GPUDirect Storage and CUDA checkpoint are CUDA APIs. vLLM
/// implements sleep-mode weight offloading and discarding with CUDA memory APIs and shares
/// zero-copy preloaded weights through CUDA IPC. io_uring is a kernel facility.
/// Execute-while-load is not classified yet (GPU-W07 names no platform), so it counts as
/// CUDA, as anything evidence adds does until it is classified here.
pub const fn needs_cuda(optimization: Optimization) -> bool {
    !matches!(optimization, Optimization::IoUring)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    /// A row as the plan's table writes it: name, first implementation, later experiment
    /// and critical boundary.
    type TableRow = (
        ModeRow,
        &'static str,
        &'static [Technique],
        &'static [Technique],
        &'static str,
    );

    #[test]
    fn the_six_rows_match_the_table() {
        use Technique::*;
        let expected: [TableRow; 6] = [
            (
                ModeRow::Transformers,
                "Transformers",
                &[ExistingLoaderBaseline, MetaConstruction, BulkIndexedLoad],
                &[FixedAddressArena, ExplicitDependencyGroups],
                "Rematerialize buffers and preserve tied weights correctly",
            ),
            (
                ModeRow::VllmRetainedProcess,
                "vLLM retained process",
                &[VersionSupportedSleepWake, NormalLoader],
                &[TunedLoaders, CudaGraphs, Concurrency],
                "Sleep can discard KV; do not advertise session preservation",
            ),
            (
                ModeRow::VllmPreloadedWeights,
                "vLLM preloaded weights",
                &[PreloadDaemonPilot],
                &[ControlledLocalSharing],
                "Zero-copy mode cannot be combined with sleep weight offloading",
            ),
            (
                ModeRow::LlamaCppGguf,
                "llama.cpp/GGUF",
                &[ExistingMmapPrequantizedPath, PersistentProcess],
                &[ReadaheadTuning, NumaTuning, OffloadTuning],
                "Do not convert GGUF solely to make it resemble another backend",
            ),
            (
                ModeRow::Sglang,
                "SGLang",
                &[OptionalUpstreamBackend],
                &[RForkFabricSharing],
                "Do not add a second default engine without an attributable benefit",
            ),
            (
                ModeRow::CpuMetalOther,
                "CPU/Metal/other",
                &[ExistingSupportedPath, TruthfulCapabilityReport],
                &[BackendSpecificCacheImprovements],
                "CUDA mechanisms are not silently assumed",
            ),
        ];
        assert_eq!(
            ModeRow::ALL.to_vec(),
            expected.iter().map(|row| row.0).collect::<Vec<_>>()
        );
        for (row, name, first, later, boundary) in expected {
            let declaration = row.declaration();
            assert_eq!(row.to_string(), name);
            assert_eq!(declaration.row, row);
            assert_eq!(declaration.first_implementation, first);
            assert_eq!(declaration.later_experiment, later);
            assert_eq!(declaration.critical_boundary.statement(), boundary);
            assert_eq!(declaration.critical_boundary.row(), row);
        }
    }

    #[test]
    fn every_technique_sits_in_one_cell_with_a_gate() {
        let mut seen = BTreeSet::new();
        for row in ModeRow::ALL {
            let declaration = row.declaration();
            for technique in declaration.first_implementation {
                assert!(seen.insert(technique), "{technique:?} appears twice");
                assert_ne!(technique.gate(), TechniqueGate::Experiment);
            }
            for technique in declaration.later_experiment {
                assert!(seen.insert(technique), "{technique:?} appears twice");
                assert_eq!(technique.gate(), TechniqueGate::Experiment);
            }
        }
        assert_eq!(seen, Technique::ALL.into_iter().collect());
        for technique in Technique::ALL {
            assert!(!technique.name().is_empty());
        }
    }

    #[test]
    fn existing_facilities_come_before_a_custom_arena() {
        // GPU part §1.1: "Evaluate existing sleep, adapter, bulk-loader and preload
        // facilities first"; adapters are §3.9's.
        for existing in [
            Technique::VersionSupportedSleepWake,
            Technique::BulkIndexedLoad,
            Technique::PreloadDaemonPilot,
            Technique::ExistingLoaderBaseline,
            Technique::NormalLoader,
            Technique::ExistingMmapPrequantizedPath,
        ] {
            assert_eq!(existing.stage(), Stage::FirstImplementation, "{existing:?}");
        }
        for custom in [
            Technique::FixedAddressArena,
            Technique::ExplicitDependencyGroups,
        ] {
            assert_eq!(custom.stage(), Stage::LaterExperiment, "{custom:?}");
            assert_eq!(custom.gate(), TechniqueGate::Experiment);
        }
    }

    #[test]
    fn capability_gates_follow_the_cell_wording() {
        let mode = |mode| TechniqueGate::Capability {
            condition: CapabilityCondition::BackendMode { mode },
        };
        let feature = |feature| TechniqueGate::Capability {
            condition: CapabilityCondition::PinnedFeature { feature },
        };
        assert_eq!(
            Technique::VersionSupportedSleepWake.gate(),
            mode(Optimization::SleepWeightOffload)
        );
        assert_eq!(
            Technique::PreloadDaemonPilot.gate(),
            mode(Optimization::ZeroCopyPreload)
        );
        assert_eq!(
            Technique::MetaConstruction.gate(),
            feature(PinnedFeature::MetaConstruction)
        );
        assert_eq!(
            Technique::PersistentProcess.gate(),
            feature(PinnedFeature::PersistentProcess)
        );
        for technique in [
            Technique::ExistingLoaderBaseline,
            Technique::BulkIndexedLoad,
            Technique::NormalLoader,
            Technique::ExistingMmapPrequantizedPath,
            Technique::OptionalUpstreamBackend,
            Technique::ExistingSupportedPath,
            Technique::TruthfulCapabilityReport,
        ] {
            assert_eq!(technique.gate(), TechniqueGate::Integration);
        }
    }

    #[test]
    fn cuda_mechanisms_are_classified() {
        for optimization in Optimization::ALL {
            assert_eq!(
                needs_cuda(optimization),
                optimization != Optimization::IoUring
            );
        }
        for technique in Technique::ALL {
            if let TechniqueGate::Capability {
                condition: CapabilityCondition::BackendMode { mode },
            } = technique.gate()
            {
                assert_eq!(technique.needs_cuda(), needs_cuda(mode), "{technique:?}");
            }
            if technique.row() == ModeRow::CpuMetalOther {
                assert!(!technique.needs_cuda(), "{technique:?}");
            }
        }
        assert!(ComputePlatform::Cuda.is_cuda());
        for platform in [
            ComputePlatform::Cpu,
            ComputePlatform::Metal,
            ComputePlatform::Other,
        ] {
            assert!(!platform.is_cuda());
        }
    }

    #[test]
    fn rows_name_their_evidence_backend() {
        assert_eq!(ModeRow::Transformers.backend(), Some(Backend::Transformers));
        assert_eq!(ModeRow::VllmRetainedProcess.backend(), Some(Backend::Vllm));
        assert_eq!(ModeRow::VllmPreloadedWeights.backend(), Some(Backend::Vllm));
        assert_eq!(ModeRow::LlamaCppGguf.backend(), Some(Backend::LlamaCpp));
        assert_eq!(ModeRow::Sglang.backend(), None);
        assert_eq!(ModeRow::CpuMetalOther.backend(), None);
    }

    #[test]
    fn declarations_serialize_with_snake_case_names() {
        let json = serde_json::to_value(ModeRow::VllmPreloadedWeights.declaration()).unwrap();
        assert_eq!(json["row"], "vllm_preloaded_weights");
        assert_eq!(
            json["first_implementation"],
            serde_json::json!(["preload_daemon_pilot"])
        );
        assert_eq!(
            json["critical_boundary"],
            "zero_copy_excludes_sleep_offload"
        );
        assert_eq!(
            serde_json::to_value(Technique::VersionSupportedSleepWake.gate()).unwrap(),
            serde_json::json!({"capability": {"condition": {"backend_mode": {"mode": "sleep_weight_offload"}}}})
        );
        assert_eq!(
            serde_json::from_str::<Technique>("\"r_fork_fabric_sharing\"").unwrap(),
            Technique::RForkFabricSharing
        );
    }
}
