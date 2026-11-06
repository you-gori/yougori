//! The GPU §2.7 admission inequality for one device and every time interval:
//!
//! ```text
//! unique_resident_weights + KV + adapters + contexts + graph_pools
//!   + peak_workspaces + staging + activation_overlap + safety_reserve
//!   <= usable_VRAM
//! ```
//!
//! Immutable weights and adapters are counted per physical allocation, so an allocation
//! that several processes map counts once; equal content in two allocations counts twice.
//! An allocation must stay resident for as long as any process maps it, because a mapping
//! keeps its physical memory (§3.7, line 607). Each process's context, KV, graph pools and
//! scratch count separately. KV must be bounded. Demand is piecewise constant in time and
//! checked on every piece, so a transient peak is refused even when the average fits.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Serialize;

use crate::foundation::ids::{Digest, GpuDeviceKey, TrustScope};

use super::{add_bytes, check_name, pieces, time_weighted_average, Capacity, InputError, Interval};

/// What an immutable physical allocation holds (GPU §2.7, §3.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum ImmutableKind {
    /// Model weights: the `unique_resident_weights` term.
    Weights,
    /// Adapter weights: the `adapters` term.
    Adapter,
}

/// One physical allocation of immutable bytes on the device. It counts once for as long
/// as it is resident, however many processes map it (GPU §2.7; §3.4: physical
/// allocations and references, not merely mapped bytes). Its resident interval must
/// contain the lifetime of every process that maps it (§3.7, line 607).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImmutableAllocation {
    /// Identity of the physical allocation on this device; not a content digest.
    pub key: String,
    pub kind: ImmutableKind,
    pub bytes: u64,
    /// The only trust scope whose processes may map it (S3.3: processed-weight sharing
    /// needs an explicitly compatible trust/runtime domain). Equal bytes are not
    /// permission: an allocation counts once because processes map the same physical
    /// allocation, which they may do only inside one scope.
    pub sharing_domain: TrustScope,
    pub resident: Interval,
}

/// Explicit context and concurrency limits that bound a process's KV (GPU §2.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KvLimits {
    pub max_concurrent_sequences: u64,
    pub max_context_tokens: u64,
    /// Tokens per KV block; the bound rounds every sequence up to whole blocks.
    pub block_tokens: u64,
    /// KV bytes one token occupies across all layers on this device.
    pub bytes_per_token: u64,
}

impl KvLimits {
    /// `max_concurrent_sequences × ceil(max_context_tokens / block_tokens) × block_tokens
    /// × bytes_per_token`: every sequence at full context, in whole blocks (GPU §2.7).
    pub fn bound_bytes(&self) -> Result<u64, InputError> {
        for (field, value) in [
            ("max concurrent sequences", self.max_concurrent_sequences),
            ("max context tokens", self.max_context_tokens),
            ("KV block tokens", self.block_tokens),
            ("KV bytes per token", self.bytes_per_token),
        ] {
            if value == 0 {
                return Err(InputError::NotPositive { field });
            }
        }
        self.max_context_tokens
            .div_ceil(self.block_tokens)
            .checked_mul(self.block_tokens)
            .and_then(|tokens| tokens.checked_mul(self.bytes_per_token))
            .and_then(|sequence_bytes| sequence_bytes.checked_mul(self.max_concurrent_sequences))
            .ok_or(InputError::Overflow { field: "KV bound" })
    }
}

/// How a process's KV is bounded (GPU §2.7: reserve bounded KV growth or impose explicit
/// context/concurrency limits).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KvBound {
    /// A pool reserved up front that the runner never grows past.
    Reserved { bytes: u64 },
    /// Explicit limits; the bound is [`KvLimits::bound_bytes`].
    Limits(KvLimits),
    /// No bound. Refused: unbounded growth could exceed any reservation.
    Unbounded,
}

/// A per-process term that varies over time (GPU §2.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum TransientKind {
    /// Scratch for one phase of work: the `peak_workspaces` term.
    PeakWorkspace,
    /// Device-side staging buffers for transfers: the `staging` term.
    Staging,
    /// Activations alive while later weights still load (§2.6): the `activation_overlap`
    /// term.
    ActivationOverlap,
}

/// One transient demand of a process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransientDemand {
    pub kind: TransientKind,
    pub bytes: u64,
    /// Must lie inside the process's lifetime.
    pub during: Interval,
}

/// One process's demand on the device (GPU §2.7). Its context, graph pools and KV bound
/// are held for its whole lifetime; workspaces, staging and activation overlap are
/// transient.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessVram {
    pub process: String,
    /// The process's trust scope; it maps only allocations of the same scope, category
    /// and domain alike (S3.3).
    pub sharing_domain: TrustScope,
    pub lifetime: Interval,
    /// Keys of the immutable allocations this process maps for its whole lifetime.
    pub maps: Vec<String>,
    /// The process's own device context; every process has one, so zero is refused.
    pub context_bytes: u64,
    pub graph_pool_bytes: u64,
    pub kv: KvBound,
    pub transients: Vec<TransientDemand>,
}

/// Everything admission needs for one device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VramPlan {
    /// The device key the CORE-03 ledger and placement share.
    pub device: GpuDeviceKey,
    /// The device sub-budget from the CORE-03 ledger (§3.1, line 491). Guest or driver
    /// telemetry is an observation and never raises it (S3.2).
    pub usable_vram: Capacity,
    /// Room kept for external GPU consumers (§3.1, line 491); zero is refused.
    pub safety_reserve_bytes: u64,
    pub allocations: Vec<ImmutableAllocation>,
    pub processes: Vec<ProcessVram>,
}

/// The nine terms of the GPU §2.7 inequality during one piece of time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct VramBreakdown {
    pub unique_resident_weights_bytes: u64,
    pub kv_bytes: u64,
    pub adapters_bytes: u64,
    pub contexts_bytes: u64,
    pub graph_pools_bytes: u64,
    pub peak_workspaces_bytes: u64,
    pub staging_bytes: u64,
    pub activation_overlap_bytes: u64,
    pub safety_reserve_bytes: u64,
}

impl VramBreakdown {
    fn terms(&self) -> [(&'static str, u64); 9] {
        [
            (
                "unique resident weights",
                self.unique_resident_weights_bytes,
            ),
            ("KV", self.kv_bytes),
            ("adapters", self.adapters_bytes),
            ("contexts", self.contexts_bytes),
            ("graph pools", self.graph_pools_bytes),
            ("peak workspaces", self.peak_workspaces_bytes),
            ("staging", self.staging_bytes),
            ("activation overlap", self.activation_overlap_bytes),
            ("safety reserve", self.safety_reserve_bytes),
        ]
    }

    /// The left-hand side of the inequality; `None` if it does not fit in 64 bits.
    pub fn total_bytes(&self) -> Option<u64> {
        self.terms()
            .into_iter()
            .try_fold(0u64, |total, (_, bytes)| total.checked_add(bytes))
    }

    /// The largest term, named as the plan names it; the first one on ties.
    pub fn largest_term(&self) -> (&'static str, u64) {
        self.terms()
            .into_iter()
            .fold(("unique resident weights", 0), |best, term| {
                if term.1 > best.1 {
                    term
                } else {
                    best
                }
            })
    }
}

/// Demand during one piece of time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct VramPiece {
    pub during: Interval,
    pub demand: VramBreakdown,
    pub total_bytes: u64,
}

impl VramPiece {
    /// The eight demand terms without the safety reserve: the bytes the plan itself uses,
    /// which is what a ledger reservation covers. The reserve stays unreserved headroom,
    /// and the ledger keeps its own supervisor reserve.
    pub fn demand_bytes(&self) -> u64 {
        self.total_bytes
            .saturating_sub(self.demand.safety_reserve_bytes)
    }
}

/// Demand on one device for every piece of time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VramEvaluation {
    pub device: GpuDeviceKey,
    pub usable_vram_bytes: u64,
    /// In time order; a gap where nothing is resident has no piece.
    pub pieces: Vec<VramPiece>,
}

impl VramEvaluation {
    /// The piece with the largest total, the earliest on ties.
    pub fn peak(&self) -> Option<&VramPiece> {
        self.pieces
            .iter()
            .fold(None, |best: Option<&VramPiece>, piece| match best {
                Some(best) if best.total_bytes >= piece.total_bytes => Some(best),
                _ => Some(piece),
            })
    }

    /// The earliest piece whose total exceeds the usable VRAM.
    pub fn first_over(&self) -> Option<&VramPiece> {
        self.pieces
            .iter()
            .find(|piece| piece.total_bytes > self.usable_vram_bytes)
    }

    /// Whether the inequality holds on every piece.
    pub fn fits(&self) -> bool {
        self.first_over().is_none()
    }

    /// The time-weighted mean total. Reported for comparison only: admission checks every
    /// piece, never the mean.
    pub fn average_total_bytes(&self) -> Option<u64> {
        time_weighted_average(
            self.pieces
                .iter()
                .map(|piece| (piece.during, piece.total_bytes)),
        )
    }
}

/// Where and by how much a device is overcommitted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VramOvercommit {
    pub device: GpuDeviceKey,
    pub usable_vram_bytes: u64,
    pub first_over: VramPiece,
    pub peak: VramPiece,
}

impl VramOvercommit {
    /// How far the peak exceeds the usable VRAM.
    pub fn excess_bytes(&self) -> u64 {
        self.peak.total_bytes.saturating_sub(self.usable_vram_bytes)
    }
}

/// Why a device plan was refused (GPU §2.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VramError {
    Input(InputError),
    /// The usable VRAM was given as an address reservation (§2.7).
    VirtualReservationIsNotCapacity {
        device: GpuDeviceKey,
    },
    /// The plan keeps no room for external GPU consumers (§3.1, line 491).
    NoSafetyReserve {
        device: GpuDeviceKey,
    },
    /// Two plans name the same device, which must be checked as one (§2.7: "for each
    /// device").
    DuplicateDevice {
        device: GpuDeviceKey,
    },
    /// A process maps an allocation outside the allocation's resident interval. The
    /// mapping would keep physical memory the sum no longer counts (§3.7, line 607).
    MappingOutlivesAllocation {
        allocation: String,
        process: String,
    },
    /// A process's KV can grow without bound (§2.7).
    UnboundedKv {
        process: String,
    },
    /// A process declares no context of its own (§2.7: each process's contexts count).
    MissingContext {
        process: String,
    },
    /// A process maps an allocation from another sharing domain (S3.3).
    CrossDomainSharing {
        allocation: String,
        process: String,
    },
    /// A transient demand lies outside its process's lifetime.
    OutsideLifetime {
        process: String,
    },
    /// The inequality fails on at least one piece of time.
    DoesNotFit(Box<VramOvercommit>),
}

impl fmt::Display for VramError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(error) => error.fmt(f),
            Self::VirtualReservationIsNotCapacity { device } => write!(
                f,
                "{}: an address reservation supplies no physical VRAM",
                device_label(device)
            ),
            Self::NoSafetyReserve { device } => write!(
                f,
                "{}: keep a safety reserve for GPU consumers outside managed allocations",
                device_label(device)
            ),
            Self::DuplicateDevice { device } => write!(
                f,
                "{} has two plans; one plan must hold all of its demand",
                device_label(device)
            ),
            Self::MappingOutlivesAllocation {
                allocation,
                process,
            } => write!(
                f,
                "{process} maps {allocation} beyond its resident interval; a mapping keeps \
                 physical memory, so the allocation must stay resident while it is mapped"
            ),
            Self::UnboundedKv { process } => write!(
                f,
                "{process}: reserve bounded KV growth or set explicit context and \
                 concurrency limits"
            ),
            Self::MissingContext { process } => {
                write!(
                    f,
                    "{process}: every process's own device context must be counted"
                )
            }
            Self::CrossDomainSharing {
                allocation,
                process,
            } => write!(
                f,
                "{process} maps {allocation} from another trust/runtime domain"
            ),
            Self::OutsideLifetime { process } => {
                write!(f, "{process}: a transient demand lies outside its lifetime")
            }
            Self::DoesNotFit(overcommit) => {
                let (term, bytes) = overcommit.peak.demand.largest_term();
                write!(
                    f,
                    "{}: needs {} bytes of VRAM during [{}, {}) ns but {} are usable; \
                     the largest term is {term} at {bytes} bytes",
                    device_label(&overcommit.device),
                    overcommit.peak.total_bytes,
                    overcommit.peak.during.start().as_nanos(),
                    overcommit.peak.during.end().as_nanos(),
                    overcommit.usable_vram_bytes,
                )
            }
        }
    }
}

impl std::error::Error for VramError {}

impl From<InputError> for VramError {
    fn from(error: InputError) -> Self {
        Self::Input(error)
    }
}

/// How messages name a device: the first 12 hex digits of its device and machine
/// digests. Errors carry the whole key.
pub fn device_label(device: &GpuDeviceKey) -> String {
    let short = |digest: &Digest| digest.to_hex().chars().take(12).collect::<String>();
    format!(
        "GPU {} on machine {}",
        short(&device.device),
        short(&device.machine)
    )
}

/// Validates a plan and computes its demand on every piece of time, whether or not it
/// fits (GPU §2.7).
pub fn evaluate_vram(plan: &VramPlan) -> Result<VramEvaluation, VramError> {
    let usable_vram_bytes =
        plan.usable_vram
            .physical_bytes()
            .ok_or(VramError::VirtualReservationIsNotCapacity {
                device: plan.device,
            })?;
    if usable_vram_bytes == 0 {
        return Err(InputError::NotPositive {
            field: "usable VRAM",
        }
        .into());
    }
    if plan.safety_reserve_bytes == 0 {
        return Err(VramError::NoSafetyReserve {
            device: plan.device,
        });
    }

    let mut allocations: BTreeMap<&str, &ImmutableAllocation> = BTreeMap::new();
    for allocation in &plan.allocations {
        check_name("allocation key", &allocation.key)?;
        if allocations
            .insert(allocation.key.as_str(), allocation)
            .is_some()
        {
            return Err(InputError::Duplicate {
                field: "allocation key",
                name: allocation.key.clone(),
            }
            .into());
        }
    }

    let mut processes = BTreeSet::new();
    let mut kv_bytes = Vec::with_capacity(plan.processes.len());
    for process in &plan.processes {
        check_name("process", &process.process)?;
        if !processes.insert(process.process.as_str()) {
            return Err(InputError::Duplicate {
                field: "process",
                name: process.process.clone(),
            }
            .into());
        }
        if process.context_bytes == 0 {
            return Err(VramError::MissingContext {
                process: process.process.clone(),
            });
        }
        kv_bytes.push(match process.kv {
            KvBound::Reserved { bytes } => bytes,
            KvBound::Limits(limits) => limits.bound_bytes()?,
            KvBound::Unbounded => {
                return Err(VramError::UnboundedKv {
                    process: process.process.clone(),
                })
            }
        });
        let mut mapped = BTreeSet::new();
        for key in &process.maps {
            let allocation = allocations
                .get(key.as_str())
                .ok_or_else(|| InputError::Unknown {
                    field: "mapped allocation",
                    name: key.clone(),
                })?;
            if !mapped.insert(key.as_str()) {
                return Err(InputError::Duplicate {
                    field: "mapped allocation",
                    name: key.clone(),
                }
                .into());
            }
            if allocation.sharing_domain != process.sharing_domain {
                return Err(VramError::CrossDomainSharing {
                    allocation: key.clone(),
                    process: process.process.clone(),
                });
            }
            if !allocation.resident.contains(&process.lifetime) {
                return Err(VramError::MappingOutlivesAllocation {
                    allocation: key.clone(),
                    process: process.process.clone(),
                });
            }
        }
        if process
            .transients
            .iter()
            .any(|transient| !process.lifetime.contains(&transient.during))
        {
            return Err(VramError::OutsideLifetime {
                process: process.process.clone(),
            });
        }
    }

    let intervals: Vec<Interval> = plan
        .allocations
        .iter()
        .map(|allocation| allocation.resident)
        .chain(plan.processes.iter().flat_map(|process| {
            std::iter::once(process.lifetime)
                .chain(process.transients.iter().map(|transient| transient.during))
        }))
        .collect();

    let mut evaluated = Vec::new();
    for piece in pieces(&intervals) {
        let demand = demand_during(plan, &kv_bytes, &piece)?;
        let total_bytes = demand.total_bytes().ok_or(InputError::Overflow {
            field: "VRAM demand",
        })?;
        evaluated.push(VramPiece {
            during: piece,
            demand,
            total_bytes,
        });
    }
    Ok(VramEvaluation {
        device: plan.device,
        usable_vram_bytes,
        pieces: evaluated,
    })
}

/// The breakdown during one piece. Allocations are summed from the plan's list of
/// physical allocations, never from processes' mappings, so a shared one counts once.
fn demand_during(
    plan: &VramPlan,
    kv_bytes: &[u64],
    piece: &Interval,
) -> Result<VramBreakdown, InputError> {
    const FIELD: &str = "VRAM demand";
    let mut demand = VramBreakdown {
        safety_reserve_bytes: plan.safety_reserve_bytes,
        ..VramBreakdown::default()
    };
    for allocation in &plan.allocations {
        if !allocation.resident.overlaps(piece) {
            continue;
        }
        let term = match allocation.kind {
            ImmutableKind::Weights => &mut demand.unique_resident_weights_bytes,
            ImmutableKind::Adapter => &mut demand.adapters_bytes,
        };
        *term = add_bytes(FIELD, *term, allocation.bytes)?;
    }
    for (process, kv) in plan.processes.iter().zip(kv_bytes) {
        if process.lifetime.overlaps(piece) {
            demand.kv_bytes = add_bytes(FIELD, demand.kv_bytes, *kv)?;
            demand.contexts_bytes = add_bytes(FIELD, demand.contexts_bytes, process.context_bytes)?;
            demand.graph_pools_bytes =
                add_bytes(FIELD, demand.graph_pools_bytes, process.graph_pool_bytes)?;
        }
        for transient in &process.transients {
            if !transient.during.overlaps(piece) {
                continue;
            }
            let term = match transient.kind {
                TransientKind::PeakWorkspace => &mut demand.peak_workspaces_bytes,
                TransientKind::Staging => &mut demand.staging_bytes,
                TransientKind::ActivationOverlap => &mut demand.activation_overlap_bytes,
            };
            *term = add_bytes(FIELD, *term, transient.bytes)?;
        }
    }
    Ok(demand)
}

/// Admits a device plan only if the GPU §2.7 inequality holds on every piece of time.
pub fn admit_vram(plan: &VramPlan) -> Result<VramEvaluation, VramError> {
    let evaluation = evaluate_vram(plan)?;
    if let (Some(first_over), Some(peak)) = (evaluation.first_over(), evaluation.peak()) {
        return Err(VramError::DoesNotFit(Box::new(VramOvercommit {
            device: evaluation.device,
            usable_vram_bytes: evaluation.usable_vram_bytes,
            first_over: *first_over,
            peak: *peak,
        })));
    }
    Ok(evaluation)
}

/// Admits every device ("for each device", GPU §2.7); the first device that does not fit
/// refuses the whole set.
pub fn admit_devices(plans: &[VramPlan]) -> Result<Vec<VramEvaluation>, VramError> {
    let mut devices = BTreeSet::new();
    for plan in plans {
        if !devices.insert(plan.device) {
            return Err(VramError::DuplicateDevice {
                device: plan.device,
            });
        }
    }
    plans.iter().map(admit_vram).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::ExecutionCategory;
    use crate::model_memory::residency::test_support::{gpu, span, GB, GIB, MB};

    fn domain(runtime: &str) -> TrustScope {
        TrustScope::named(
            ExecutionCategory::SharedKernelGpuRuntime,
            &format!("tenant-a/{runtime}"),
        )
    }

    fn weights(key: &str, bytes: u64, resident: Interval) -> ImmutableAllocation {
        ImmutableAllocation {
            key: key.to_string(),
            kind: ImmutableKind::Weights,
            bytes,
            sharing_domain: domain("runner"),
            resident,
        }
    }

    fn process(name: &str, maps: &[&str], kv_bytes: u64, lifetime: Interval) -> ProcessVram {
        ProcessVram {
            process: name.to_string(),
            sharing_domain: domain("runner"),
            lifetime,
            maps: maps.iter().map(|key| key.to_string()).collect(),
            context_bytes: 500 * MB,
            graph_pool_bytes: 0,
            kv: KvBound::Reserved { bytes: kv_bytes },
            transients: Vec::new(),
        }
    }

    fn plan(allocations: Vec<ImmutableAllocation>, processes: Vec<ProcessVram>) -> VramPlan {
        VramPlan {
            device: gpu("gpu0"),
            usable_vram: Capacity::Physical { bytes: 24 * GB },
            safety_reserve_bytes: GB,
            allocations,
            processes,
        }
    }

    fn overcommit<T: fmt::Debug>(result: Result<T, VramError>) -> VramOvercommit {
        match result {
            Err(VramError::DoesNotFit(overcommit)) => *overcommit,
            other => panic!("expected DoesNotFit, got {other:?}"),
        }
    }

    #[test]
    fn two_14_gb_weight_sets_do_not_fit_on_a_24_gb_gpu() {
        // Worked check of GPU §2.7, with no KV and no workspace at all.
        let refused = overcommit(admit_vram(&plan(
            vec![
                weights("w1", 14 * GB, span(0, 60)),
                weights("w2", 14 * GB, span(0, 60)),
            ],
            vec![
                process("a", &["w1"], 0, span(0, 60)),
                process("b", &["w2"], 0, span(0, 60)),
            ],
        )));
        let demand = refused.peak.demand;
        assert_eq!(demand.unique_resident_weights_bytes, 28 * GB);
        assert_eq!(demand.kv_bytes, 0);
        assert_eq!(demand.peak_workspaces_bytes, 0);
        // The weights alone exceed the device before KV and workspace.
        assert!(demand.unique_resident_weights_bytes > refused.usable_vram_bytes);
        assert_eq!(demand.largest_term(), ("unique resident weights", 28 * GB));

        // The same two weight sets held without any process are refused too.
        assert!(matches!(
            admit_vram(&plan(
                vec![
                    weights("w1", 14 * GB, span(0, 60)),
                    weights("w2", 14 * GB, span(0, 60))
                ],
                Vec::new(),
            )),
            Err(VramError::DoesNotFit(_))
        ));
    }

    #[test]
    fn shared_weights_count_once_while_kv_and_contexts_count_per_process() {
        let shared = admit_vram(&plan(
            vec![weights("w", 14 * GB, span(0, 60))],
            vec![
                process("a", &["w"], 3 * GB, span(0, 60)),
                process("b", &["w"], 3 * GB, span(0, 60)),
            ],
        ))
        .unwrap();
        let peak = shared.peak().unwrap();
        assert_eq!(peak.demand.unique_resident_weights_bytes, 14 * GB);
        assert_eq!(peak.demand.kv_bytes, 6 * GB);
        assert_eq!(peak.demand.contexts_bytes, GB);
        // 14 + 2 × 3 + 2 × 0.5 + 1 reserve = 22 GB ≤ 24 GB.
        assert_eq!(peak.total_bytes, 22 * GB);

        // Equal content loaded as two physical allocations is two weight sets.
        let copied = overcommit(admit_vram(&plan(
            vec![
                weights("w-a", 14 * GB, span(0, 60)),
                weights("w-b", 14 * GB, span(0, 60)),
            ],
            vec![
                process("a", &["w-a"], 3 * GB, span(0, 60)),
                process("b", &["w-b"], 3 * GB, span(0, 60)),
            ],
        )));
        assert_eq!(copied.peak.demand.unique_resident_weights_bytes, 28 * GB);
    }

    #[test]
    fn a_transient_peak_in_one_interval_is_refused_although_the_average_fits() {
        // 14 GB weights + 4 GB KV + 0.5 GB context + 1 GB reserve = 19.5 GB for 10 s,
        // plus 6 GB of staging during one second.
        let mut loader = process("a", &["w"], 4 * GB, span(0, 10));
        loader.transients.push(TransientDemand {
            kind: TransientKind::Staging,
            bytes: 6 * GB,
            during: span(4, 5),
        });
        let peaked = plan(vec![weights("w", 14 * GB, span(0, 10))], vec![loader]);

        let evaluation = evaluate_vram(&peaked).unwrap();
        assert_eq!(evaluation.pieces.len(), 3);
        // (19.5 × 9 + 25.5 × 1) / 10 = 20.1 GB on average, which fits.
        assert_eq!(evaluation.average_total_bytes(), Some(20_100 * MB));
        assert!(evaluation.average_total_bytes().unwrap() <= 24 * GB);

        let refused = overcommit(admit_vram(&peaked));
        assert_eq!(refused.first_over.during, span(4, 5));
        assert_eq!(refused.peak.total_bytes, 25_500 * MB);
        assert_eq!(refused.excess_bytes(), 1_500 * MB);
        assert_eq!(refused.peak.demand.staging_bytes, 6 * GB);
    }

    #[test]
    fn weights_resident_one_after_the_other_fit_where_concurrent_ones_do_not() {
        let swapped = admit_vram(&plan(
            vec![
                weights("w1", 14 * GB, span(0, 10)),
                weights("w2", 14 * GB, span(10, 20)),
            ],
            Vec::new(),
        ))
        .unwrap();
        assert_eq!(swapped.pieces.len(), 2);
        assert_eq!(swapped.peak().unwrap().total_bytes, 15 * GB);

        // One second of overlap during the swap is two weight sets at once.
        let overlapping = overcommit(admit_vram(&plan(
            vec![
                weights("w1", 14 * GB, span(0, 11)),
                weights("w2", 14 * GB, span(10, 20)),
            ],
            Vec::new(),
        )));
        assert_eq!(overlapping.first_over.during, span(10, 11));
    }

    #[test]
    fn all_nine_terms_are_summed() {
        let mut runner = process("a", &["w", "lora"], 2 * GB, span(0, 10));
        runner.graph_pool_bytes = 300 * MB;
        for (kind, bytes) in [
            (TransientKind::PeakWorkspace, 700 * MB),
            (TransientKind::Staging, 400 * MB),
            (TransientKind::ActivationOverlap, 200 * MB),
        ] {
            runner.transients.push(TransientDemand {
                kind,
                bytes,
                during: span(2, 3),
            });
        }
        let mut lora = weights("lora", 100 * MB, span(0, 10));
        lora.kind = ImmutableKind::Adapter;
        let evaluation = admit_vram(&plan(
            vec![weights("w", 14 * GB, span(0, 10)), lora],
            vec![runner],
        ))
        .unwrap();
        let peak = evaluation.peak().unwrap();
        assert_eq!(
            peak.demand,
            VramBreakdown {
                unique_resident_weights_bytes: 14 * GB,
                kv_bytes: 2 * GB,
                adapters_bytes: 100 * MB,
                contexts_bytes: 500 * MB,
                graph_pools_bytes: 300 * MB,
                peak_workspaces_bytes: 700 * MB,
                staging_bytes: 400 * MB,
                activation_overlap_bytes: 200 * MB,
                safety_reserve_bytes: GB,
            }
        );
        assert_eq!(peak.total_bytes, 19_200 * MB);
        // What a ledger reservation covers: everything but the safety reserve.
        assert_eq!(peak.demand_bytes(), 18_200 * MB);
        assert_eq!(peak.during, span(2, 3));
    }

    #[test]
    fn the_inequality_is_less_than_or_equal() {
        // 22 GB of weights + 0.5 GB context + 1 GB reserve + KV filling the rest.
        let exact = plan(
            vec![weights("w", 22 * GB, span(0, 10))],
            vec![process("a", &["w"], 500 * MB, span(0, 10))],
        );
        assert_eq!(
            admit_vram(&exact).unwrap().peak().unwrap().total_bytes,
            24 * GB
        );
        let over = plan(
            vec![weights("w", 22 * GB, span(0, 10))],
            vec![process("a", &["w"], 500 * MB + 1, span(0, 10))],
        );
        assert_eq!(overcommit(admit_vram(&over)).excess_bytes(), 1);
    }

    #[test]
    fn kv_must_be_bounded() {
        let mut unbounded = process("a", &["w"], 0, span(0, 10));
        unbounded.kv = KvBound::Unbounded;
        assert_eq!(
            admit_vram(&plan(vec![weights("w", GB, span(0, 10))], vec![unbounded])),
            Err(VramError::UnboundedKv {
                process: "a".to_string()
            })
        );
    }

    #[test]
    fn explicit_limits_bound_kv_in_whole_blocks() {
        // 32 layers × 8 KV heads × 128 dims × 2 (K and V) × 2 bytes = 128 KiB per token;
        // 4 sequences of 8,192 tokens is 4 GiB.
        let limits = KvLimits {
            max_concurrent_sequences: 4,
            max_context_tokens: 8192,
            block_tokens: 16,
            bytes_per_token: 32 * 8 * 128 * 2 * 2,
        };
        assert_eq!(limits.bound_bytes(), Ok(4 * GIB));
        // 1,000 tokens occupy 63 blocks of 16 = 1,008 tokens.
        let partial = KvLimits {
            max_concurrent_sequences: 1,
            max_context_tokens: 1000,
            block_tokens: 16,
            bytes_per_token: 1,
        };
        assert_eq!(partial.bound_bytes(), Ok(1008));
        assert_eq!(
            KvLimits {
                max_concurrent_sequences: 0,
                ..limits
            }
            .bound_bytes(),
            Err(InputError::NotPositive {
                field: "max concurrent sequences"
            })
        );
        assert_eq!(
            KvLimits {
                bytes_per_token: u64::MAX,
                ..limits
            }
            .bound_bytes(),
            Err(InputError::Overflow { field: "KV bound" })
        );

        let mut limited = process("a", &["w"], 0, span(0, 10));
        limited.kv = KvBound::Limits(limits);
        let evaluation = admit_vram(&plan(
            vec![weights("w", 14 * GB, span(0, 10))],
            vec![limited],
        ))
        .unwrap();
        assert_eq!(evaluation.peak().unwrap().demand.kv_bytes, 4 * GIB);
    }

    #[test]
    fn every_process_must_count_its_own_context() {
        let mut contextless = process("a", &["w"], 0, span(0, 10));
        contextless.context_bytes = 0;
        assert_eq!(
            admit_vram(&plan(
                vec![weights("w", GB, span(0, 10))],
                vec![contextless]
            )),
            Err(VramError::MissingContext {
                process: "a".to_string()
            })
        );
    }

    #[test]
    fn sharing_across_trust_scopes_is_refused() {
        let refused = Err(VramError::CrossDomainSharing {
            allocation: "w".to_string(),
            process: "b".to_string(),
        });
        let shared = |other: TrustScope| {
            let mut second = process("b", &["w"], 0, span(0, 10));
            second.sharing_domain = other;
            admit_vram(&plan(
                vec![weights("w", GB, span(0, 10))],
                vec![process("a", &["w"], 0, span(0, 10)), second],
            ))
        };
        // Another tenant's domain in the same category.
        let tenant_b =
            TrustScope::named(ExecutionCategory::SharedKernelGpuRuntime, "tenant-b/runner");
        assert_eq!(shared(tenant_b), refused);
        // The same domain in another execution category: both parts must match.
        let same_domain_in_a_vm = TrustScope {
            category: ExecutionCategory::VmSandbox,
            ..domain("runner")
        };
        assert_eq!(shared(same_domain_in_a_vm), refused);
        // The same scope maps the allocation and counts it once.
        let evaluation = shared(domain("runner")).unwrap();
        assert_eq!(
            evaluation
                .peak()
                .unwrap()
                .demand
                .unique_resident_weights_bytes,
            GB
        );
    }

    #[test]
    fn an_address_reservation_is_not_usable_vram() {
        let mut reserved = plan(vec![weights("w", GB, span(0, 10))], Vec::new());
        reserved.usable_vram = Capacity::VirtualReservation { bytes: 256 * GB };
        assert_eq!(
            admit_vram(&reserved),
            Err(VramError::VirtualReservationIsNotCapacity {
                device: gpu("gpu0")
            })
        );
    }

    #[test]
    fn a_safety_reserve_is_required_and_counted() {
        let mut bare = plan(vec![weights("w", GB, span(0, 10))], Vec::new());
        bare.safety_reserve_bytes = 0;
        assert_eq!(
            admit_vram(&bare),
            Err(VramError::NoSafetyReserve {
                device: gpu("gpu0")
            })
        );
        let evaluation =
            admit_vram(&plan(vec![weights("w", GB, span(0, 10))], Vec::new())).unwrap();
        assert_eq!(evaluation.peak().unwrap().demand.safety_reserve_bytes, GB);
        assert_eq!(evaluation.peak().unwrap().total_bytes, 2 * GB);
    }

    #[test]
    fn malformed_plans_are_refused() {
        let mut stray = process("a", &["w"], 0, span(0, 10));
        stray.transients.push(TransientDemand {
            kind: TransientKind::PeakWorkspace,
            bytes: GB,
            during: span(9, 11),
        });
        assert_eq!(
            admit_vram(&plan(vec![weights("w", GB, span(0, 10))], vec![stray])),
            Err(VramError::OutsideLifetime {
                process: "a".to_string()
            })
        );
        assert_eq!(
            admit_vram(&plan(
                Vec::new(),
                vec![process("a", &["missing"], 0, span(0, 10))]
            )),
            Err(VramError::Input(InputError::Unknown {
                field: "mapped allocation",
                name: "missing".to_string()
            }))
        );
        assert!(matches!(
            admit_vram(&plan(
                vec![weights("w", GB, span(0, 10))],
                vec![process("a", &["w", "w"], 0, span(0, 10))],
            )),
            Err(VramError::Input(InputError::Duplicate { .. }))
        ));
        assert!(matches!(
            admit_vram(&plan(
                vec![weights("w", GB, span(0, 10)), weights("w", GB, span(0, 10))],
                Vec::new(),
            )),
            Err(VramError::Input(InputError::Duplicate { .. }))
        ));
        assert!(matches!(
            admit_vram(&plan(
                Vec::new(),
                vec![
                    process("a", &[], 0, span(0, 10)),
                    process("a", &[], 0, span(0, 10))
                ],
            )),
            Err(VramError::Input(InputError::Duplicate { .. }))
        ));
        assert_eq!(
            admit_vram(&plan(
                vec![
                    weights("w1", u64::MAX, span(0, 10)),
                    weights("w2", 1, span(0, 10))
                ],
                Vec::new(),
            )),
            Err(VramError::Input(InputError::Overflow {
                field: "VRAM demand"
            }))
        );
        let mut nameless = plan(vec![weights("", GB, span(0, 10))], Vec::new());
        assert!(matches!(
            admit_vram(&nameless),
            Err(VramError::Input(InputError::EmptyName { .. }))
        ));
        nameless.allocations.clear();
        nameless.processes.push(process("", &[], 0, span(0, 10)));
        assert!(matches!(
            admit_vram(&nameless),
            Err(VramError::Input(InputError::EmptyName { .. }))
        ));
        let mut empty = plan(Vec::new(), Vec::new());
        empty.usable_vram = Capacity::Physical { bytes: 0 };
        assert!(matches!(
            admit_vram(&empty),
            Err(VramError::Input(InputError::NotPositive { .. }))
        ));
    }

    #[test]
    fn every_device_is_checked() {
        let fits = plan(vec![weights("w", 14 * GB, span(0, 10))], Vec::new());
        let mut over = plan(
            vec![
                weights("w1", 14 * GB, span(0, 10)),
                weights("w2", 14 * GB, span(0, 10)),
            ],
            Vec::new(),
        );
        over.device = gpu("gpu1");
        assert_eq!(admit_devices(std::slice::from_ref(&fits)).unwrap().len(), 1);
        let error = admit_devices(&[fits.clone(), over]).unwrap_err();
        let message = error.to_string();
        assert!(message.starts_with(&format!(
            "{}: needs 29000000000 bytes",
            device_label(&gpu("gpu1"))
        )));
        assert!(message.contains("the largest term is unique resident weights"));
        assert_eq!(overcommit::<()>(Err(error)).device, gpu("gpu1"));
        assert_eq!(
            admit_devices(&[fits.clone(), fits]),
            Err(VramError::DuplicateDevice {
                device: gpu("gpu0")
            })
        );
    }

    #[test]
    fn a_device_is_named_by_short_digests_and_carried_whole() {
        let device = gpu("gpu0");
        let label = device_label(&device);
        assert_eq!(
            label,
            format!(
                "GPU {} on machine {}",
                &device.device.to_hex()[..12],
                &device.machine.to_hex()[..12]
            )
        );
        assert_ne!(label, device_label(&gpu("gpu1")));
        let mut reserved = plan(Vec::new(), Vec::new());
        reserved.usable_vram = Capacity::VirtualReservation { bytes: GB };
        let error = admit_vram(&reserved).unwrap_err();
        assert!(error.to_string().starts_with(&label));
        assert_eq!(error, VramError::VirtualReservationIsNotCapacity { device });
    }

    #[test]
    fn a_mapping_never_outlives_its_allocation() {
        // The weights leave at 5 s while the process still maps them until 10 s: the sum
        // would drop them while the mapping keeps their physical memory (§3.7, line 607).
        let outlived = plan(
            vec![weights("w", 14 * GB, span(0, 5))],
            vec![process("a", &["w"], GB, span(0, 10))],
        );
        let refused = VramError::MappingOutlivesAllocation {
            allocation: "w".to_string(),
            process: "a".to_string(),
        };
        assert_eq!(admit_vram(&outlived), Err(refused.clone()));
        assert_eq!(evaluate_vram(&outlived), Err(refused));
        // Mapping before the allocation exists is refused too, never silently extended.
        let early = plan(
            vec![weights("w", 14 * GB, span(2, 10))],
            vec![process("a", &["w"], GB, span(0, 10))],
        );
        assert!(matches!(
            admit_vram(&early),
            Err(VramError::MappingOutlivesAllocation { .. })
        ));
        // A process inside the resident interval is fine.
        let inside = plan(
            vec![weights("w", 14 * GB, span(0, 10))],
            vec![process("a", &["w"], GB, span(2, 8))],
        );
        assert!(admit_vram(&inside).is_ok());
    }

    #[test]
    fn an_empty_plan_fits_with_no_pieces() {
        let evaluation = admit_vram(&plan(Vec::new(), Vec::new())).unwrap();
        assert!(evaluation.pieces.is_empty());
        assert!(evaluation.fits());
        assert_eq!(evaluation.peak(), None);
        assert_eq!(evaluation.average_total_bytes(), None);
    }
}
