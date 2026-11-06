//! Workloads for the GPU-N1 first prototype (GPU §4.14 line 834): the counterexample,
//! seeded tiny, adversarial and shared-base horizons with request histories, seeded
//! forecast errors and the realization of predicted requests.
//!
//! Randomness comes only from the seeded
//! [`SplitMix64`], so every
//! workload is a function of its seed. Durations are whole milliseconds and memory is
//! counted in abstract units of one byte, so the arithmetic stays exact.

use std::collections::BTreeSet;
use std::time::Duration;

use crate::foundation::ids::{digest, Digest, ExecutionCategory, TrustScope};
use crate::model_memory::graph::dag::Policy;
use crate::model_memory::graph::node::{
    CancellationBoundary, DemandSegment, DurationEstimate, NodeKind, ResourceUnit, SegmentEnd,
};
use crate::model_memory::graph::ResourceId;
use crate::model_memory::math::prefetch::{Objective, RawCost};
use crate::model_memory::residency::simulator::SplitMix64;
use crate::model_memory::residency::Capacity;

use super::horizon::{Admission, HorizonBounds, HorizonSpec, ObjectSpec, RequestSpec};
use super::BundleError;

const IDENTITY_DOMAIN: &str = "yougori/model-memory/bundles/workload/v1";
const TINY_SALT: u64 = 0x7469_6e79;
const ADVERSARIAL_SALT: u64 = 0x6164_7665;
const SHARED_SALT: u64 = 0x7368_6172;
const PERTURB_SALT: u64 = 0x7065_7274;
const REALIZE_SALT: u64 = 0x7265_616c;

/// A horizon specification with the request history that caching baselines replay.
#[derive(Clone, Debug, PartialEq)]
pub struct Workload {
    /// The workload family.
    pub name: &'static str,
    pub spec: HorizonSpec,
    /// Past requests, oldest first, each the list of objects it needed.
    pub history: Vec<Vec<String>>,
}

/// The device memory resource of every workload.
pub fn memory_resource() -> Result<ResourceId, BundleError> {
    Ok(ResourceId::new("gpu0.vram")?)
}

/// The shared load link of the generated workloads, counted in slots.
pub fn link_resource() -> Result<ResourceId, BundleError> {
    Ok(ResourceId::new("link0")?)
}

/// The trust scope every generated workload runs in.
pub fn workload_scope() -> TrustScope {
    TrustScope::named(
        ExecutionCategory::SharedKernelGpuRuntime,
        "bundles-workload",
    )
}

fn identity(kind: &str, workload: &str, id: &str) -> Digest {
    digest(
        IDENTITY_DOMAIN,
        &[kind.as_bytes(), workload.as_bytes(), id.as_bytes()],
    )
}

fn millis(value: u64) -> Duration {
    Duration::from_millis(value)
}

fn exact(duration: Duration) -> Result<DurationEstimate, BundleError> {
    Ok(DurationEstimate::exact(duration)?)
}

fn between(rng: &mut SplitMix64, low: u64, high: u64) -> u64 {
    low.saturating_add(
        rng.below(high.saturating_sub(low).saturating_add(1))
            .unwrap_or(0),
    )
}

fn link_slot(load: Duration) -> Result<DemandSegment, BundleError> {
    Ok(DemandSegment::transient(
        link_resource()?,
        ResourceUnit::Slots,
        1,
        Duration::ZERO,
        load,
    )?)
}

struct ObjectArgs<'a> {
    workload: &'a str,
    id: String,
    kind: NodeKind,
    bytes: u64,
    load: Duration,
    requires: Vec<String>,
    resident: bool,
    load_demand: Vec<DemandSegment>,
    preparation: RawCost,
    interference: RawCost,
}

fn object(args: ObjectArgs<'_>) -> Result<ObjectSpec, BundleError> {
    Ok(ObjectSpec {
        identity: identity("object", args.workload, &args.id),
        id: args.id,
        kind: args.kind,
        trust_scope: workload_scope(),
        bytes: args.bytes,
        load: exact(args.load)?,
        load_demand: args.load_demand,
        cancellation: CancellationBoundary::BeforeStart,
        requires: args.requires,
        resident: args.resident,
        preparation: args.preparation,
        interference: args.interference,
    })
}

fn request(
    workload: &str,
    id: String,
    needs: Vec<String>,
    admission: Admission,
    arrival: Duration,
    compute: Duration,
) -> Result<RequestSpec, BundleError> {
    Ok(RequestSpec {
        identity: identity("request", workload, &id),
        id,
        trust_scope: workload_scope(),
        weight: 1.0,
        admission,
        arrival,
        needs,
        compute: exact(compute)?,
        compute_demand: Vec::new(),
        cancellation: CancellationBoundary::BeforeStart,
    })
}

fn spec(
    objects: Vec<ObjectSpec>,
    requests: Vec<RequestSpec>,
    memory_capacity_bytes: u64,
    retention_budget_bytes: u64,
    capacities: Vec<(ResourceId, ResourceUnit, u64)>,
    objective: Objective,
    min_probability: f64,
) -> Result<HorizonSpec, BundleError> {
    Ok(HorizonSpec {
        objects,
        requests,
        memory: memory_resource()?,
        memory_capacity: Capacity::Physical {
            bytes: memory_capacity_bytes,
        },
        retention_budget_bytes,
        scope_budgets: Vec::new(),
        capacities,
        policy: Policy::new(),
        objective,
        bounds: HorizonBounds {
            min_probability,
            max_requests: 4096,
            max_objects: 4096,
        },
    })
}

/// The §4.14 toy (lines 810–818): objects a, b and c of one unit each, retention budget
/// two; request r1 waits for a and b, each available after 8 s through independent
/// paths; request r2 waits 4 s for c; equal weights; one second of compute each. Scores
/// are milliseconds of weighted delay. The history serves r1, then r2.
pub fn counterexample() -> Result<Workload, BundleError> {
    let name = "counterexample";
    let resident = |id: &str, load: u64| {
        object(ObjectArgs {
            workload: name,
            id: id.to_string(),
            kind: NodeKind::ArtifactExtent,
            bytes: 1,
            load: millis(load),
            requires: Vec::new(),
            resident: true,
            load_demand: Vec::new(),
            preparation: RawCost::default(),
            interference: RawCost::default(),
        })
    };
    let objects = vec![
        resident("a", 8_000)?,
        resident("b", 8_000)?,
        resident("c", 4_000)?,
    ];
    let requests = vec![
        request(
            name,
            "r1".to_string(),
            vec!["a".to_string(), "b".to_string()],
            Admission::Admitted,
            Duration::ZERO,
            millis(1_000),
        )?,
        request(
            name,
            "r2".to_string(),
            vec!["c".to_string()],
            Admission::Admitted,
            Duration::ZERO,
            millis(1_000),
        )?,
    ];
    Ok(Workload {
        name,
        spec: spec(
            objects,
            requests,
            3,
            2,
            Vec::new(),
            Objective::new(1.0, 0.0, 0.0, 0.0)?,
            0.0,
        )?,
        history: vec![
            vec!["a".to_string(), "b".to_string()],
            vec!["c".to_string()],
        ],
    })
}

/// One request per resident object, each object with its own bytes and load: a
/// knapsack-shaped horizon for the replacement and counterexample tests. `items` are
/// (id, bytes, load milliseconds).
pub fn independent(
    name: &'static str,
    items: &[(&str, u64, u64)],
    retention_budget_bytes: u64,
) -> Result<Workload, BundleError> {
    let mut objects = Vec::with_capacity(items.len());
    let mut requests = Vec::with_capacity(items.len());
    let mut total = 0u64;
    for &(id, bytes, load) in items {
        objects.push(object(ObjectArgs {
            workload: name,
            id: id.to_string(),
            kind: NodeKind::ArtifactExtent,
            bytes,
            load: millis(load),
            requires: Vec::new(),
            resident: true,
            load_demand: Vec::new(),
            preparation: RawCost::default(),
            interference: RawCost::default(),
        })?);
        requests.push(request(
            name,
            format!("q-{id}"),
            vec![id.to_string()],
            Admission::Admitted,
            Duration::ZERO,
            millis(1_000),
        )?);
        total = total.saturating_add(bytes);
    }
    Ok(Workload {
        name,
        spec: spec(
            objects,
            requests,
            total.saturating_add(1),
            retention_budget_bytes,
            Vec::new(),
            Objective::new(1.0, 0.0, 0.0, 0.0)?,
            0.0,
        )?,
        history: items
            .iter()
            .map(|(id, _, _)| vec![id.to_string()])
            .collect(),
    })
}

/// A seeded tiny horizon for the exhaustive comparison: 3–8 objects of mixed kinds with
/// random reconstruction requirements, residency, a shared link of one or two slots,
/// 1–3 admitted or predicted requests, and a retention budget of 30–60 % of all bytes.
pub fn tiny(seed: u64) -> Result<Workload, BundleError> {
    let name = "tiny";
    let mut rng = SplitMix64::new(seed ^ TINY_SALT);
    let count = between(&mut rng, 3, 8);
    let kinds = [
        NodeKind::ArtifactExtent,
        NodeKind::RankLayout,
        NodeKind::Adapter,
        NodeKind::KvBlock,
    ];
    let mut objects = Vec::new();
    let mut total = 0u64;
    for at in 0..count {
        let id = format!("o{at}");
        let kind = usize::try_from(between(&mut rng, 0, 3))
            .ok()
            .and_then(|at| kinds.get(at).copied())
            .unwrap_or(NodeKind::ArtifactExtent);
        let bytes = between(&mut rng, 1, 3);
        let load = millis(between(&mut rng, 1, 9) * 1_000);
        let resident = between(&mut rng, 0, 9) < 6;
        let mut requires = Vec::new();
        for earlier in 0..at {
            if requires.len() < 2 && between(&mut rng, 0, 9) < 2 {
                requires.push(format!("o{earlier}"));
            }
        }
        let load_demand = if between(&mut rng, 0, 1) == 0 {
            vec![link_slot(load)?]
        } else {
            Vec::new()
        };
        total = total.saturating_add(bytes);
        objects.push(object(ObjectArgs {
            workload: name,
            id,
            kind,
            bytes,
            load,
            requires,
            resident,
            load_demand,
            preparation: RawCost {
                bytes: bytes as f64,
                ..RawCost::default()
            },
            interference: RawCost::default(),
        })?);
    }
    let request_count = between(&mut rng, 1, 3);
    let mut requests = Vec::new();
    for position in 0..request_count {
        let wanted = between(&mut rng, 1, count.min(3));
        let mut needs = BTreeSet::new();
        while (needs.len() as u64) < wanted {
            needs.insert(between(&mut rng, 0, count - 1));
        }
        let admitted = position == 0 || between(&mut rng, 0, 9) < 6;
        let (admission, arrival) = if admitted {
            (Admission::Admitted, Duration::ZERO)
        } else {
            (
                Admission::Predicted {
                    probability: between(&mut rng, 5, 10) as f64 / 10.0,
                },
                millis(between(&mut rng, 1, 6) * 1_000),
            )
        };
        let mut spec = request(
            name,
            format!("r{position}"),
            needs.iter().map(|at| format!("o{at}")).collect(),
            admission,
            arrival,
            millis(between(&mut rng, 1, 2) * 1_000),
        )?;
        spec.weight = between(&mut rng, 1, 3) as f64;
        requests.push(spec);
    }
    let budget = (total * between(&mut rng, 30, 60) / 100).max(1);
    let link_capacity = between(&mut rng, 1, 2);
    let history = requests
        .iter()
        .map(|request| {
            request
                .needs
                .iter()
                .filter(|need| {
                    objects
                        .iter()
                        .any(|object| &&object.id == need && object.resident)
                })
                .cloned()
                .collect::<Vec<_>>()
        })
        .filter(|needs| !needs.is_empty())
        .collect();
    Ok(Workload {
        name,
        spec: spec(
            objects,
            requests,
            total + 1,
            budget,
            vec![(link_resource()?, ResourceUnit::Slots, link_capacity)],
            Objective::new(1.0, 200.0, 0.0, 0.0)?,
            0.25,
        )?,
        history,
    })
}

/// A seeded adversarial horizon: two or three barrier requests, each waiting for two or
/// three equally slow objects (8–12 s), and three decoy requests on one faster object
/// each (3–5 s); every object resident and loaded over one two-slot link. The budget
/// fits the two smallest barrier groups. The history serves each barrier once and then
/// each decoy twice, so recency and frequency favour the decoys.
pub fn adversarial(seed: u64) -> Result<Workload, BundleError> {
    let name = "adversarial";
    let mut rng = SplitMix64::new(seed ^ ADVERSARIAL_SALT);
    let groups = between(&mut rng, 2, 3);
    let mut objects = Vec::new();
    let mut requests = Vec::new();
    let mut history = Vec::new();
    let mut sizes = Vec::new();
    for group in 0..groups {
        let size = between(&mut rng, 2, 3);
        sizes.push(size);
        let mut needs = Vec::new();
        for member in 0..size {
            let id = format!("bar{group}x{member}");
            let load = millis(between(&mut rng, 8_000, 12_000));
            objects.push(object(ObjectArgs {
                workload: name,
                id: id.clone(),
                kind: NodeKind::ArtifactExtent,
                bytes: 1,
                load,
                requires: Vec::new(),
                resident: true,
                load_demand: vec![link_slot(load)?],
                preparation: RawCost::default(),
                interference: RawCost::default(),
            })?);
            needs.push(id);
        }
        history.push(needs.clone());
        requests.push(request(
            name,
            format!("bar{group}"),
            needs,
            Admission::Admitted,
            Duration::ZERO,
            millis(1_000),
        )?);
    }
    let mut decoys = Vec::new();
    for decoy in 0..3 {
        let id = format!("dec{decoy}");
        let load = millis(between(&mut rng, 3_000, 5_000));
        objects.push(object(ObjectArgs {
            workload: name,
            id: id.clone(),
            kind: NodeKind::Adapter,
            bytes: 1,
            load,
            requires: Vec::new(),
            resident: true,
            load_demand: vec![link_slot(load)?],
            preparation: RawCost::default(),
            interference: RawCost::default(),
        })?);
        requests.push(request(
            name,
            format!("dec{decoy}"),
            vec![id.clone()],
            Admission::Admitted,
            Duration::ZERO,
            millis(1_000),
        )?);
        decoys.push(id);
    }
    for _ in 0..2 {
        for id in &decoys {
            history.push(vec![id.clone()]);
        }
    }
    sizes.sort_unstable();
    let budget = sizes.iter().take(2).sum::<u64>();
    let total = objects.len() as u64;
    Ok(Workload {
        name,
        spec: spec(
            objects,
            requests,
            total + 1,
            budget,
            vec![(link_resource()?, ResourceUnit::Slots, 2)],
            Objective::new(1.0, 0.0, 0.0, 0.0)?,
            0.0,
        )?,
        history,
    })
}

/// A seeded shared-base horizon: `models` base weights (8 units, 6–10 s, with a
/// transient 2-unit staging buffer), two adapters per base and one exact session state
/// per base and adapter, all loaded over one two-slot link. Each of `requests` requests
/// needs a base chosen with Zipf popularity, one of its adapters and that session; the
/// first half is admitted and arrives now, the rest are predicted (probability 0.5–1)
/// and arrive within 10 s. The history holds twice as many requests from the same
/// distribution, and exactly the objects it used are resident. Preparing costs 50 score
/// units per byte and interferes with foreground work for 5 % of its load time.
pub fn shared_base(seed: u64, models: u64, requests: u64) -> Result<Workload, BundleError> {
    let name = "shared-base";
    if models == 0 || requests == 0 {
        return Err(BundleError::InvalidValue {
            field: "shared-base workload",
            reason: "needs at least one model and one request",
        });
    }
    let mut rng = SplitMix64::new(seed ^ SHARED_SALT);
    let memory = memory_resource()?;
    let mut draws = Vec::new();
    let popularity: Vec<u64> = (0..models)
        .map(|at| 1_000_000 / at.saturating_add(1))
        .collect();
    let total_popularity: u64 = popularity.iter().sum();
    let total_draws = requests.saturating_mul(3);
    for _ in 0..total_draws {
        let mut pick = rng.below(total_popularity).unwrap_or(0);
        let mut base = 0;
        for (at, weight) in popularity.iter().enumerate() {
            if pick < *weight {
                base = at as u64;
                break;
            }
            pick -= weight;
        }
        draws.push((base, between(&mut rng, 0, 1)));
    }
    let past = usize::try_from(requests.saturating_mul(2)).unwrap_or(usize::MAX);
    let history_draws: Vec<(u64, u64)> = draws.iter().take(past).copied().collect();
    let horizon_draws: Vec<(u64, u64)> = draws.iter().skip(past).copied().collect();
    let needs_of = |(base, adapter): (u64, u64)| {
        vec![
            format!("base{base}"),
            format!("ad{base}x{adapter}"),
            format!("kv{base}x{adapter}"),
        ]
    };
    let history: Vec<Vec<String>> = history_draws.iter().map(|&draw| needs_of(draw)).collect();
    let used: BTreeSet<&String> = history.iter().flatten().collect();

    let mut objects = Vec::new();
    let mut total = 0u64;
    for base in 0..models {
        let base_id = format!("base{base}");
        let load = millis(between(&mut rng, 6_000, 10_000));
        objects.push(object(ObjectArgs {
            workload: name,
            id: base_id.clone(),
            kind: NodeKind::ArtifactExtent,
            bytes: 8,
            load,
            requires: Vec::new(),
            resident: used.contains(&base_id),
            load_demand: vec![
                link_slot(load)?,
                DemandSegment::transient(
                    memory.clone(),
                    ResourceUnit::Bytes,
                    2,
                    Duration::ZERO,
                    load,
                )?,
            ],
            preparation: RawCost {
                bytes: 8.0,
                ..RawCost::default()
            },
            interference: RawCost {
                milliseconds: load.as_millis() as f64 * 0.05,
                ..RawCost::default()
            },
        })?);
        total += 8;
        for adapter in 0..2 {
            let adapter_id = format!("ad{base}x{adapter}");
            let adapter_load = millis(between(&mut rng, 800, 1_600));
            objects.push(object(ObjectArgs {
                workload: name,
                id: adapter_id.clone(),
                kind: NodeKind::Adapter,
                bytes: 1,
                load: adapter_load,
                requires: vec![base_id.clone()],
                resident: used.contains(&adapter_id),
                load_demand: vec![link_slot(adapter_load)?],
                preparation: RawCost {
                    bytes: 1.0,
                    ..RawCost::default()
                },
                interference: RawCost {
                    milliseconds: adapter_load.as_millis() as f64 * 0.05,
                    ..RawCost::default()
                },
            })?);
            let session_id = format!("kv{base}x{adapter}");
            let session_load = millis(between(&mut rng, 1_500, 3_000));
            objects.push(object(ObjectArgs {
                workload: name,
                id: session_id.clone(),
                kind: NodeKind::KvBlock,
                bytes: 2,
                load: session_load,
                requires: vec![base_id.clone(), adapter_id],
                resident: used.contains(&session_id),
                load_demand: vec![link_slot(session_load)?],
                preparation: RawCost {
                    bytes: 2.0,
                    ..RawCost::default()
                },
                interference: RawCost {
                    milliseconds: session_load.as_millis() as f64 * 0.05,
                    ..RawCost::default()
                },
            })?);
            total += 3;
        }
    }
    let admitted = (requests / 2).max(1);
    let mut specs = Vec::new();
    for (position, &draw) in horizon_draws.iter().enumerate() {
        let position = position as u64;
        let (admission, arrival) = if position < admitted {
            (Admission::Admitted, Duration::ZERO)
        } else {
            (
                Admission::Predicted {
                    probability: between(&mut rng, 5, 10) as f64 / 10.0,
                },
                millis(between(&mut rng, 1, 10) * 1_000),
            )
        };
        specs.push(request(
            name,
            format!("q{position}"),
            needs_of(draw),
            admission,
            arrival,
            millis(between(&mut rng, 1_000, 2_000)),
        )?);
    }
    let budget = (total * 30 / 100).max(9);
    Ok(Workload {
        name,
        spec: spec(
            objects,
            specs,
            total + 8,
            budget,
            vec![(link_resource()?, ResourceUnit::Slots, 2)],
            Objective::new(1.0, 50.0, 0.0, 0.0)?,
            0.3,
        )?,
        history,
    })
}

fn scaled_nanos(duration: Duration, factor: f64) -> Duration {
    let nanos = (duration.as_nanos() as f64 * factor).round();
    Duration::from_nanos(if nanos >= u64::MAX as f64 {
        u64::MAX
    } else {
        nanos as u64
    })
}

fn scale_estimate(
    estimate: &DurationEstimate,
    factor: f64,
) -> Result<DurationEstimate, BundleError> {
    let expected = scaled_nanos(estimate.expected(), factor).max(Duration::from_nanos(1));
    Ok(DurationEstimate::new(
        scaled_nanos(estimate.low(), factor).min(expected),
        expected,
        scaled_nanos(estimate.high(), factor).max(expected),
    )?)
}

fn scale_segment(
    segment: &DemandSegment,
    factor: f64,
    expected: Duration,
) -> Result<DemandSegment, BundleError> {
    let from = scaled_nanos(segment.from(), factor).min(expected);
    Ok(match segment.end() {
        SegmentEnd::RequestEnd => DemandSegment::retained(
            segment.resource().clone(),
            segment.unit(),
            segment.quantity(),
            from,
        )?,
        SegmentEnd::AfterStart(until) => {
            let until = scaled_nanos(until, factor).min(expected);
            if until <= from {
                return Err(BundleError::InvalidValue {
                    field: "perturbed demand",
                    reason: "a segment vanished when its duration was scaled",
                });
            }
            DemandSegment::transient(
                segment.resource().clone(),
                segment.unit(),
                segment.quantity(),
                from,
                until,
            )?
        }
    })
}

/// A factor in [1 − e, 1 + e].
fn factor(rng: &mut SplitMix64, relative_error: f64) -> f64 {
    let unit = rng.below(2_000_001).unwrap_or(1_000_000) as f64 / 1_000_000.0 - 1.0;
    1.0 + relative_error * unit
}

/// The planner's view of `spec` with seeded forecast errors (GPU §4.14 line 836): every
/// load, compute and arrival scaled by its own factor in [1 − e, 1 + e], demand segments
/// scaled with their node, and predicted probabilities shifted by up to ±e within
/// [0.05, 1]. Bytes, needs and requirements are unchanged.
pub fn perturb(
    spec: &HorizonSpec,
    seed: u64,
    relative_error: f64,
) -> Result<HorizonSpec, BundleError> {
    if !(0.0..1.0).contains(&relative_error) {
        return Err(BundleError::InvalidValue {
            field: "relative error",
            reason: "must lie in [0, 1)",
        });
    }
    let mut rng = SplitMix64::new(seed ^ PERTURB_SALT);
    let mut view = spec.clone();
    for object in &mut view.objects {
        let scale = factor(&mut rng, relative_error);
        object.load = scale_estimate(&object.load, scale)?;
        object.load_demand = object
            .load_demand
            .iter()
            .map(|segment| scale_segment(segment, scale, object.load.expected()))
            .collect::<Result<_, _>>()?;
    }
    for request in &mut view.requests {
        let scale = factor(&mut rng, relative_error);
        request.compute = scale_estimate(&request.compute, scale)?;
        request.compute_demand = request
            .compute_demand
            .iter()
            .map(|segment| scale_segment(segment, scale, request.compute.expected()))
            .collect::<Result<_, _>>()?;
        request.arrival = scaled_nanos(request.arrival, factor(&mut rng, relative_error));
        if let Admission::Predicted { probability } = request.admission {
            let shift = relative_error * (factor(&mut rng, 1.0) - 1.0);
            request.admission = Admission::Predicted {
                probability: (probability + shift).clamp(0.05, 1.0),
            };
        }
    }
    Ok(view)
}

/// Which predicted requests of `truth` arrive, drawn with their true probabilities: the
/// arrivals become admitted, the others leave. Returns the realized specification and,
/// for calibration, each predicted request's probability in `view` (1 when the view
/// admits it) with whether it arrived.
pub fn realize(
    truth: &HorizonSpec,
    view: &HorizonSpec,
    seed: u64,
) -> Result<(HorizonSpec, Vec<(f64, bool)>), BundleError> {
    let mut rng = SplitMix64::new(seed ^ REALIZE_SALT);
    let mut realized = truth.clone();
    let mut samples = Vec::new();
    realized.requests.clear();
    for request in &truth.requests {
        match request.admission {
            Admission::Admitted => realized.requests.push(request.clone()),
            Admission::Predicted { probability } => {
                let threshold = (probability * 1_000_000.0).round() as u64;
                let arrived = rng.below(1_000_000).unwrap_or(0) < threshold;
                let predicted = view
                    .requests
                    .iter()
                    .find(|other| other.id == request.id)
                    .map_or(1.0, |other| other.admission.probability());
                samples.push((predicted, arrived));
                if arrived {
                    let mut admitted = request.clone();
                    admitted.admission = Admission::Admitted;
                    realized.requests.push(admitted);
                }
            }
        }
    }
    Ok((realized, samples))
}
