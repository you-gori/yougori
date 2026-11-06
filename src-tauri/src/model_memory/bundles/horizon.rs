//! The bounded request horizon (GPU §4.14, step 1): admitted and sufficiently likely
//! upcoming requests, the state objects they need with their reconstruction requirements,
//! the physical memory, retention and per-scope budgets, the other capacity-limited
//! resources, the trust policy and the declared objective that every term is scored in.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use crate::foundation::ids::{validate_identifier, Digest, TrustScope};
use crate::model_memory::graph::dag::Policy;
use crate::model_memory::graph::node::{
    CancellationBoundary, DemandSegment, DurationEstimate, NodeKind, ResourceUnit, SegmentEnd,
};
use crate::model_memory::graph::ResourceId;
use crate::model_memory::math::prefetch::{Objective, RawCost};
use crate::model_memory::residency::Capacity;

use super::BundleError;

/// Longest object or request id, so derived node and operation names stay within the
/// shared identifier limit.
pub const MAX_ID_LEN: usize = 48;

/// One piece of state a request can need (GPU §2.3, §4.14): weights, a processed layout,
/// an adapter, exact session state, a graph capture and so on.
#[derive(Clone, Debug, PartialEq)]
pub struct ObjectSpec {
    /// Unique within the horizon; a valid identifier of at most [`MAX_ID_LEN`] characters.
    pub id: String,
    /// What the state is; compute and response work are never state.
    pub kind: NodeKind,
    /// The semantic identity that ready state is matched by (§3.2).
    pub identity: Digest,
    /// The scope the state lives in; consumers in other scopes need an allowance.
    pub trust_scope: TrustScope,
    /// Device memory held while the object is ready; more than zero.
    pub bytes: u64,
    /// Time to make the object usable when it is not ready, measured or estimated.
    pub load: DurationEstimate,
    /// Transient demand while loading, such as a link slot or staging memory. Memory held
    /// after loading is `bytes`, never a segment here.
    pub load_demand: Vec<DemandSegment>,
    pub cancellation: CancellationBoundary,
    /// Reconstruction requirements: objects that must be ready before this one can be
    /// made ready (line 830). Descendants are never listed.
    pub requires: Vec<String>,
    /// Whether the object is on the device at the decision point. A resident object in X
    /// is retained; an absent object in X is prepared, starting now.
    pub resident: bool,
    /// Resource consumption of preparing the object when absent: bytes, energy and
    /// currency. Milliseconds are refused: latency is already inside T_r (line 808).
    pub preparation: RawCost,
    /// Interference of preparing the object with work outside the horizon, such as
    /// foreground serving delayed by the transfer.
    pub interference: RawCost,
}

/// Whether a request is admitted or a prediction (GPU §4.14 step 1, §2.9).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Admission {
    /// Admitted work: probability 1, never dropped to fit the bounds.
    Admitted,
    /// A predicted upcoming request with a calibrated probability in (0, 1].
    Predicted { probability: f64 },
}

impl Admission {
    /// 1 for admitted requests, the forecast probability otherwise.
    pub fn probability(self) -> f64 {
        match self {
            Self::Admitted => 1.0,
            Self::Predicted { probability } => probability,
        }
    }
}

/// One request of the horizon.
#[derive(Clone, Debug, PartialEq)]
pub struct RequestSpec {
    /// Unique within the horizon; a valid identifier of at most [`MAX_ID_LEN`] characters.
    pub id: String,
    /// The identity of its first-token compute.
    pub identity: Digest,
    pub trust_scope: TrustScope,
    /// The request weight w_r; more than zero.
    pub weight: f64,
    pub admission: Admission,
    /// Arrival offset from the decision point; its demand loads cannot start earlier.
    pub arrival: Duration,
    /// Objects its first-token compute needs directly.
    pub needs: Vec<String>,
    /// Compute up to the first correct token once every need is ready.
    pub compute: DurationEstimate,
    /// Transient workspace and other demand of that compute.
    pub compute_demand: Vec<DemandSegment>,
    pub cancellation: CancellationBoundary,
}

/// How far the horizon reaches (GPU §4.14 step 1: a bounded graph).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HorizonBounds {
    /// Predicted requests below this probability are left out.
    pub min_probability: f64,
    /// Requests included at most.
    pub max_requests: usize,
    /// Distinct objects the included requests may need in total.
    pub max_objects: usize,
}

/// Everything a horizon is built from.
#[derive(Clone, Debug, PartialEq)]
pub struct HorizonSpec {
    pub objects: Vec<ObjectSpec>,
    pub requests: Vec<RequestSpec>,
    /// The device memory resource every object's bytes are held on.
    pub memory: ResourceId,
    /// Device memory granted to this planner by the CORE-03 ledger. Only physical
    /// capacity counts: an address reservation supplies none (§2.7) and is refused.
    pub memory_capacity: Capacity,
    /// Bytes the retained and prepared set X may hold; less than the memory capacity, so
    /// requests keep transient room.
    pub retention_budget_bytes: u64,
    /// Optional per-scope limits on X; when any is declared every object's scope must be.
    pub scope_budgets: Vec<(TrustScope, u64)>,
    /// Other capacity-limited resources, such as shared links and staging pools.
    pub capacities: Vec<(ResourceId, ResourceUnit, u64)>,
    /// Cross-scope allowances, each naming producer scope, consumer scope and identity.
    pub policy: Policy,
    /// The declared objective all terms are scored in (GPU §2.9, §4.14 line 808).
    pub objective: Objective,
    pub bounds: HorizonBounds,
}

/// Why a request was left out of the horizon.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exclusion {
    /// A prediction below [`HorizonBounds::min_probability`].
    BelowMinimumProbability,
    /// [`HorizonBounds::max_requests`] was already reached.
    RequestBound,
    /// Its objects would pass [`HorizonBounds::max_objects`].
    ObjectBound,
}

/// A set of objects of one horizon, by index: the X of GPU §4.14.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Selection(BTreeSet<usize>);

impl Selection {
    /// X = empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// The objects at these indices.
    pub fn from_indices(indices: impl IntoIterator<Item = usize>) -> Self {
        Self(indices.into_iter().collect())
    }

    /// Whether the object at `object` is in X.
    pub fn contains(&self, object: usize) -> bool {
        self.0.contains(&object)
    }

    /// Adds an object; false when it was already in X.
    pub fn insert(&mut self, object: usize) -> bool {
        self.0.insert(object)
    }

    /// Objects in X.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether X is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Object indices, ascending.
    pub fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        self.0.iter().copied()
    }

    /// X with the objects of `other` added.
    pub fn union(&self, other: &Selection) -> Selection {
        Self(self.0.union(&other.0).copied().collect())
    }

    /// X without the objects of `other`.
    pub fn difference(&self, other: &Selection) -> Selection {
        Self(self.0.difference(&other.0).copied().collect())
    }

    /// Whether every object of X is in `other`.
    pub fn is_subset(&self, other: &Selection) -> bool {
        self.0.is_subset(&other.0)
    }
}

/// A validated, bounded horizon (GPU §4.14 step 1).
#[derive(Clone, Debug)]
pub struct Horizon {
    spec: HorizonSpec,
    memory_capacity_bytes: u64,
    object_index: BTreeMap<String, usize>,
    requires: Vec<Vec<usize>>,
    included: Vec<usize>,
    excluded: Vec<(String, Exclusion)>,
    needs: Vec<Vec<usize>>,
    requesters: Vec<Vec<usize>>,
    scope_budgets: BTreeMap<TrustScope, u64>,
}

fn check_id(field: &'static str, id: &str) -> Result<(), BundleError> {
    if id.len() > MAX_ID_LEN || validate_identifier(id).is_err() {
        return Err(BundleError::InvalidId {
            field,
            value: id.to_string(),
        });
    }
    Ok(())
}

fn check_cost(field: &'static str, cost: &RawCost) -> Result<(), BundleError> {
    let values = [
        cost.milliseconds,
        cost.bytes,
        cost.energy_joules,
        cost.currency_units,
    ];
    if values
        .iter()
        .any(|value| !value.is_finite() || *value < 0.0)
    {
        return Err(BundleError::InvalidValue {
            field,
            reason: "costs must be finite and not negative",
        });
    }
    Ok(())
}

impl Horizon {
    /// Validates `spec` and includes requests in priority order (GPU §4.14 step 1):
    /// every admitted request, then predicted requests at or above the minimum
    /// probability, most likely first, while the request and object bounds hold.
    pub fn build(spec: HorizonSpec) -> Result<Self, BundleError> {
        if spec.retention_budget_bytes == 0 {
            return Err(BundleError::InvalidValue {
                field: "retention budget",
                reason: "must be more than zero",
            });
        }
        let memory_capacity_bytes = match spec.memory_capacity {
            Capacity::Physical { bytes } => bytes,
            Capacity::VirtualReservation { bytes } => {
                return Err(BundleError::NotPhysicalCapacity { bytes })
            }
        };
        if spec.retention_budget_bytes >= memory_capacity_bytes {
            return Err(BundleError::InvalidValue {
                field: "retention budget",
                reason: "must leave transient room below the memory capacity",
            });
        }
        let bounds = spec.bounds;
        if !(0.0..=1.0).contains(&bounds.min_probability) {
            return Err(BundleError::InvalidValue {
                field: "minimum probability",
                reason: "must lie in [0, 1]",
            });
        }
        if bounds.max_requests == 0 || bounds.max_objects == 0 {
            return Err(BundleError::InvalidValue {
                field: "horizon bounds",
                reason: "must allow at least one request and one object",
            });
        }
        if spec.capacities.iter().any(|(id, _, _)| id == &spec.memory) {
            return Err(BundleError::Duplicate {
                field: "capacity",
                id: spec.memory.to_string(),
            });
        }

        let mut object_index = BTreeMap::new();
        for (at, object) in spec.objects.iter().enumerate() {
            check_id("object", &object.id)?;
            if object_index.insert(object.id.clone(), at).is_some() {
                return Err(BundleError::Duplicate {
                    field: "object",
                    id: object.id.clone(),
                });
            }
        }
        let mut requires = Vec::with_capacity(spec.objects.len());
        for object in &spec.objects {
            if !object.kind.can_be_ready() {
                return Err(BundleError::InvalidValue {
                    field: "object kind",
                    reason: "compute and response work are not state",
                });
            }
            if object.bytes == 0 {
                return Err(BundleError::InvalidValue {
                    field: "object bytes",
                    reason: "must be more than zero",
                });
            }
            check_cost("preparation cost", &object.preparation)?;
            check_cost("interference cost", &object.interference)?;
            if object.preparation.milliseconds != 0.0 {
                return Err(BundleError::PreparationPricesLatency {
                    object: object.id.clone(),
                });
            }
            if object.load_demand.iter().any(|segment| {
                segment.resource() == &spec.memory && segment.end() == SegmentEnd::RequestEnd
            }) {
                return Err(BundleError::InvalidValue {
                    field: "load demand",
                    reason: "memory held after loading is the object's bytes",
                });
            }
            let mut listed = Vec::with_capacity(object.requires.len());
            for requirement in &object.requires {
                let at = *object_index
                    .get(requirement)
                    .ok_or_else(|| BundleError::Unknown {
                        field: "requirement",
                        id: requirement.clone(),
                    })?;
                if listed.contains(&at) {
                    return Err(BundleError::Duplicate {
                        field: "requirement",
                        id: requirement.clone(),
                    });
                }
                let producer = &spec.objects[at];
                if !spec.policy.allows(
                    &producer.trust_scope,
                    &object.trust_scope,
                    &producer.identity,
                ) {
                    return Err(BundleError::CrossScope {
                        consumer: object.id.clone(),
                        object: requirement.clone(),
                    });
                }
                listed.push(at);
            }
            requires.push(listed);
        }
        check_acyclic(&spec.objects, &requires)?;

        let mut scope_budgets = BTreeMap::new();
        for (scope, bytes) in &spec.scope_budgets {
            if scope_budgets.insert(*scope, *bytes).is_some() {
                return Err(BundleError::Duplicate {
                    field: "scope budget",
                    id: format!("{:?}", scope.domain),
                });
            }
        }
        if !scope_budgets.is_empty() {
            if let Some(object) = spec
                .objects
                .iter()
                .find(|object| !scope_budgets.contains_key(&object.trust_scope))
            {
                return Err(BundleError::ScopeWithoutBudget {
                    object: object.id.clone(),
                });
            }
        }

        let mut request_ids = BTreeSet::new();
        let mut all_needs = Vec::with_capacity(spec.requests.len());
        for request in &spec.requests {
            check_id("request", &request.id)?;
            if !request_ids.insert(request.id.as_str()) {
                return Err(BundleError::Duplicate {
                    field: "request",
                    id: request.id.clone(),
                });
            }
            if !request.weight.is_finite() || request.weight <= 0.0 {
                return Err(BundleError::InvalidValue {
                    field: "request weight",
                    reason: "must be finite and more than zero",
                });
            }
            let probability = request.admission.probability();
            if !(probability > 0.0 && probability <= 1.0) {
                return Err(BundleError::InvalidValue {
                    field: "request probability",
                    reason: "must lie in (0, 1]",
                });
            }
            if request.needs.is_empty() {
                return Err(BundleError::InvalidValue {
                    field: "request needs",
                    reason: "a request needs at least one object",
                });
            }
            let mut needs = Vec::with_capacity(request.needs.len());
            for need in &request.needs {
                let at = *object_index.get(need).ok_or_else(|| BundleError::Unknown {
                    field: "need",
                    id: need.clone(),
                })?;
                if needs.contains(&at) {
                    return Err(BundleError::Duplicate {
                        field: "need",
                        id: need.clone(),
                    });
                }
                let object = &spec.objects[at];
                if !spec
                    .policy
                    .allows(&object.trust_scope, &request.trust_scope, &object.identity)
                {
                    return Err(BundleError::CrossScope {
                        consumer: request.id.clone(),
                        object: need.clone(),
                    });
                }
                needs.push(at);
            }
            all_needs.push(needs);
        }

        let mut horizon = Self {
            memory_capacity_bytes,
            object_index,
            requires,
            included: Vec::new(),
            excluded: Vec::new(),
            needs: Vec::new(),
            requesters: vec![Vec::new(); spec.objects.len()],
            scope_budgets,
            spec,
        };
        horizon.include(&all_needs)?;
        Ok(horizon)
    }

    fn include(&mut self, all_needs: &[Vec<usize>]) -> Result<(), BundleError> {
        let bounds = self.spec.bounds;
        let mut order: Vec<usize> = (0..self.spec.requests.len()).collect();
        let requests = &self.spec.requests;
        order.sort_by(|&a, &b| {
            let (left, right) = (&requests[a], &requests[b]);
            let predicted = |r: &RequestSpec| !matches!(r.admission, Admission::Admitted);
            predicted(left)
                .cmp(&predicted(right))
                .then(
                    right
                        .admission
                        .probability()
                        .total_cmp(&left.admission.probability()),
                )
                .then(left.arrival.cmp(&right.arrival))
                .then(a.cmp(&b))
        });
        let mut covered: BTreeSet<usize> = BTreeSet::new();
        let mut included = Vec::new();
        for at in order {
            let request = &self.spec.requests[at];
            let admitted = matches!(request.admission, Admission::Admitted);
            if !admitted && request.admission.probability() < bounds.min_probability {
                self.excluded
                    .push((request.id.clone(), Exclusion::BelowMinimumProbability));
                continue;
            }
            if included.len() >= bounds.max_requests {
                if admitted {
                    return Err(BundleError::HorizonTooLarge {
                        reason: "admitted requests exceed the request bound",
                    });
                }
                self.excluded
                    .push((request.id.clone(), Exclusion::RequestBound));
                continue;
            }
            let reach = self.reach(&all_needs[at]);
            let union = covered.union(&reach).count();
            if union > bounds.max_objects {
                if admitted {
                    return Err(BundleError::HorizonTooLarge {
                        reason: "admitted requests need more objects than the object bound",
                    });
                }
                self.excluded
                    .push((request.id.clone(), Exclusion::ObjectBound));
                continue;
            }
            covered.extend(reach);
            included.push(at);
        }
        if included.is_empty() {
            return Err(BundleError::InvalidValue {
                field: "requests",
                reason: "the horizon includes no request",
            });
        }
        included.sort_unstable();
        for (position, &at) in included.iter().enumerate() {
            for object in self.reach(&all_needs[at]) {
                self.requesters[object].push(position);
            }
            self.needs.push(all_needs[at].clone());
        }
        self.included = included;
        Ok(())
    }

    /// `needs` and every transitive reconstruction requirement of them.
    fn reach(&self, needs: &[usize]) -> BTreeSet<usize> {
        let mut seen = BTreeSet::new();
        let mut stack: Vec<usize> = needs.to_vec();
        while let Some(at) = stack.pop() {
            if seen.insert(at) {
                stack.extend(self.requires[at].iter().copied());
            }
        }
        seen
    }

    /// The specification the horizon was built from.
    pub fn spec(&self) -> &HorizonSpec {
        &self.spec
    }

    /// Physical device memory of the planner's grant.
    pub fn memory_capacity_bytes(&self) -> u64 {
        self.memory_capacity_bytes
    }

    /// Every declared object, needed or not, in declaration order.
    pub fn objects(&self) -> &[ObjectSpec] {
        &self.spec.objects
    }

    /// The object at index `at`.
    pub fn object(&self, at: usize) -> &ObjectSpec {
        &self.spec.objects[at]
    }

    /// The index of the object named `id`.
    pub fn index_of(&self, id: &str) -> Option<usize> {
        self.object_index.get(id).copied()
    }

    /// Reconstruction requirements of an object, by index.
    pub fn requirements(&self, at: usize) -> &[usize] {
        &self.requires[at]
    }

    /// Included request positions that need the object directly or through requirements.
    pub fn requesters(&self, at: usize) -> &[usize] {
        &self.requesters[at]
    }

    /// Whether any included request needs the object.
    pub fn is_needed(&self, at: usize) -> bool {
        !self.requesters[at].is_empty()
    }

    /// Objects some included request needs, ascending: the bounded dependency graph.
    pub fn needed_objects(&self) -> Vec<usize> {
        (0..self.spec.objects.len())
            .filter(|&at| self.is_needed(at))
            .collect()
    }

    /// Included requests.
    pub fn request_count(&self) -> usize {
        self.included.len()
    }

    /// The included request at `position`, in spec order.
    pub fn request(&self, position: usize) -> &RequestSpec {
        &self.spec.requests[self.included[position]]
    }

    /// Objects the included request at `position` needs directly.
    pub fn needs(&self, position: usize) -> &[usize] {
        &self.needs[position]
    }

    /// w_r times the request's probability: the expected weight (GPU §2.9).
    pub fn effective_weight(&self, position: usize) -> f64 {
        let request = self.request(position);
        request.weight * request.admission.probability()
    }

    /// The sum of every included request's effective weight.
    pub fn total_effective_weight(&self) -> f64 {
        (0..self.request_count())
            .map(|position| self.effective_weight(position))
            .sum()
    }

    /// Requests left out of the horizon, with the reason.
    pub fn excluded(&self) -> &[(String, Exclusion)] {
        &self.excluded
    }

    /// The selection of the named objects.
    pub fn selection_of(&self, ids: &[&str]) -> Result<Selection, BundleError> {
        ids.iter()
            .map(|id| {
                self.index_of(id).ok_or_else(|| BundleError::Unknown {
                    field: "object",
                    id: id.to_string(),
                })
            })
            .collect::<Result<BTreeSet<_>, _>>()
            .map(Selection)
    }

    /// The ids of a selection, ascending by index.
    pub fn ids(&self, selection: &Selection) -> Vec<&str> {
        selection
            .iter()
            .filter_map(|at| self.spec.objects.get(at))
            .map(|object| object.id.as_str())
            .collect()
    }

    /// The same objects in another horizon built from the same object list.
    pub fn translate(
        &self,
        selection: &Selection,
        other: &Horizon,
    ) -> Result<Selection, BundleError> {
        other.selection_of(&self.ids(selection))
    }

    /// Bytes the selection holds, each object once.
    pub fn bytes(&self, selection: &Selection) -> Result<u64, BundleError> {
        selection.iter().try_fold(0u64, |total, at| {
            total
                .checked_add(self.spec.objects[at].bytes)
                .ok_or(BundleError::InvalidValue {
                    field: "selection bytes",
                    reason: "do not fit in 64 bits",
                })
        })
    }

    /// The per-scope limit of `scope`, if per-scope budgets are declared.
    pub fn scope_budget(&self, scope: &TrustScope) -> Option<u64> {
        self.scope_budgets.get(scope).copied()
    }

    pub(crate) fn scope_budgets(&self) -> &BTreeMap<TrustScope, u64> {
        &self.scope_budgets
    }

    /// The dependency-closed group that makes `object` ready on top of `base` (line 830):
    /// the object, and for every absent member each requirement not already in `base`,
    /// recursively. A resident member needs nothing more, and descendants never join.
    pub fn closure(&self, object: usize, base: &Selection) -> Selection {
        let mut group = Selection::new();
        let mut stack = vec![object];
        while let Some(at) = stack.pop() {
            if base.contains(at) || !group.insert(at) {
                continue;
            }
            if !self.spec.objects[at].resident {
                stack.extend(self.requires[at].iter().copied());
            }
        }
        group
    }

    /// The first absent member of `selection` with a requirement outside it, if any.
    pub fn unclosed(&self, selection: &Selection) -> Option<(usize, usize)> {
        selection.iter().find_map(|at| {
            if self.spec.objects[at].resident {
                return None;
            }
            self.requires[at]
                .iter()
                .find(|requirement| !selection.contains(**requirement))
                .map(|&requirement| (at, requirement))
        })
    }
}

fn check_acyclic(objects: &[ObjectSpec], requires: &[Vec<usize>]) -> Result<(), BundleError> {
    // 0 unvisited, 1 on the current path, 2 done.
    let mut state = vec![0u8; objects.len()];
    for start in 0..objects.len() {
        if state[start] != 0 {
            continue;
        }
        let mut stack: Vec<(usize, usize)> = vec![(start, 0)];
        state[start] = 1;
        while let Some(&(at, next)) = stack.last() {
            match requires[at].get(next) {
                Some(&requirement) => {
                    if let Some(top) = stack.last_mut() {
                        top.1 += 1;
                    }
                    match state[requirement] {
                        0 => {
                            state[requirement] = 1;
                            stack.push((requirement, 0));
                        }
                        1 => {
                            return Err(BundleError::RequirementCycle {
                                object: objects[requirement].id.clone(),
                            })
                        }
                        _ => {}
                    }
                }
                None => {
                    state[at] = 2;
                    stack.pop();
                }
            }
        }
    }
    Ok(())
}
