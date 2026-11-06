//! The GPU §2.7 accounting applied to host memory: host RAM, pinned RAM, cgroups and the
//! WSL VM, for every time interval.
//!
//! For each scope and each piece of time:
//!
//! ```text
//! demand charged to the scope + occupied bytes + safety_reserve <= physical capacity
//! ```
//!
//! Occupied bytes include page cache and unattributed usage: page-cache bytes are not
//! free. Demand is charged to its memory scope and every enclosing scope up to host RAM,
//! so a WSL VM's memory setting never stands in for host RAM; pinned demand is also
//! charged to its pinned-memory caps. A plan has exactly one host RAM scope and at most
//! one root pinned-memory cap, the hard host-wide cap (§3.4, line 540), with any memlock
//! limits nested under it, so no demand avoids either. Reclaimable memory is not
//! guaranteed residency and a mincore estimate is advisory ([`HostCopy`]). An address
//! reservation supplies no physical capacity ([`Capacity`]).
//!
//! Each demand is one physical allocation: a copy that several processes map, such as one
//! file's page cache, is listed once.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Serialize;

use super::{add_bytes, check_name, pieces, time_weighted_average, Capacity, InputError, Interval};

/// What a host memory scope limits (GPU §2.7, §3.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum HostScopeKind {
    /// Physical host RAM: the root of every memory chain, exactly one per plan.
    HostRam,
    /// The WSL VM's memory setting, nested in host RAM.
    WslVm,
    /// A cgroup's memory limit, nested in host RAM, the WSL VM or another cgroup.
    Cgroup,
    /// A cap on page-locked memory: the hard host-wide cap (§3.4, line 540), the only
    /// root one in a plan, or a memlock limit nested under it.
    PinnedRam,
}

impl HostScopeKind {
    /// Whether the scope limits ordinary memory rather than page-locked memory.
    pub const fn limits_memory(self) -> bool {
        !matches!(self, Self::PinnedRam)
    }

    const fn allows_parent(self, parent: Option<HostScopeKind>) -> bool {
        matches!(
            (self, parent),
            (Self::HostRam, None)
                | (Self::WslVm, Some(Self::HostRam))
                | (
                    Self::Cgroup,
                    Some(Self::HostRam | Self::WslVm | Self::Cgroup)
                )
                | (Self::PinnedRam, None | Some(Self::PinnedRam))
        )
    }
}

/// Bytes already in a scope that the plan does not account for, as observed. All of them
/// are occupied; none is free capacity.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ScopeOccupancy {
    /// Anonymous and other committed memory.
    pub committed_bytes: u64,
    /// File-backed page cache: not free (§2.7), however reclaimable it looks.
    pub page_cache_bytes: u64,
    /// Usage nobody could attribute: never counted as free.
    pub unattributed_bytes: u64,
}

impl ScopeOccupancy {
    /// Every observed byte, page cache included; `None` if the sum overflows.
    pub fn occupied_bytes(&self) -> Option<u64> {
        self.committed_bytes
            .checked_add(self.page_cache_bytes)?
            .checked_add(self.unattributed_bytes)
    }
}

/// One host memory scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostScope {
    pub name: String,
    pub kind: HostScopeKind,
    /// The enclosing scope: see [`HostScopeKind`] for which kinds may nest where.
    pub parent: Option<String>,
    /// The scope's physical limit, from the CORE-03 ledger or its configuration.
    /// Observations only ever fill [`occupancy`](Self::occupancy); they never raise this
    /// (S3.2).
    pub capacity: Capacity,
    /// Zero is refused: the §2.7 inequality keeps a reserve in every scope.
    pub safety_reserve_bytes: u64,
    pub occupancy: ScopeOccupancy,
}

impl HostScope {
    /// Bytes a new demand could still use: capacity − committed − page cache −
    /// unattributed − safety reserve, or zero when the scope is already full. Page cache
    /// is subtracted like any other occupied byte, never added back (§2.7).
    pub fn free_bytes(&self) -> Result<u64, HostError> {
        let capacity = self.physical_capacity()?;
        let held = self
            .occupancy
            .occupied_bytes()
            .and_then(|occupied| occupied.checked_add(self.safety_reserve_bytes))
            .ok_or(InputError::Overflow {
                field: "host scope occupancy",
            })?;
        Ok(capacity.saturating_sub(held))
    }

    fn physical_capacity(&self) -> Result<u64, HostError> {
        self.capacity
            .physical_bytes()
            .ok_or_else(|| HostError::VirtualReservationIsNotCapacity {
                scope: self.name.clone(),
            })
    }
}

/// How a host demand is backed (GPU §2.7, §3.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum HostBacking {
    /// Ordinary process memory.
    Anonymous,
    /// Page-locked memory: also charged to its pinned-memory caps.
    Pinned,
    /// Page cache the plan relies on, such as model files read through the cache. It is
    /// charged like any other byte; relying on it never makes it guaranteed residency.
    PageCache,
}

/// One physical host allocation the model side needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostDemand {
    pub label: String,
    pub backing: HostBacking,
    pub bytes: u64,
    pub during: Interval,
    /// The innermost memory scope; every enclosing scope is charged too.
    pub memory_scope: String,
    /// The innermost pinned-memory cap: required for pinned demand, refused otherwise.
    pub pinned_scope: Option<String>,
}

/// Everything the host check needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostPlan {
    pub scopes: Vec<HostScope>,
    pub demands: Vec<HostDemand>,
}

/// One scope during one piece of time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ScopePiece {
    pub during: Interval,
    pub demand_bytes: u64,
    pub occupied_bytes: u64,
    pub safety_reserve_bytes: u64,
    pub total_bytes: u64,
}

/// One scope for every piece of time in which demand is charged to it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ScopeEvaluation {
    pub scope: String,
    pub kind: HostScopeKind,
    pub capacity_bytes: u64,
    pub pieces: Vec<ScopePiece>,
}

impl ScopeEvaluation {
    /// The piece with the largest total, the earliest on ties.
    pub fn peak(&self) -> Option<&ScopePiece> {
        self.pieces
            .iter()
            .fold(None, |best: Option<&ScopePiece>, piece| match best {
                Some(best) if best.total_bytes >= piece.total_bytes => Some(best),
                _ => Some(piece),
            })
    }

    /// The earliest piece whose total exceeds the capacity.
    pub fn first_over(&self) -> Option<&ScopePiece> {
        self.pieces
            .iter()
            .find(|piece| piece.total_bytes > self.capacity_bytes)
    }

    pub fn fits(&self) -> bool {
        self.first_over().is_none()
    }

    /// The time-weighted mean total, for comparison only: admission checks every piece.
    pub fn average_total_bytes(&self) -> Option<u64> {
        time_weighted_average(
            self.pieces
                .iter()
                .map(|piece| (piece.during, piece.total_bytes)),
        )
    }
}

/// Every scope of a host plan, in plan order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HostEvaluation {
    pub scopes: Vec<ScopeEvaluation>,
}

impl HostEvaluation {
    pub fn scope(&self, name: &str) -> Option<&ScopeEvaluation> {
        self.scopes.iter().find(|scope| scope.scope == name)
    }

    pub fn fits(&self) -> bool {
        self.scopes.iter().all(ScopeEvaluation::fits)
    }
}

/// A scope that does not fit: the limiting resource.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ScopeOvercommit {
    pub scope: String,
    pub kind: HostScopeKind,
    pub capacity_bytes: u64,
    pub first_over: ScopePiece,
    pub peak: ScopePiece,
}

impl ScopeOvercommit {
    pub fn excess_bytes(&self) -> u64 {
        self.peak.total_bytes.saturating_sub(self.capacity_bytes)
    }
}

/// Why a host plan was refused (GPU §2.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostError {
    Input(InputError),
    /// A scope's capacity was given as an address reservation (§2.7).
    VirtualReservationIsNotCapacity {
        scope: String,
    },
    /// A scope keeps no safety reserve.
    NoSafetyReserve {
        scope: String,
    },
    /// A scope nests where its kind may not.
    MisplacedScope {
        scope: String,
        kind: HostScopeKind,
        parent: Option<HostScopeKind>,
    },
    /// The plan has no host RAM scope, so no demand would meet physical host RAM.
    MissingHostRam,
    /// A second host RAM scope would let demand split across two "hosts".
    SecondHostRam {
        first: String,
        second: String,
    },
    /// A second root pinned-memory cap would let pinned demand avoid the hard host-wide
    /// cap (§3.4, line 540); nest memlock limits under the first instead.
    SecondPinnedRoot {
        first: String,
        second: String,
    },
    /// A demand names a pinned-memory cap as its memory scope.
    NotAMemoryScope {
        demand: String,
        scope: String,
    },
    /// A pinned demand names a memory scope as its pinned-memory cap.
    NotAPinnedScope {
        demand: String,
        scope: String,
    },
    /// A pinned demand names no pinned-memory cap.
    PinnedScopeMissing {
        demand: String,
    },
    /// A demand that is not pinned names a pinned-memory cap.
    PinnedScopeOnUnpinnedDemand {
        demand: String,
    },
    /// These scopes, in plan order, do not fit on at least one piece of time.
    DoesNotFit(Vec<ScopeOvercommit>),
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(error) => error.fmt(f),
            Self::VirtualReservationIsNotCapacity { scope } => write!(
                f,
                "{scope}: an address reservation supplies no physical capacity"
            ),
            Self::NoSafetyReserve { scope } => write!(f, "{scope}: keep a safety reserve"),
            Self::MisplacedScope {
                scope,
                kind,
                parent,
            } => write!(f, "{scope}: a {kind:?} scope cannot nest in {parent:?}"),
            Self::MissingHostRam => f.write_str("a host plan needs its host RAM scope"),
            Self::SecondHostRam { first, second } => write!(
                f,
                "{second} is a second host RAM scope after {first}; a plan has exactly one"
            ),
            Self::SecondPinnedRoot { first, second } => write!(
                f,
                "{second} is a second host-wide pinned-memory cap after {first}; nest it \
                 under {first}"
            ),
            Self::NotAMemoryScope { demand, scope } => {
                write!(
                    f,
                    "{demand}: {scope} is a pinned-memory cap, not a memory scope"
                )
            }
            Self::NotAPinnedScope { demand, scope } => {
                write!(f, "{demand}: {scope} is not a pinned-memory cap")
            }
            Self::PinnedScopeMissing { demand } => {
                write!(f, "{demand}: pinned memory must name its pinned-memory cap")
            }
            Self::PinnedScopeOnUnpinnedDemand { demand } => {
                write!(
                    f,
                    "{demand}: only pinned memory is charged to a pinned-memory cap"
                )
            }
            Self::DoesNotFit(overcommits) => {
                f.write_str("host memory does not fit:")?;
                for overcommit in overcommits {
                    write!(
                        f,
                        " {} ({:?}) needs {} of {} bytes during [{}, {}) ns;",
                        overcommit.scope,
                        overcommit.kind,
                        overcommit.peak.total_bytes,
                        overcommit.capacity_bytes,
                        overcommit.peak.during.start().as_nanos(),
                        overcommit.peak.during.end().as_nanos(),
                    )?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for HostError {}

impl From<InputError> for HostError {
    fn from(error: InputError) -> Self {
        Self::Input(error)
    }
}

/// Validates a host plan and computes each scope's total on every piece of time, whether
/// or not it fits (GPU §2.7).
pub fn evaluate_host(plan: &HostPlan) -> Result<HostEvaluation, HostError> {
    let mut scopes: BTreeMap<&str, &HostScope> = BTreeMap::new();
    for scope in &plan.scopes {
        check_name("host scope", &scope.name)?;
        if scopes.insert(scope.name.as_str(), scope).is_some() {
            return Err(InputError::Duplicate {
                field: "host scope",
                name: scope.name.clone(),
            }
            .into());
        }
    }
    for scope in &plan.scopes {
        if scope.physical_capacity()? == 0 {
            return Err(InputError::NotPositive {
                field: "host scope capacity",
            }
            .into());
        }
        if scope.safety_reserve_bytes == 0 {
            return Err(HostError::NoSafetyReserve {
                scope: scope.name.clone(),
            });
        }
        let parent = match &scope.parent {
            None => None,
            Some(parent) => Some(lookup(&scopes, "parent scope", parent)?.kind),
        };
        if !scope.kind.allows_parent(parent) {
            return Err(HostError::MisplacedScope {
                scope: scope.name.clone(),
                kind: scope.kind,
                parent,
            });
        }
        chain(&scopes, &scope.name)?;
    }
    let mut host_ram: Option<&str> = None;
    let mut pinned_root: Option<&str> = None;
    for scope in &plan.scopes {
        let second = scope.name.as_str();
        if scope.kind == HostScopeKind::HostRam {
            if let Some(first) = host_ram.replace(second) {
                return Err(HostError::SecondHostRam {
                    first: first.to_string(),
                    second: second.to_string(),
                });
            }
        } else if scope.kind == HostScopeKind::PinnedRam && scope.parent.is_none() {
            if let Some(first) = pinned_root.replace(second) {
                return Err(HostError::SecondPinnedRoot {
                    first: first.to_string(),
                    second: second.to_string(),
                });
            }
        }
    }
    if host_ram.is_none() {
        return Err(HostError::MissingHostRam);
    }

    let mut charged: Vec<BTreeSet<&str>> = Vec::with_capacity(plan.demands.len());
    for demand in &plan.demands {
        check_name("host demand", &demand.label)?;
        let memory = lookup(&scopes, "memory scope", &demand.memory_scope)?;
        if !memory.kind.limits_memory() {
            return Err(HostError::NotAMemoryScope {
                demand: demand.label.clone(),
                scope: memory.name.clone(),
            });
        }
        let mut names: BTreeSet<&str> = chain(&scopes, &demand.memory_scope)?.into_iter().collect();
        match (demand.backing, &demand.pinned_scope) {
            (HostBacking::Pinned, Some(pinned)) => {
                let cap = lookup(&scopes, "pinned scope", pinned)?;
                if cap.kind != HostScopeKind::PinnedRam {
                    return Err(HostError::NotAPinnedScope {
                        demand: demand.label.clone(),
                        scope: cap.name.clone(),
                    });
                }
                names.extend(chain(&scopes, pinned)?);
            }
            (HostBacking::Pinned, None) => {
                return Err(HostError::PinnedScopeMissing {
                    demand: demand.label.clone(),
                })
            }
            (HostBacking::Anonymous | HostBacking::PageCache, Some(_)) => {
                return Err(HostError::PinnedScopeOnUnpinnedDemand {
                    demand: demand.label.clone(),
                })
            }
            (HostBacking::Anonymous | HostBacking::PageCache, None) => {}
        }
        charged.push(names);
    }

    let mut evaluated = Vec::with_capacity(plan.scopes.len());
    for scope in &plan.scopes {
        let occupied_bytes = scope
            .occupancy
            .occupied_bytes()
            .ok_or(InputError::Overflow {
                field: "host scope occupancy",
            })?;
        let demands: Vec<&HostDemand> = plan
            .demands
            .iter()
            .zip(&charged)
            .filter(|(_, names)| names.contains(scope.name.as_str()))
            .map(|(demand, _)| demand)
            .collect();
        let intervals: Vec<Interval> = demands.iter().map(|demand| demand.during).collect();
        let mut scope_pieces = Vec::new();
        for piece in pieces(&intervals) {
            let demand_bytes = demands
                .iter()
                .filter(|demand| demand.during.overlaps(&piece))
                .try_fold(0u64, |total, demand| {
                    add_bytes("host demand", total, demand.bytes)
                })?;
            let total_bytes = add_bytes("host demand", demand_bytes, occupied_bytes)
                .and_then(|total| add_bytes("host demand", total, scope.safety_reserve_bytes))?;
            scope_pieces.push(ScopePiece {
                during: piece,
                demand_bytes,
                occupied_bytes,
                safety_reserve_bytes: scope.safety_reserve_bytes,
                total_bytes,
            });
        }
        evaluated.push(ScopeEvaluation {
            scope: scope.name.clone(),
            kind: scope.kind,
            capacity_bytes: scope.physical_capacity()?,
            pieces: scope_pieces,
        });
    }
    Ok(HostEvaluation { scopes: evaluated })
}

/// Admits a host plan only if every scope fits on every piece of time; otherwise names
/// every scope that does not.
pub fn admit_host(plan: &HostPlan) -> Result<HostEvaluation, HostError> {
    let evaluation = evaluate_host(plan)?;
    let overcommits: Vec<ScopeOvercommit> = evaluation
        .scopes
        .iter()
        .filter_map(|scope| {
            let first_over = scope.first_over()?;
            let peak = scope.peak()?;
            Some(ScopeOvercommit {
                scope: scope.scope.clone(),
                kind: scope.kind,
                capacity_bytes: scope.capacity_bytes,
                first_over: *first_over,
                peak: *peak,
            })
        })
        .collect();
    if overcommits.is_empty() {
        Ok(evaluation)
    } else {
        Err(HostError::DoesNotFit(overcommits))
    }
}

fn lookup<'a>(
    scopes: &BTreeMap<&'a str, &'a HostScope>,
    field: &'static str,
    name: &str,
) -> Result<&'a HostScope, HostError> {
    scopes.get(name).copied().ok_or_else(|| {
        InputError::Unknown {
            field,
            name: name.to_string(),
        }
        .into()
    })
}

/// `start` and every enclosing scope, innermost first; a cycle is refused.
fn chain<'a>(
    scopes: &BTreeMap<&'a str, &'a HostScope>,
    start: &str,
) -> Result<Vec<&'a str>, HostError> {
    let mut names: Vec<&'a str> = Vec::new();
    let mut current = Some(lookup(scopes, "host scope", start)?);
    while let Some(scope) = current {
        if names.contains(&scope.name.as_str()) {
            return Err(InputError::Cycle {
                field: "host scope",
                name: scope.name.clone(),
            }
            .into());
        }
        names.push(scope.name.as_str());
        current = match &scope.parent {
            Some(parent) => Some(lookup(scopes, "parent scope", parent)?),
            None => None,
        };
    }
    Ok(names)
}

/// What is known about whether a host copy is in RAM (GPU §2.7, §3.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum HostResidency {
    /// Page-locked and held by its runtime: resident for as long as it is held.
    Pinned,
    /// Page cache or an ordinary host copy, which the kernel or a cache budget may
    /// reclaim or swap at any time. A mincore estimate, when there is one, is advisory and
    /// may be stale as soon as it is read.
    Reclaimable { mincore_resident_bytes: Option<u64> },
}

/// A host copy of some bytes and what is known about its residency.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct HostCopy {
    pub bytes: u64,
    pub residency: HostResidency,
}

impl HostCopy {
    /// Bytes that admission and reload planning may rely on staying in RAM: all of a
    /// pinned copy and none of a reclaimable one, whatever mincore reports (§2.7).
    pub fn guaranteed_resident_bytes(&self) -> u64 {
        match self.residency {
            HostResidency::Pinned => self.bytes,
            HostResidency::Reclaimable { .. } => 0,
        }
    }

    /// The best available estimate, capped at the copy's size, for diagnostics only.
    pub fn advisory_resident_bytes(&self) -> Option<u64> {
        match self.residency {
            HostResidency::Pinned => Some(self.bytes),
            HostResidency::Reclaimable {
                mincore_resident_bytes,
            } => mincore_resident_bytes.map(|estimate| estimate.min(self.bytes)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model_memory::residency::test_support::{span, GB, MB};

    fn scope(
        name: &str,
        kind: HostScopeKind,
        parent: Option<&str>,
        capacity_bytes: u64,
        safety_reserve_bytes: u64,
        occupancy: ScopeOccupancy,
    ) -> HostScope {
        HostScope {
            name: name.to_string(),
            kind,
            parent: parent.map(str::to_string),
            capacity: Capacity::Physical {
                bytes: capacity_bytes,
            },
            safety_reserve_bytes,
            occupancy,
        }
    }

    fn committed(bytes: u64) -> ScopeOccupancy {
        ScopeOccupancy {
            committed_bytes: bytes,
            ..ScopeOccupancy::default()
        }
    }

    fn host_ram(capacity_bytes: u64, committed_bytes: u64) -> HostScope {
        scope(
            "host-ram",
            HostScopeKind::HostRam,
            None,
            capacity_bytes,
            2 * GB,
            committed(committed_bytes),
        )
    }

    fn demand(
        label: &str,
        backing: HostBacking,
        bytes: u64,
        during: Interval,
        memory_scope: &str,
        pinned_scope: Option<&str>,
    ) -> HostDemand {
        HostDemand {
            label: label.to_string(),
            backing,
            bytes,
            during,
            memory_scope: memory_scope.to_string(),
            pinned_scope: pinned_scope.map(str::to_string),
        }
    }

    fn refused(result: Result<HostEvaluation, HostError>) -> Vec<ScopeOvercommit> {
        match result {
            Err(HostError::DoesNotFit(overcommits)) => overcommits,
            other => panic!("expected DoesNotFit, got {other:?}"),
        }
    }

    #[test]
    fn page_cache_is_not_counted_as_free() {
        let runner = |page_cache_bytes| {
            scope(
                "runner",
                HostScopeKind::Cgroup,
                Some("host-ram"),
                32 * GB,
                GB,
                ScopeOccupancy {
                    committed_bytes: 8 * GB,
                    page_cache_bytes,
                    unattributed_bytes: 0,
                },
            )
        };
        // 32 − 8 committed − 20 page cache − 1 reserve: 3 GB free, not 23 GB.
        assert_eq!(runner(20 * GB).free_bytes(), Ok(3 * GB));
        let load = vec![demand(
            "host copy",
            HostBacking::Anonymous,
            10 * GB,
            span(0, 60),
            "runner",
            None,
        )];
        let overcommits = refused(admit_host(&HostPlan {
            scopes: vec![host_ram(128 * GB, 40 * GB), runner(20 * GB)],
            demands: load.clone(),
        }));
        assert_eq!(overcommits.len(), 1);
        assert_eq!(overcommits[0].scope, "runner");
        // 10 demand + 28 occupied + 1 reserve = 39 GB in a 32 GB cgroup.
        assert_eq!(overcommits[0].peak.total_bytes, 39 * GB);
        assert_eq!(overcommits[0].excess_bytes(), 7 * GB);

        // Without that page cache the same demand fits, so the page cache is what refused.
        assert!(admit_host(&HostPlan {
            scopes: vec![host_ram(128 * GB, 40 * GB), runner(0)],
            demands: load,
        })
        .is_ok());
    }

    #[test]
    fn unattributed_usage_is_never_free() {
        let unknown = scope(
            "runner",
            HostScopeKind::Cgroup,
            Some("host-ram"),
            16 * GB,
            GB,
            ScopeOccupancy {
                unattributed_bytes: 12 * GB,
                ..ScopeOccupancy::default()
            },
        );
        assert_eq!(unknown.free_bytes(), Ok(3 * GB));
        let overcommits = refused(admit_host(&HostPlan {
            scopes: vec![host_ram(128 * GB, 0), unknown],
            demands: vec![demand(
                "copy",
                HostBacking::Anonymous,
                4 * GB,
                span(0, 1),
                "runner",
                None,
            )],
        }));
        assert_eq!(overcommits[0].scope, "runner");
    }

    #[test]
    fn page_cache_the_plan_relies_on_is_charged_like_any_byte() {
        let overcommits = refused(admit_host(&HostPlan {
            scopes: vec![
                host_ram(128 * GB, 0),
                scope(
                    "runner",
                    HostScopeKind::Cgroup,
                    Some("host-ram"),
                    16 * GB,
                    GB,
                    ScopeOccupancy::default(),
                ),
            ],
            demands: vec![demand(
                "model file cache",
                HostBacking::PageCache,
                16 * GB,
                span(0, 60),
                "runner",
                None,
            )],
        }));
        assert_eq!(overcommits[0].peak.demand_bytes, 16 * GB);
        assert_eq!(overcommits[0].excess_bytes(), GB);
    }

    fn pinned_plan(host_copy_bytes: u64) -> HostPlan {
        HostPlan {
            scopes: vec![
                host_ram(64 * GB, 10 * GB),
                scope(
                    "pinned",
                    HostScopeKind::PinnedRam,
                    None,
                    8 * GB,
                    500 * MB,
                    ScopeOccupancy::default(),
                ),
            ],
            demands: vec![
                demand(
                    "staging ring",
                    HostBacking::Pinned,
                    4 * GB,
                    span(0, 10),
                    "host-ram",
                    Some("pinned"),
                ),
                demand(
                    "pinned host copy",
                    HostBacking::Pinned,
                    host_copy_bytes,
                    span(5, 10),
                    "host-ram",
                    Some("pinned"),
                ),
            ],
        }
    }

    #[test]
    fn the_pinned_ram_cap_holds() {
        // 4 + 4 GB pinned + 0.5 GB reserve exceed the 8 GB cap during [5, 10) although
        // host RAM has 64 GB.
        let overcommits = refused(admit_host(&pinned_plan(4 * GB)));
        assert_eq!(overcommits.len(), 1);
        assert_eq!(overcommits[0].scope, "pinned");
        assert_eq!(overcommits[0].kind, HostScopeKind::PinnedRam);
        assert_eq!(overcommits[0].first_over.during, span(5, 10));
        assert_eq!(overcommits[0].excess_bytes(), 500 * MB);

        // Exactly at the cap fits.
        let evaluation = admit_host(&pinned_plan(3_500 * MB)).unwrap();
        assert_eq!(
            evaluation
                .scope("pinned")
                .unwrap()
                .peak()
                .unwrap()
                .total_bytes,
            8 * GB
        );
        // Pinned bytes are host RAM too.
        let ram = evaluation.scope("host-ram").unwrap();
        assert_eq!(ram.peak().unwrap().demand_bytes, 7_500 * MB);
        assert_eq!(ram.peak().unwrap().total_bytes, 19_500 * MB);
    }

    #[test]
    fn nested_pinned_caps_are_all_charged() {
        let mut plan = pinned_plan(GB);
        plan.scopes.push(scope(
            "runner-memlock",
            HostScopeKind::PinnedRam,
            Some("pinned"),
            4 * GB,
            256 * MB,
            ScopeOccupancy::default(),
        ));
        for demand in &mut plan.demands {
            demand.pinned_scope = Some("runner-memlock".to_string());
        }
        let overcommits = refused(admit_host(&plan));
        // 5 GB pinned exceeds the 4 GB memlock limit but fits the 8 GB host-wide cap.
        assert_eq!(overcommits.len(), 1);
        assert_eq!(overcommits[0].scope, "runner-memlock");
    }

    #[test]
    fn a_wsl_vm_setting_does_not_supply_host_ram() {
        let plan = HostPlan {
            scopes: vec![
                host_ram(64 * GB, 45 * GB),
                scope(
                    "wsl",
                    HostScopeKind::WslVm,
                    Some("host-ram"),
                    48 * GB,
                    GB,
                    committed(4 * GB),
                ),
                scope(
                    "runner",
                    HostScopeKind::Cgroup,
                    Some("wsl"),
                    24 * GB,
                    GB,
                    ScopeOccupancy::default(),
                ),
            ],
            demands: vec![demand(
                "host copy",
                HostBacking::Anonymous,
                20 * GB,
                span(0, 60),
                "runner",
                None,
            )],
        };
        let evaluation = evaluate_host(&plan).unwrap();
        // The cgroup (21 of 24 GB) and the VM (25 of 48 GB) fit.
        assert!(evaluation.scope("runner").unwrap().fits());
        assert!(evaluation.scope("wsl").unwrap().fits());
        // The host does not: 20 + 45 + 2 = 67 GB of 64 GB.
        let overcommits = refused(admit_host(&plan));
        assert_eq!(overcommits.len(), 1);
        assert_eq!(overcommits[0].scope, "host-ram");
        assert_eq!(overcommits[0].peak.total_bytes, 67 * GB);
    }

    #[test]
    fn an_address_reservation_supplies_no_host_capacity() {
        let mut reserved = host_ram(64 * GB, 0);
        reserved.capacity = Capacity::VirtualReservation { bytes: 1 << 47 };
        assert_eq!(
            admit_host(&HostPlan {
                scopes: vec![reserved.clone()],
                demands: Vec::new(),
            }),
            Err(HostError::VirtualReservationIsNotCapacity {
                scope: "host-ram".to_string()
            })
        );
        assert!(matches!(
            reserved.free_bytes(),
            Err(HostError::VirtualReservationIsNotCapacity { .. })
        ));
    }

    #[test]
    fn reclaimable_memory_is_not_guaranteed_and_mincore_is_advisory() {
        let cached = HostCopy {
            bytes: 14 * GB,
            residency: HostResidency::Reclaimable {
                mincore_resident_bytes: Some(14 * GB),
            },
        };
        assert_eq!(cached.guaranteed_resident_bytes(), 0);
        assert_eq!(cached.advisory_resident_bytes(), Some(14 * GB));
        let overstated = HostCopy {
            bytes: GB,
            residency: HostResidency::Reclaimable {
                mincore_resident_bytes: Some(2 * GB),
            },
        };
        assert_eq!(overstated.advisory_resident_bytes(), Some(GB));
        let unknown = HostCopy {
            bytes: GB,
            residency: HostResidency::Reclaimable {
                mincore_resident_bytes: None,
            },
        };
        assert_eq!(unknown.advisory_resident_bytes(), None);
        let pinned = HostCopy {
            bytes: 2 * GB,
            residency: HostResidency::Pinned,
        };
        assert_eq!(pinned.guaranteed_resident_bytes(), 2 * GB);
    }

    #[test]
    fn a_transient_host_peak_is_refused_although_the_average_fits() {
        let plan = HostPlan {
            scopes: vec![host_ram(32 * GB, 10 * GB)],
            demands: vec![
                demand(
                    "runtime",
                    HostBacking::Anonymous,
                    12 * GB,
                    span(0, 10),
                    "host-ram",
                    None,
                ),
                demand(
                    "unpack buffer",
                    HostBacking::Anonymous,
                    10 * GB,
                    span(3, 4),
                    "host-ram",
                    None,
                ),
            ],
        };
        let evaluation = evaluate_host(&plan).unwrap();
        let ram = evaluation.scope("host-ram").unwrap();
        // 24 GB for nine seconds and 34 GB for one: 25 GB on average.
        assert_eq!(ram.average_total_bytes(), Some(25 * GB));
        let overcommits = refused(admit_host(&plan));
        assert_eq!(overcommits[0].first_over.during, span(3, 4));
        assert_eq!(overcommits[0].excess_bytes(), 2 * GB);
    }

    #[test]
    fn scopes_must_nest_properly() {
        let orphan_vm = scope(
            "wsl",
            HostScopeKind::WslVm,
            None,
            GB,
            1,
            ScopeOccupancy::default(),
        );
        assert!(matches!(
            admit_host(&HostPlan {
                scopes: vec![orphan_vm],
                demands: Vec::new()
            }),
            Err(HostError::MisplacedScope { parent: None, .. })
        ));
        let pinned = scope(
            "pinned",
            HostScopeKind::PinnedRam,
            None,
            GB,
            1,
            ScopeOccupancy::default(),
        );
        let under_pinned = scope(
            "runner",
            HostScopeKind::Cgroup,
            Some("pinned"),
            GB,
            1,
            ScopeOccupancy::default(),
        );
        assert!(matches!(
            admit_host(&HostPlan {
                scopes: vec![pinned.clone(), under_pinned],
                demands: Vec::new()
            }),
            Err(HostError::MisplacedScope {
                parent: Some(HostScopeKind::PinnedRam),
                ..
            })
        ));
        let mut nested_ram = host_ram(GB, 0);
        nested_ram.parent = Some("pinned".to_string());
        assert!(matches!(
            admit_host(&HostPlan {
                scopes: vec![pinned, nested_ram],
                demands: Vec::new()
            }),
            Err(HostError::MisplacedScope { .. })
        ));
        let loop_a = scope(
            "a",
            HostScopeKind::Cgroup,
            Some("b"),
            GB,
            1,
            ScopeOccupancy::default(),
        );
        let loop_b = scope(
            "b",
            HostScopeKind::Cgroup,
            Some("a"),
            GB,
            1,
            ScopeOccupancy::default(),
        );
        assert!(matches!(
            admit_host(&HostPlan {
                scopes: vec![loop_a, loop_b],
                demands: Vec::new()
            }),
            Err(HostError::Input(InputError::Cycle { .. }))
        ));
        let lost = scope(
            "c",
            HostScopeKind::Cgroup,
            Some("nowhere"),
            GB,
            1,
            ScopeOccupancy::default(),
        );
        assert!(matches!(
            admit_host(&HostPlan {
                scopes: vec![lost],
                demands: Vec::new()
            }),
            Err(HostError::Input(InputError::Unknown { .. }))
        ));
        assert!(matches!(
            admit_host(&HostPlan {
                scopes: vec![host_ram(GB, 0), host_ram(GB, 0)],
                demands: Vec::new()
            }),
            Err(HostError::Input(InputError::Duplicate { .. }))
        ));
    }

    #[test]
    fn a_plan_has_exactly_one_host_ram_scope() {
        // 80 GB split across two 64 GB "hosts" would pass scope by scope.
        let split = HostPlan {
            scopes: vec![
                host_ram(64 * GB, 0),
                scope(
                    "host-ram-2",
                    HostScopeKind::HostRam,
                    None,
                    64 * GB,
                    2 * GB,
                    ScopeOccupancy::default(),
                ),
                scope(
                    "runner",
                    HostScopeKind::Cgroup,
                    Some("host-ram-2"),
                    64 * GB,
                    GB,
                    ScopeOccupancy::default(),
                ),
            ],
            demands: vec![
                demand(
                    "copy a",
                    HostBacking::Anonymous,
                    40 * GB,
                    span(0, 10),
                    "host-ram",
                    None,
                ),
                demand(
                    "copy b",
                    HostBacking::Anonymous,
                    40 * GB,
                    span(0, 10),
                    "runner",
                    None,
                ),
            ],
        };
        assert_eq!(
            admit_host(&split),
            Err(HostError::SecondHostRam {
                first: "host-ram".to_string(),
                second: "host-ram-2".to_string()
            })
        );
        let pinned_only = HostPlan {
            scopes: vec![scope(
                "pinned",
                HostScopeKind::PinnedRam,
                None,
                8 * GB,
                MB,
                ScopeOccupancy::default(),
            )],
            demands: Vec::new(),
        };
        assert_eq!(admit_host(&pinned_only), Err(HostError::MissingHostRam));
        assert_eq!(
            evaluate_host(&HostPlan {
                scopes: Vec::new(),
                demands: Vec::new()
            }),
            Err(HostError::MissingHostRam)
        );
    }

    #[test]
    fn a_plan_has_one_host_wide_pinned_cap() {
        // 4 + 4 GB pinned against the 8 GB host-wide cap is refused (the_pinned_ram_cap_holds).
        // Charging the second 4 GB to another root cap would dodge it.
        let mut plan = pinned_plan(4 * GB);
        plan.scopes.push(scope(
            "pinned-2",
            HostScopeKind::PinnedRam,
            None,
            8 * GB,
            MB,
            ScopeOccupancy::default(),
        ));
        plan.demands[1].pinned_scope = Some("pinned-2".to_string());
        assert_eq!(
            admit_host(&plan),
            Err(HostError::SecondPinnedRoot {
                first: "pinned".to_string(),
                second: "pinned-2".to_string()
            })
        );
        // Nested under the host-wide cap as a memlock limit, it is charged with it.
        plan.scopes[2].parent = Some("pinned".to_string());
        let overcommits = refused(admit_host(&plan));
        assert_eq!(overcommits.len(), 1);
        assert_eq!(overcommits[0].scope, "pinned");
        assert_eq!(overcommits[0].excess_bytes(), 500 * MB);
    }

    #[test]
    fn every_scope_keeps_a_reserve() {
        let mut bare = host_ram(64 * GB, 0);
        bare.safety_reserve_bytes = 0;
        assert_eq!(
            admit_host(&HostPlan {
                scopes: vec![bare],
                demands: Vec::new()
            }),
            Err(HostError::NoSafetyReserve {
                scope: "host-ram".to_string()
            })
        );
        let mut empty = host_ram(0, 0);
        empty.safety_reserve_bytes = 1;
        assert!(matches!(
            admit_host(&HostPlan {
                scopes: vec![empty],
                demands: Vec::new()
            }),
            Err(HostError::Input(InputError::NotPositive { .. }))
        ));
    }

    #[test]
    fn demands_must_name_the_right_scopes() {
        let scopes = vec![
            host_ram(64 * GB, 0),
            scope(
                "pinned",
                HostScopeKind::PinnedRam,
                None,
                8 * GB,
                MB,
                ScopeOccupancy::default(),
            ),
        ];
        let check = |demand: HostDemand| {
            admit_host(&HostPlan {
                scopes: scopes.clone(),
                demands: vec![demand],
            })
        };
        assert_eq!(
            check(demand(
                "ring",
                HostBacking::Anonymous,
                GB,
                span(0, 1),
                "pinned",
                None
            )),
            Err(HostError::NotAMemoryScope {
                demand: "ring".to_string(),
                scope: "pinned".to_string()
            })
        );
        assert_eq!(
            check(demand(
                "ring",
                HostBacking::Pinned,
                GB,
                span(0, 1),
                "host-ram",
                None
            )),
            Err(HostError::PinnedScopeMissing {
                demand: "ring".to_string()
            })
        );
        assert_eq!(
            check(demand(
                "ring",
                HostBacking::Pinned,
                GB,
                span(0, 1),
                "host-ram",
                Some("host-ram")
            )),
            Err(HostError::NotAPinnedScope {
                demand: "ring".to_string(),
                scope: "host-ram".to_string()
            })
        );
        assert_eq!(
            check(demand(
                "copy",
                HostBacking::PageCache,
                GB,
                span(0, 1),
                "host-ram",
                Some("pinned")
            )),
            Err(HostError::PinnedScopeOnUnpinnedDemand {
                demand: "copy".to_string()
            })
        );
        assert!(matches!(
            check(demand(
                "copy",
                HostBacking::Anonymous,
                GB,
                span(0, 1),
                "elsewhere",
                None
            )),
            Err(HostError::Input(InputError::Unknown { .. }))
        ));
        assert!(matches!(
            check(demand(
                "",
                HostBacking::Anonymous,
                GB,
                span(0, 1),
                "host-ram",
                None
            )),
            Err(HostError::Input(InputError::EmptyName { .. }))
        ));
        let fits = check(demand(
            "ring",
            HostBacking::Pinned,
            GB,
            span(0, 1),
            "host-ram",
            Some("pinned"),
        ))
        .unwrap();
        assert!(fits.fits());
        assert!(HostError::PinnedScopeMissing {
            demand: "ring".to_string()
        }
        .to_string()
        .contains("pinned-memory cap"));
    }
}
