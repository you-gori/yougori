//! The thin adapter from model-side admission to the CORE-03 ledger (§3.1, line 491;
//! S3.2).
//!
//! Admission in this module computes model-side demand only; the ledger stays the
//! capacity authority. [`PlacementReservation::new`] admits a placement's plans
//! model-side and turns them into one ledger [`ReservationRequest`]. The ledger reserves
//! amounts, not demand over time, so each amount is that resource's peak demand across
//! the plans' pieces, which covers the steady state and every transition:
//!
//! - the VRAM of each device: the peak of the eight §2.7 demand terms, keyed by
//!   [`vram_resource`];
//! - host RAM: the peak demand charged to the plan's host RAM scope;
//! - pinned host RAM: the peak demand charged to its host-wide pinned cap.
//!
//! Safety reserves and observed occupancy are not requested: the ledger keeps its own
//! supervisor reserve and unmanaged usage for them, so requesting them as well would count
//! them twice. [`PlacementReservation::reserve`] hands the request to [`Ledger::reserve`]
//! and returns its [`Admission`] or [`LedgerError`] unchanged. Nothing here grants
//! anything, and nothing is kept between calls.

use std::fmt;
use std::time::Duration;

use crate::foundation::ids::{Clock, GpuDeviceKey};
use crate::foundation::ledger::{
    Admission, Amounts, Ledger, LedgerError, Priority, Provenance, ReservationId,
    ReservationRequest, ResourceKey,
};

use super::host::{admit_host, HostError, HostPlan, HostScopeKind};
use super::vram::{admit_devices, VramError, VramPiece, VramPlan};

/// The ledger's key for `device`'s VRAM: the one place a [`GpuDeviceKey`] becomes a
/// ledger resource.
pub fn vram_resource(device: GpuDeviceKey) -> ResourceKey {
    ResourceKey::vram(device)
}

/// Why a placement could not become a reservation request: it does not fit model-side.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlacementError {
    Vram(VramError),
    Host(HostError),
}

impl fmt::Display for PlacementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vram(error) => error.fmt(f),
            Self::Host(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for PlacementError {}

impl From<VramError> for PlacementError {
    fn from(error: VramError) -> Self {
        Self::Vram(error)
    }
}

impl From<HostError> for PlacementError {
    fn from(error: HostError) -> Self {
        Self::Host(error)
    }
}

/// Each resource's peak model-side demand across the pieces of `vram` (each device once)
/// and `host`, after both are admitted model-side.
pub fn peak_demand(vram: &[VramPlan], host: Option<&HostPlan>) -> Result<Amounts, PlacementError> {
    let mut amounts = Amounts::new();
    for evaluation in admit_devices(vram)? {
        let peak = evaluation
            .pieces
            .iter()
            .map(VramPiece::demand_bytes)
            .max()
            .unwrap_or(0);
        amounts = amounts.with(vram_resource(evaluation.device), peak);
    }
    if let Some(plan) = host {
        let evaluation = admit_host(plan)?;
        let peak_of = |name: &str| {
            evaluation
                .scope(name)
                .and_then(|scope| scope.pieces.iter().map(|piece| piece.demand_bytes).max())
                .unwrap_or(0)
        };
        // Admission guarantees one host RAM scope and at most one root pinned cap.
        for scope in &plan.scopes {
            match (scope.kind, &scope.parent) {
                (HostScopeKind::HostRam, _) => {
                    amounts = amounts.host_ram_bytes(peak_of(&scope.name));
                }
                (HostScopeKind::PinnedRam, None) => {
                    amounts = amounts.pinned_host_ram_bytes(peak_of(&scope.name));
                }
                _ => {}
            }
        }
    }
    Ok(amounts)
}

/// A model placement's ledger request, built only from plans that fit model-side.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlacementReservation {
    request: ReservationRequest,
}

impl PlacementReservation {
    /// Admits the plans model-side and asks for each resource's [`peak_demand`]. The
    /// request does not wait, and it is charged to host capacity and the provenance's
    /// tenant unless [`within`](Self::within) carves it from a parent.
    pub fn new(
        provenance: Provenance,
        priority: Priority,
        vram: &[VramPlan],
        host: Option<&HostPlan>,
    ) -> Result<Self, PlacementError> {
        let demand = peak_demand(vram, host)?;
        Ok(Self {
            request: ReservationRequest::new(provenance, priority, demand),
        })
    }

    /// Carves the request from `parent`, such as the VM the model runs in (S3.2).
    pub fn within(self, parent: ReservationId) -> Self {
        Self {
            request: self.request.within(parent),
        }
    }

    /// Lets the request wait in the ledger's bounded queue for at most `max_wait`.
    pub fn wait_up_to(self, max_wait: Duration) -> Self {
        Self {
            request: self.request.wait_up_to(max_wait),
        }
    }

    /// The request the ledger will see.
    pub fn request(&self) -> &ReservationRequest {
        &self.request
    }

    /// Asks the ledger, the capacity authority; its admission or refusal comes back
    /// unchanged.
    pub fn reserve<C: Clock>(self, ledger: &mut Ledger<C>) -> Result<Admission, LedgerError> {
        ledger.reserve(self.request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::evidence::{HostSubject, SourceClass};
    use crate::foundation::ids::{
        digest, ExecutionCategory, ExecutionId, ManualClock, OperationId, TenantId, TrustScope,
    };
    use crate::foundation::ledger::{
        CapacityDeclaration, CostPurpose, HostResource, LedgerConfig, Limit, QueueLimits,
        QueuePolicy, Requester,
    };
    use crate::model_memory::residency::host::{
        HostBacking, HostDemand, HostScope, ScopeOccupancy,
    };
    use crate::model_memory::residency::test_support::{gpu, machine, span, GB, MB};
    use crate::model_memory::residency::vram::{
        admit_vram, ImmutableAllocation, ImmutableKind, KvBound, ProcessVram, TransientDemand,
        TransientKind,
    };
    use crate::model_memory::residency::{Capacity, Interval};

    const RAM: ResourceKey = ResourceKey::Host(HostResource::Ram);
    const PINNED: ResourceKey = ResourceKey::Host(HostResource::PinnedRam);

    fn tenant() -> TenantId {
        TenantId::new("tenant-a").unwrap()
    }

    fn provenance(requester: Requester) -> Provenance {
        Provenance {
            requester,
            execution: ExecutionId::new("exe-1").unwrap(),
            operation: OperationId::new("op-1").unwrap(),
            tenant: tenant(),
            purpose: CostPurpose::Compute,
            retry_number: 0,
        }
    }

    fn probe(total: u64, supervisor_reserve: u64, unmanaged_in_use: u64) -> CapacityDeclaration {
        CapacityDeclaration {
            total,
            supervisor_reserve,
            unmanaged_in_use,
            source: SourceClass::HostProbe,
        }
    }

    /// The test host: 24 GB of VRAM on gpu0 with a 1 GB supervisor reserve and
    /// `vram_in_use` used outside the ledger, 64 GB of RAM and 8 GB pinned; the tenant may
    /// use all of it.
    fn ledger(vram_in_use: u64) -> Ledger<ManualClock> {
        let config = LedgerConfig {
            queue: QueueLimits {
                max_entries: 4,
                max_entries_per_tenant: 4,
                max_wait: Duration::from_secs(60),
            },
            grant_ttl: Duration::from_secs(300),
            unmanaged_usage_max_age: Duration::from_secs(3_600),
        };
        let mut ledger = Ledger::new(
            ManualClock::default(),
            HostSubject { machine: machine() },
            config,
        );
        let vram = vram_resource(gpu("gpu0"));
        for (resource, declaration, budget) in [
            (vram, probe(24 * GB, GB, vram_in_use), 24 * GB),
            (RAM, probe(64 * GB, 2 * GB, 0), 64 * GB),
            (PINNED, probe(8 * GB, 0, 0), 8 * GB),
        ] {
            ledger.declare_capacity(resource, declaration).unwrap();
            ledger
                .set_tenant_budget(tenant(), resource, budget)
                .unwrap();
        }
        ledger
    }

    /// 14 GB of weights, 4 GB of KV and a 0.5 GB context for 10 s (18.5 GB), plus
    /// `staging_bytes` during [4, 5); 1 GB safety reserve on a 24 GB device.
    fn vram_plan(device: GpuDeviceKey, staging_bytes: u64) -> VramPlan {
        let domain = TrustScope::named(ExecutionCategory::SharedKernelGpuRuntime, "tenant-a");
        let transients = if staging_bytes > 0 {
            vec![TransientDemand {
                kind: TransientKind::Staging,
                bytes: staging_bytes,
                during: span(4, 5),
            }]
        } else {
            Vec::new()
        };
        VramPlan {
            device,
            usable_vram: Capacity::Physical { bytes: 24 * GB },
            safety_reserve_bytes: GB,
            allocations: vec![ImmutableAllocation {
                key: "weights".to_string(),
                kind: ImmutableKind::Weights,
                bytes: 14 * GB,
                sharing_domain: domain,
                resident: span(0, 10),
            }],
            processes: vec![ProcessVram {
                process: "runner".to_string(),
                sharing_domain: domain,
                lifetime: span(0, 10),
                maps: vec!["weights".to_string()],
                context_bytes: 500 * MB,
                graph_pool_bytes: 0,
                kv: KvBound::Reserved { bytes: 4 * GB },
                transients,
            }],
        }
    }

    fn host_demand(label: &str, backing: HostBacking, bytes: u64, during: Interval) -> HostDemand {
        let pinned = backing == HostBacking::Pinned;
        HostDemand {
            label: label.to_string(),
            backing,
            bytes,
            during,
            memory_scope: "host-ram".to_string(),
            pinned_scope: pinned.then(|| "pinned".to_string()),
        }
    }

    /// Host RAM peaks at 12 GB during [3, 4) (6 GB runtime, 4 GB unpack buffer and the
    /// 2 GB pinned ring); pinned RAM peaks at 3 GB during [5, 10). 20 GB of host RAM is
    /// already in use outside the plan.
    fn host_plan() -> HostPlan {
        HostPlan {
            scopes: vec![
                HostScope {
                    name: "host-ram".to_string(),
                    kind: HostScopeKind::HostRam,
                    parent: None,
                    capacity: Capacity::Physical { bytes: 64 * GB },
                    safety_reserve_bytes: 2 * GB,
                    occupancy: ScopeOccupancy {
                        committed_bytes: 20 * GB,
                        ..ScopeOccupancy::default()
                    },
                },
                HostScope {
                    name: "pinned".to_string(),
                    kind: HostScopeKind::PinnedRam,
                    parent: None,
                    capacity: Capacity::Physical { bytes: 8 * GB },
                    safety_reserve_bytes: 512 * MB,
                    occupancy: ScopeOccupancy::default(),
                },
            ],
            demands: vec![
                host_demand("runtime", HostBacking::Anonymous, 6 * GB, span(0, 10)),
                host_demand("unpack buffer", HostBacking::Anonymous, 4 * GB, span(3, 4)),
                host_demand("staging ring", HostBacking::Pinned, 2 * GB, span(0, 10)),
                host_demand("pinned copy", HostBacking::Pinned, GB, span(5, 10)),
            ],
        }
    }

    #[test]
    fn a_plan_that_fits_model_side_is_refused_by_the_ledger_naming_the_resource() {
        let plan = vram_plan(gpu("gpu0"), 0);
        // Model-side the device fits: 18.5 GB + 1 GB reserve of 24 GB usable.
        assert!(admit_vram(&plan).is_ok());
        // The host sees 8 GB used outside the ledger: 24 − 1 − 8 = 15 GB is grantable.
        let mut ledger = ledger(8 * GB);
        let reservation = PlacementReservation::new(
            provenance(Requester::ModelPlacement),
            Priority::Foreground,
            &[plan],
            None,
        )
        .unwrap();
        let vram = vram_resource(gpu("gpu0"));
        let capacity = match reservation.reserve(&mut ledger) {
            Err(LedgerError::Capacity(capacity)) => capacity,
            other => panic!("expected a capacity refusal, got {other:?}"),
        };
        assert_eq!(capacity.resource(), vram);
        assert_eq!(capacity.limiting().limit, Limit::PhysicalCapacity);
        assert_eq!(capacity.limiting().requested, 18_500 * MB);
        assert_eq!(capacity.limiting().available, 15 * GB);
        assert!(capacity.retry_can_progress());
        assert!(capacity.to_string().starts_with("VRAM on GPU"));
        assert_eq!(ledger.reserved(vram), 0);
    }

    #[test]
    fn a_fitting_plan_reserves_exactly_the_peaks() {
        let mut ledger = ledger(0);
        let reservation = PlacementReservation::new(
            provenance(Requester::ModelPlacement),
            Priority::Foreground,
            &[vram_plan(gpu("gpu0"), 3 * GB)],
            Some(&host_plan()),
        )
        .unwrap();
        let vram = vram_resource(gpu("gpu0"));
        // VRAM: 18.5 GB steady plus 3 GB of staging, without the 1 GB safety reserve.
        // Host RAM: the 12 GB peak, without the 20 GB in use or the reserve.
        let peaks = Amounts::new()
            .with(vram, 21_500 * MB)
            .host_ram_bytes(12 * GB)
            .pinned_host_ram_bytes(3 * GB);
        assert_eq!(reservation.request().demand, peaks);
        assert_eq!(reservation.request().parent, None);
        assert!(matches!(
            reservation.reserve(&mut ledger),
            Ok(Admission::Granted(_))
        ));
        assert_eq!(ledger.reserved(vram), 21_500 * MB);
        assert_eq!(ledger.reserved(RAM), 12 * GB);
        assert_eq!(ledger.reserved(PINNED), 3 * GB);
    }

    #[test]
    fn a_placement_is_carved_from_its_parent() {
        let mut ledger = ledger(0);
        let vram = vram_resource(gpu("gpu0"));
        // Room for two placements' host memory but only one placement's VRAM.
        let parent_demand = Amounts::new()
            .with(vram, 22 * GB)
            .host_ram_bytes(24 * GB)
            .pinned_host_ram_bytes(6 * GB);
        let parent = match ledger.reserve(ReservationRequest::new(
            provenance(Requester::VmLifecycle),
            Priority::Foreground,
            parent_demand,
        )) {
            Ok(Admission::Granted(parent)) => parent,
            other => panic!("expected the parent to be granted, got {other:?}"),
        };
        let placement = || {
            PlacementReservation::new(
                provenance(Requester::ModelPlacement),
                Priority::Foreground,
                &[vram_plan(gpu("gpu0"), 3 * GB)],
                Some(&host_plan()),
            )
            .unwrap()
            .within(parent)
        };
        assert_eq!(placement().request().parent, Some(parent));
        assert_eq!(
            placement()
                .wait_up_to(Duration::from_secs(5))
                .request()
                .queue,
            QueuePolicy::WaitUpTo(Duration::from_secs(5))
        );
        assert!(matches!(
            placement().reserve(&mut ledger),
            Ok(Admission::Granted(_))
        ));
        // The child is inside its parent, so host-level reservations are unchanged.
        assert_eq!(ledger.reserved(vram), 22 * GB);
        // A second child does not fit in what the parent has left: 0.5 GB of VRAM.
        let refused = match placement().reserve(&mut ledger) {
            Err(LedgerError::Capacity(capacity)) => capacity,
            other => panic!("expected a parent refusal, got {other:?}"),
        };
        assert_eq!(
            refused.limiting().limit,
            Limit::ParentReservation { parent }
        );
        assert_eq!(refused.resource(), vram);
        assert_eq!(refused.limiting().available, 500 * MB);
    }

    #[test]
    fn a_placement_that_does_not_fit_model_side_never_reaches_the_ledger() {
        let mut small = vram_plan(gpu("gpu0"), 0);
        small.usable_vram = Capacity::Physical { bytes: 16 * GB };
        let request = |vram: &[VramPlan], host: Option<&HostPlan>| {
            PlacementReservation::new(
                provenance(Requester::ModelPlacement),
                Priority::Foreground,
                vram,
                host,
            )
        };
        assert!(matches!(
            request(&[small], None),
            Err(PlacementError::Vram(VramError::DoesNotFit(_)))
        ));
        let plan = vram_plan(gpu("gpu0"), 0);
        assert_eq!(
            request(&[plan.clone(), plan.clone()], None),
            Err(PlacementError::Vram(VramError::DuplicateDevice {
                device: gpu("gpu0")
            }))
        );
        let mut two_hosts = host_plan();
        two_hosts.scopes[1].kind = HostScopeKind::HostRam;
        assert_eq!(
            request(&[plan], Some(&two_hosts)),
            Err(PlacementError::Host(HostError::SecondHostRam {
                first: "host-ram".to_string(),
                second: "pinned".to_string()
            }))
        );
    }

    #[test]
    fn every_device_gets_its_own_vram_amount() {
        let peaks = peak_demand(
            &[vram_plan(gpu("gpu0"), 3 * GB), vram_plan(gpu("gpu1"), 0)],
            None,
        )
        .unwrap();
        assert_eq!(peaks.len(), 2);
        assert_eq!(peaks.get(vram_resource(gpu("gpu0"))), 21_500 * MB);
        assert_eq!(peaks.get(vram_resource(gpu("gpu1"))), 18_500 * MB);
        assert_eq!(peaks.get(RAM), 0);
    }

    #[test]
    fn ledger_refusals_come_back_unchanged() {
        // A device on another machine: the ledger refuses it as foreign.
        let foreign = GpuDeviceKey {
            machine: digest("yougori/test/residency/machine/v1", &[b"host-2"]),
            device: gpu("gpu0").device,
        };
        let mut ledger = ledger(0);
        let reservation = PlacementReservation::new(
            provenance(Requester::ModelPlacement),
            Priority::Foreground,
            &[vram_plan(foreign, 0)],
            None,
        )
        .unwrap();
        assert!(matches!(
            reservation.reserve(&mut ledger),
            Err(LedgerError::ForeignDevice { .. })
        ));
        // A placement with no demand at all.
        let empty = PlacementReservation::new(
            provenance(Requester::ModelPlacement),
            Priority::Foreground,
            &[],
            None,
        )
        .unwrap();
        assert!(empty.request().demand.is_empty());
        assert_eq!(empty.reserve(&mut ledger), Err(LedgerError::EmptyDemand));
    }
}
