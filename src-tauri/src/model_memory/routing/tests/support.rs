//! Shared fixtures: a fleet authority over a real CORE-02 catalog and CORE-01 evidence,
//! endpoint reports for the §4.6 router, and float comparison.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use crate::foundation::ids::{
    GpuDeviceKey, ManualClock, ModelActivationGeneration, MonotonicTime, OperationId, ResourceId,
};
use crate::model_memory::identity::fakes::{scope_enforcement, GrantCatalog};
use crate::model_memory::identity::GrantedUse;
use crate::model_memory::math::bounds::{BandwidthRating, ResourceTable, TransferDemand};

use super::super::estimate::{SecondsEstimate, StalenessPolicy};
use super::super::fixtures::{device, FleetAuthority, SyntheticFleet};
use super::super::joint::{
    EndpointReport, EndpointState, FlowKey, HysteresisPolicy, MigrationSupport,
    PlacementRestrictions, Preparation, PreparationSource, RoutingPolicy, RoutingRequest,
    SessionState,
};

/// Far enough in the future that nothing expires during a test.
pub(super) const FAR: MonotonicTime = MonotonicTime::from_nanos(u64::MAX / 2);

/// The router's clock starts at 10 s.
pub(super) const NOW: MonotonicTime = MonotonicTime::from_nanos(10_000_000_000);

pub(super) fn assert_close(actual: f64, expected: f64) {
    assert!(
        (actual - expected).abs() <= 1e-9 * expected.abs().max(1.0),
        "{actual} is not {expected}"
    );
}

pub(super) fn estimate(expected: f64, spread: f64) -> SecondsEstimate {
    SecondsEstimate::new(expected, spread).unwrap()
}

pub(super) fn seconds_ago(seconds: f64) -> MonotonicTime {
    MonotonicTime::from_nanos(NOW.as_nanos() - (seconds * 1e9) as u64)
}

/// A fleet authority and the temporary catalog it stands on; keep it alive while the
/// grants are used.
pub(super) struct Authority {
    pub(super) authority: FleetAuthority,
    pub(super) _grants: GrantCatalog,
}

/// The synthetic tenant's artifact published in a catalog of its own, readable by the
/// fleet's parent execution as owner, and KV-scope evidence fresh for a long time.
pub(super) fn authority(synthetic: &SyntheticFleet) -> Authority {
    let clock = Arc::new(ManualClock::new(MonotonicTime::ZERO));
    let grants = GrantCatalog::open(clock, std::slice::from_ref(&synthetic.tenant));
    let object = grants.publish_artifact(&synthetic.tenant, &synthetic.artifact);
    Authority {
        authority: FleetAuthority {
            catalog: Arc::clone(grants.catalog()),
            object,
            execution: synthetic.parent.clone(),
            kv_enforcement: scope_enforcement(MonotonicTime::ZERO, Duration::from_secs(1 << 30)),
        },
        _grants: grants,
    }
}

/// The synthetic fleet, its authority and a router clock at [`NOW`].
pub(super) struct World {
    pub(super) synthetic: SyntheticFleet,
    pub(super) authority: Authority,
    pub(super) clock: ManualClock,
}

impl World {
    pub(super) fn new() -> Self {
        let synthetic = SyntheticFleet::new().unwrap();
        let authority = authority(&synthetic);
        Self {
            synthetic,
            authority,
            clock: ManualClock::new(NOW),
        }
    }

    pub(super) fn fleet_authority(&self) -> &FleetAuthority {
        &self.authority.authority
    }

    pub(super) fn gpu(&self, machine: &str) -> GpuDeviceKey {
        device(machine, "gpu0")
    }

    /// The single-GPU execution, ready on `machine`, observed now, with the given queue
    /// and compute, a 20 ms client tail and every session-move mechanism unsupported.
    pub(super) fn ready(
        &self,
        machine: &str,
        queue: SecondsEstimate,
        compute: SecondsEstimate,
    ) -> EndpointReport {
        let scope = self.synthetic.scope(machine);
        let claim = self
            .synthetic
            .resident_claim(
                self.fleet_authority(),
                self.gpu(machine),
                scope,
                self.synthetic.single_execution().unwrap(),
                ModelActivationGeneration::FIRST,
                FAR,
            )
            .unwrap();
        EndpointReport {
            device: self.gpu(machine),
            scope,
            observed_at: NOW,
            queue,
            request_compute: compute,
            client_network_tail: estimate(0.02, 0.0),
            state: EndpointState::Ready(claim),
            migration: MigrationSupport::default(),
            input_link: None,
            egress_usd_per_byte: 0.0,
            donor_impact_seconds: 0.0,
        }
    }

    /// The 14 GB model read from local NVMe at 7 GB/s (a 2 s bound) with 0.8 s of engine
    /// start, claimed to take `preparation`.
    pub(super) fn local_preparation(
        &self,
        machine: &str,
        preparation: SecondsEstimate,
    ) -> Preparation {
        nvme_preparation(machine, preparation, 7.0e9)
    }

    /// A cold endpoint on `machine` that loads from its local artifact under a storage
    /// grant.
    pub(super) fn cold(
        &self,
        machine: &str,
        preparation: SecondsEstimate,
        compute: SecondsEstimate,
    ) -> EndpointReport {
        let scope = self.synthetic.scope(machine);
        let grant = self
            .synthetic
            .grant(
                self.fleet_authority(),
                scope,
                &[GrantedUse::ShareImmutableStorage],
                FAR,
            )
            .unwrap();
        EndpointReport {
            state: EndpointState::Cold {
                execution: self.synthetic.single_execution().unwrap(),
                source: PreparationSource::LocalArtifact {
                    artifact: self.synthetic.artifact,
                    owner: self.synthetic.tenant.clone(),
                    grant: Some(grant),
                },
                preparation: self.local_preparation(machine, preparation),
            },
            queue: SecondsEstimate::ZERO,
            ..self.ready(machine, SecondsEstimate::ZERO, compute)
        }
    }

    /// A request for the exact single-GPU execution from the synthetic tenant, every
    /// listed machine authorized, the tenant's runtime category accepted.
    pub(super) fn request(
        &self,
        machines: &[&str],
        session: Option<SessionState>,
    ) -> RoutingRequest {
        let model = self.synthetic.requested_single().unwrap();
        RoutingRequest {
            request: OperationId::new("op-route").unwrap(),
            requester: self.synthetic.tenant.clone(),
            flow: FlowKey::model(&self.synthetic.tenant, &model),
            model,
            authorized_machines: machines
                .iter()
                .map(|machine| self.gpu(machine).machine)
                .collect(),
            restrictions: PlacementRestrictions {
                excluded_machines: BTreeSet::new(),
                categories: BTreeSet::from([self.synthetic.category]),
                max_egress_usd: None,
            },
            session,
            input: None,
        }
    }
}

/// `bytes` of model read at `bytes_per_second` from `machine`'s NVMe plus 0.8 s of
/// engine start, claimed to take `preparation`.
pub(super) fn nvme_preparation(
    machine: &str,
    preparation: SecondsEstimate,
    bytes_per_second: f64,
) -> Preparation {
    let nvme = ResourceId::new(format!("{machine}-nvme-read")).unwrap();
    let mut resources = ResourceTable::new();
    resources
        .add(
            nvme.clone(),
            BandwidthRating::measured_directional(bytes_per_second).unwrap(),
        )
        .unwrap();
    Preparation {
        critical_path: preparation,
        resources,
        demands: vec![TransferDemand {
            bytes: 14_000_000_000,
            resources: vec![nvme],
        }],
        minimum_seconds: 0.8,
    }
}

/// Risk weight 1, no egress value, reports penalized 0.1 s per second of age and unused
/// at 5 s, and the given hysteresis.
pub(super) fn policy(min_gain_seconds: f64, min_gain_fraction: f64) -> RoutingPolicy {
    RoutingPolicy {
        risk_weight: 1.0,
        seconds_per_usd: 0.0,
        staleness: StalenessPolicy::new(0.1, 0.1, 5.0).unwrap(),
        hysteresis: HysteresisPolicy {
            min_gain_seconds,
            min_gain_fraction,
        },
    }
}
