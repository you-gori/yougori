//! Planning extents onto sources (GPU §2.5; §3.5 step 3): batches from the batching
//! port, checked; batches assigned by the multi-source planner; and the path each read
//! takes.

use std::collections::{BTreeMap, BTreeSet};

use super::error::{MethodUnavailable, PlanFailure};
use super::machine::TransferExecutor;
use super::model::{
    AllocationKey, LoaderPermissions, ManifestExtent, ReadMethod, SourceCandidate, SourceKind,
    StagingPlace, TransferPath,
};
use super::ports::{BatchLimits, ExtentSpan};
use super::state::{slots_needed, BatchState, FlightId, Job, Load, LoadBatch};
use super::validate::check_batch_plans;
use crate::foundation::ids::{Clock, ContentKey, GpuDeviceKey, OperationId};
use crate::model_memory::math::bounds::BandwidthRating;
use crate::model_memory::math::sources::{CutSpec, MultiSourceLoad, SourceSpec};

/// Extents of one representation, bound for one allocation, to plan onto sources.
pub(super) struct LoadInput<'a> {
    pub(super) artifact: ContentKey,
    /// The stored object the extents are read from.
    pub(super) representation: ContentKey,
    pub(super) allocation: AllocationKey,
    pub(super) members: &'a [(FlightId, ManifestExtent)],
    pub(super) sources: &'a [SourceCandidate],
    pub(super) cuts: &'a [CutSpec],
    pub(super) limits: BatchLimits,
}

impl<C: Clock> TransferExecutor<C> {
    /// Coalesces the members into aligned batches through the batching port, checks the
    /// plans, and assigns the batches to sources by predicted completion (GPU §2.5).
    /// Measured read rates replace the catalog's figures.
    pub(super) fn build_load(&self, input: LoadInput<'_>) -> Result<Load, PlanFailure> {
        let mut members = input.members.to_vec();
        members.sort_by_key(|(_, extent)| extent.stored_offset_bytes);
        let spans: Vec<ExtentSpan> = members
            .iter()
            .map(|(_, extent)| ExtentSpan {
                index: extent.index,
                offset_bytes: extent.stored_offset_bytes,
                length_bytes: extent.stored_length_bytes,
                decode_bytes: extent.decode_bytes(),
            })
            .collect();
        let plans = self.ports.batches.coalesce(&spans, &input.limits);
        check_batch_plans(&plans, &spans, &input.limits).map_err(PlanFailure::Batch)?;
        let by_index: BTreeMap<u64, FlightId> = members
            .iter()
            .map(|(id, extent)| (extent.index, *id))
            .collect();
        let batches: Vec<LoadBatch> = plans
            .iter()
            .map(|plan| LoadBatch {
                members: plan
                    .members
                    .iter()
                    .filter_map(|index| by_index.get(index).copied())
                    .collect(),
                read_offset_bytes: plan.read_offset_bytes,
                read_length_bytes: plan.read_length_bytes,
                state: BatchState::Queued,
            })
            .collect();
        let batch_bytes: Vec<u64> = plans.iter().map(|plan| plan.read_length_bytes).collect();
        let specs: Vec<SourceSpec> = input
            .sources
            .iter()
            .map(|candidate| self.current_spec(&candidate.spec))
            .collect();
        let plan = MultiSourceLoad::plan(
            specs,
            input.cuts.to_vec(),
            &batch_bytes,
            self.config.steal_policy,
        )
        .map_err(PlanFailure::Sources)?;
        Ok(Load {
            plan,
            batches,
            kinds: input
                .sources
                .iter()
                .map(|candidate| (candidate.spec.id.clone(), candidate.kind))
                .collect(),
            caps: input
                .sources
                .iter()
                .map(|candidate| (candidate.spec.id.clone(), candidate.spec.max_in_flight))
                .collect(),
            artifact: input.artifact,
            representation: input.representation,
            allocation: input.allocation,
        })
    }

    /// The catalog's profile of a source, with its measured rate where one exists.
    fn current_spec(&self, spec: &SourceSpec) -> SourceSpec {
        let mut spec = spec.clone();
        if let Some(rating) = self
            .observed_rates
            .get(&spec.id)
            .and_then(|rate| BandwidthRating::measured_directional(*rate).ok())
        {
            spec.bandwidth = rating;
        }
        spec
    }

    /// Sources an operation may be read from now, in the first subscriber's order: every
    /// subscriber may use the source, none has blacklisted it, and a path to the
    /// destination GPU exists.
    pub(super) fn eligible_sources(&mut self, id: FlightId) -> Vec<SourceCandidate> {
        let subscribers: Vec<OperationId> = self
            .flights
            .get(&id)
            .map(|flight| flight.subscribers.iter().cloned().collect())
            .unwrap_or_default();
        self.eligible_sources_for(id, &subscribers)
    }

    /// Sources an operation may be read from for these subscribers alone.
    pub(super) fn eligible_sources_for(
        &mut self,
        id: FlightId,
        subscribers: &[OperationId],
    ) -> Vec<SourceCandidate> {
        let Some(flight) = self.flights.get(&id) else {
            return Vec::new();
        };
        let jobs: Vec<&Job> = subscribers
            .iter()
            .filter_map(|operation| self.jobs.get(operation))
            .collect();
        let Some(first) = jobs.first() else {
            return Vec::new();
        };
        if jobs.len() != subscribers.len() {
            return Vec::new();
        }
        let allowed: Vec<SourceCandidate> = first
            .sources
            .iter()
            .filter(|candidate| {
                jobs.iter()
                    .all(|job| job.allows(&candidate.spec.id, candidate.kind))
            })
            .cloned()
            .collect();
        let device = flight.key.allocation.device;
        let decodes = flight.extent.stored.needs_decode();
        allowed
            .into_iter()
            .filter(|candidate| self.path_possible(candidate.kind, device, decodes))
            .collect()
    }

    /// Subscribers of an operation that no usable source serves on their own.
    pub(super) fn stranded_subscribers(&mut self, id: FlightId) -> Vec<OperationId> {
        let subscribers: Vec<OperationId> = self
            .flights
            .get(&id)
            .map(|flight| flight.subscribers.iter().cloned().collect())
            .unwrap_or_default();
        subscribers
            .into_iter()
            .filter(|operation| {
                self.eligible_sources_for(id, std::slice::from_ref(operation))
                    .is_empty()
            })
            .collect()
    }

    /// The path, read method and staging a batch from a source of `kind` takes now.
    ///
    /// A gated method is used only when the backend implements it and every
    /// subscriber's loader plan enabled it, on CUDA for a CUDA mechanism, with evidence
    /// that still holds in the registry now ([`LoaderPermissions::unavailable`]).
    /// GPUDirect Storage and GPU peers read into device staging and bypass the host ring
    /// (§3.5). A method a subscriber requires is used or refused, and the ordinary
    /// loader never replaces it (INT-06). A requirement is checked against the jobs that
    /// hold it alone: each such job needs its own evidence to hold, a job whose
    /// requirement cannot be met is shed, and the operation stays with its other
    /// subscribers, so one subscriber never fails another's work (§3.5).
    pub(super) fn choose_path(
        &self,
        kind: SourceKind,
        subscribers: &BTreeSet<OperationId>,
        device: GpuDeviceKey,
        decodes: bool,
    ) -> Route {
        let loaders: Vec<(&OperationId, &LoaderPermissions)> = subscribers
            .iter()
            .filter_map(|operation| self.jobs.get(operation).map(|job| (operation, &job.loader)))
            .collect();
        if loaders.is_empty() || loaders.len() != subscribers.len() {
            return Route::Unusable;
        }
        let evidence = &*self.evidence;
        let implemented = |method: ReadMethod| self.read_methods.contains(&method);
        let device_fits = self
            .devices
            .get(&device)
            .is_some_and(|pool| pool.slots() >= slots_needed(decodes));
        let device_place = StagingPlace::Device { device };
        let mut shed = Vec::new();
        let mut chosen = None;
        for method in [ReadMethod::GpuDirectStorage, ReadMethod::IoUring] {
            let common = if let Some(other) = chosen {
                Some(MethodUnavailable::ConflictsWith { other })
            } else if kind != SourceKind::LocalFile {
                Some(MethodUnavailable::WrongSource)
            } else if !implemented(method) {
                Some(MethodUnavailable::NotImplemented)
            } else if method == ReadMethod::GpuDirectStorage && !device_fits {
                Some(MethodUnavailable::NoDeviceStaging)
            } else {
                None
            };
            let mut met = false;
            for (operation, loader) in &loaders {
                if !loader.required().contains(&method) {
                    continue;
                }
                let reason = common
                    .clone()
                    .or_else(|| loader.unavailable(method, evidence));
                match reason {
                    Some(reason) => shed.push(((*operation).clone(), method, reason)),
                    None => met = true,
                }
            }
            if met {
                chosen = Some(method);
            }
        }
        if !shed.is_empty() {
            return Route::Shed { jobs: shed };
        }
        match chosen {
            Some(ReadMethod::GpuDirectStorage) => {
                return Route::Use {
                    path: TransferPath::DirectStorage,
                    method: ReadMethod::GpuDirectStorage,
                    place: device_place,
                }
            }
            Some(method) => {
                return Route::Use {
                    path: TransferPath::HostRing,
                    method,
                    place: StagingPlace::Host,
                }
            }
            None => {}
        }
        let permitted = |method: ReadMethod| {
            loaders
                .iter()
                .all(|(_, loader)| loader.permits(method, evidence))
        };
        let usable = |method: ReadMethod| implemented(method) && permitted(method);
        match kind {
            SourceKind::LocalFile if device_fits && usable(ReadMethod::GpuDirectStorage) => {
                Route::Use {
                    path: TransferPath::DirectStorage,
                    method: ReadMethod::GpuDirectStorage,
                    place: device_place,
                }
            }
            SourceKind::LocalFile => Route::Use {
                path: TransferPath::HostRing,
                method: if usable(ReadMethod::IoUring) {
                    ReadMethod::IoUring
                } else {
                    self.config.local_read_method
                },
                place: StagingPlace::Host,
            },
            SourceKind::Remote | SourceKind::AuthorizedPeer if usable(ReadMethod::RangeRequest) => {
                Route::Use {
                    path: TransferPath::HostRing,
                    method: ReadMethod::RangeRequest,
                    place: StagingPlace::Host,
                }
            }
            // Peer access is rechecked in CORE-01 evidence at every read (FAST-02).
            SourceKind::GpuPeer { device: from }
                if device_fits
                    && usable(ReadMethod::PeerCopy)
                    && self.peer_access_holds(from, device) =>
            {
                Route::Use {
                    path: TransferPath::GpuPeer { from },
                    method: ReadMethod::PeerCopy,
                    place: device_place,
                }
            }
            SourceKind::Remote
            | SourceKind::AuthorizedPeer
            | SourceKind::GpuPeer { .. }
            | SourceKind::ImportOnlyBind => Route::Unusable,
        }
    }
}

/// How a batch from one source would be read.
pub(super) enum Route {
    Use {
        path: TransferPath,
        method: ReadMethod,
        place: StagingPlace,
    },
    /// No path from this source reaches the destination now; plan the extents again.
    Unusable,
    /// These jobs require a method this read cannot use: they fail rather than degrade,
    /// and the operations are planned again for their other subscribers.
    Shed {
        jobs: Vec<(OperationId, ReadMethod, MethodUnavailable)>,
    },
}
