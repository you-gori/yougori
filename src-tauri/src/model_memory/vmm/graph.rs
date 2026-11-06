//! CUDA graph capture, launch and reuse (GPU part §3.7; §1.1 row 305; GPU-W05).
//!
//! A graph records its execution key (model, kernels, shapes and arguments), the
//! resources it touches, where each resolved to, and what memory and workspaces were
//! behind them. It holds that memory, so graph references count against release
//! (Appendix E step 5). Reuse is allowed only when every component is compatible: an
//! address reservation alone never makes graphs interchangeable, and memory reallocated
//! without pointer stability means recapturing.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::driver::VmmDriver;
use super::error::{GraphMismatch, NotCallableReason, VmmError};
use super::model::{Backing, VmmModel};
use super::types::{
    AddressRange, EventId, GraphId, MappingKey, PhysicalId, ProcessId, StreamId, VirtualAddress,
    WorkKind, WorkspaceId,
};
use crate::foundation::ids::{Digest, GpuAllocationGeneration};

/// What a graph's correctness rests on besides its memory (§3.7: compatible kernels,
/// shapes and arguments; §1.1 row 305: validate an execution key).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GraphExecutionKey {
    /// The model execution the graph was captured for.
    pub model: Digest,
    pub kernels: Digest,
    pub shapes: Digest,
    pub arguments: Digest,
}

/// One resource a graph touches.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "resource", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum GraphResource {
    /// Bytes of an artifact the capturing process holds.
    Artifact {
        artifact: Digest,
        offset_bytes: u64,
        length_bytes: u64,
    },
    /// A workspace buffer.
    Workspace { workspace: WorkspaceId },
}

crate::foundation::strict_serde::strict_tag!(GraphResource, "resource");

/// What a resource's addresses are bound to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AddressBinding {
    /// A VMM reservation, kept for the process lifetime: pointers stay stable.
    Reservation { start: VirtualAddress },
    /// One pool or legacy allocation, replaced by each reallocation.
    Allocation {
        physical: PhysicalId,
        generation: GpuAllocationGeneration,
    },
}

/// A resource as it resolved at one moment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Bound {
    Artifact {
        range: AddressRange,
        binding: AddressBinding,
        /// The memory behind each covered batch, with the batch's generation.
        backing: Vec<(PhysicalId, GpuAllocationGeneration)>,
    },
    Workspace {
        workspace: WorkspaceId,
        size_bytes: u64,
        generation: GpuAllocationGeneration,
    },
}

#[derive(Clone, Debug)]
pub(super) struct CapturedGraph {
    pub(super) process: ProcessId,
    pub(super) key: GraphExecutionKey,
    pub(super) resources: Vec<GraphResource>,
    pub(super) bound: Vec<Bound>,
    /// Whether the graph holds its memory and workspaces; a detached graph must pass a
    /// reuse check before it launches.
    pub(super) attached: bool,
}

/// A workspace buffer graphs use (§3.7: compatible workspaces and resource lifetimes).
#[derive(Clone, Debug)]
pub(super) struct Workspace {
    pub(super) process: ProcessId,
    pub(super) size_bytes: u64,
    pub(super) generation: GpuAllocationGeneration,
    pub(super) live: bool,
    pub(super) graphs: BTreeSet<GraphId>,
}

/// The first component of `captured` that `requested` does not match.
fn key_mismatch(
    captured: &GraphExecutionKey,
    requested: &GraphExecutionKey,
) -> Option<GraphMismatch> {
    if captured.model != requested.model {
        Some(GraphMismatch::Model)
    } else if captured.kernels != requested.kernels {
        Some(GraphMismatch::Kernels)
    } else if captured.shapes != requested.shapes {
        Some(GraphMismatch::Shapes)
    } else if captured.arguments != requested.arguments {
        Some(GraphMismatch::Arguments)
    } else {
        None
    }
}

/// How `current` differs from what was `captured` for resource `index`.
fn bound_mismatch(captured: &Bound, current: &Bound, index: usize) -> Option<GraphMismatch> {
    match (captured, current) {
        (
            Bound::Artifact {
                range,
                binding,
                backing,
            },
            Bound::Artifact {
                range: now_range,
                binding: now_binding,
                backing: now_backing,
            },
        ) => {
            if range.start != now_range.start {
                Some(GraphMismatch::Address {
                    resource: index,
                    captured: range.start,
                    current: now_range.start,
                })
            } else if binding != now_binding {
                Some(GraphMismatch::Reallocated { resource: index })
            } else if backing != now_backing {
                Some(GraphMismatch::Generation { resource: index })
            } else {
                None
            }
        }
        (Bound::Workspace { .. }, Bound::Workspace { workspace, .. }) => (captured != current)
            .then_some(GraphMismatch::Workspace {
                workspace: *workspace,
            }),
        _ => Some(GraphMismatch::Resources),
    }
}

impl VmmModel {
    /// A workspace buffer of `size_bytes` for graphs of `process`.
    pub fn create_workspace(
        &mut self,
        process: ProcessId,
        size_bytes: u64,
    ) -> Result<WorkspaceId, VmmError> {
        self.context_of(process)?;
        if size_bytes == 0 {
            return Err(VmmError::ZeroSize);
        }
        let workspace = WorkspaceId::new(self.allocate_id()?);
        self.workspaces.insert(
            workspace,
            Workspace {
                process,
                size_bytes,
                generation: GpuAllocationGeneration::FIRST,
                live: true,
                graphs: BTreeSet::new(),
            },
        );
        Ok(workspace)
    }

    /// Reallocates a workspace at `size_bytes` under a new generation. Refused while a
    /// graph holds it, so a graph never outlives its workspace.
    pub fn reallocate_workspace(
        &mut self,
        workspace: WorkspaceId,
        size_bytes: u64,
    ) -> Result<(), VmmError> {
        if size_bytes == 0 {
            return Err(VmmError::ZeroSize);
        }
        let entry = self.workspace_unheld(workspace)?;
        entry.generation = entry
            .generation
            .next()
            .ok_or(VmmError::GenerationExhausted)?;
        entry.size_bytes = size_bytes;
        entry.live = true;
        Ok(())
    }

    /// Frees a workspace. Refused while a graph holds it.
    pub fn free_workspace(&mut self, workspace: WorkspaceId) -> Result<(), VmmError> {
        let entry = self.workspace_unheld(workspace)?;
        if !entry.live {
            return Err(VmmError::WorkspaceFreed { workspace });
        }
        entry.live = false;
        Ok(())
    }

    fn workspace_unheld(&mut self, workspace: WorkspaceId) -> Result<&mut Workspace, VmmError> {
        let entry = self
            .workspaces
            .get_mut(&workspace)
            .ok_or(VmmError::UnknownWorkspace { workspace })?;
        if !entry.graphs.is_empty() {
            return Err(VmmError::WorkspaceInUse {
                workspace,
                graphs: entry.graphs.iter().copied().collect(),
            });
        }
        Ok(entry)
    }

    /// Captures a graph over published memory and live workspaces of `process`. The graph
    /// holds the memory and workspaces it uses until it is detached or destroyed.
    pub fn capture_graph(
        &mut self,
        process: ProcessId,
        key: GraphExecutionKey,
        resources: Vec<GraphResource>,
    ) -> Result<GraphId, VmmError> {
        self.context_of(process)?;
        if !resources
            .iter()
            .any(|resource| matches!(resource, GraphResource::Artifact { .. }))
        {
            return Err(VmmError::EmptyGraph);
        }
        let bound = resources
            .iter()
            .map(|resource| self.resolve(process, *resource))
            .collect::<Result<Vec<_>, _>>()?;
        let graph = GraphId::new(self.allocate_id()?);
        self.hold(graph, process, &bound);
        self.graphs.insert(
            graph,
            CapturedGraph {
                process,
                key,
                resources,
                bound,
                attached: true,
            },
        );
        Ok(graph)
    }

    /// Replays a graph on `stream`. Refused unless it is attached and every resource
    /// resolves exactly as captured: no replay over unmapped, unpublished or re-created
    /// memory, and no replay after a workspace changed.
    pub fn launch_graph(
        &mut self,
        driver: &mut dyn VmmDriver,
        graph: GraphId,
        stream: StreamId,
    ) -> Result<EventId, VmmError> {
        let record = self
            .graphs
            .get(&graph)
            .ok_or(VmmError::UnknownGraph { graph })?;
        if !record.attached {
            return Err(VmmError::GraphDetached { graph });
        }
        let process = record.process;
        let captured = record.bound.clone();
        let resources = record.resources.clone();
        let mut ranges = Vec::new();
        let mut artifacts = BTreeSet::new();
        for (index, (resource, captured)) in resources.iter().zip(&captured).enumerate() {
            let current = self.resolve(process, *resource)?;
            if let Some(mismatch) = bound_mismatch(captured, &current, index) {
                return Err(VmmError::GraphIncompatible { graph, mismatch });
            }
            if let (GraphResource::Artifact { artifact, .. }, Bound::Artifact { range, .. }) =
                (resource, &current)
            {
                ranges.push(*range);
                artifacts.insert(*artifact);
            }
        }
        let event = driver.enqueue(process, stream, WorkKind::GraphReplay, &ranges)?;
        self.track(process, event, artifacts, Some(graph));
        Ok(event)
    }

    /// Checks whether a captured graph may serve a request with `key` over `resources`,
    /// and rebinds it to the memory behind them now.
    ///
    /// Kernels, shapes, arguments and model must all match the capture; so must every
    /// address and workspace, and every resource must be usable. Memory re-created at the
    /// same reserved addresses (a VMM wake) is acceptable and is rebound. Memory
    /// reallocated without pointer stability is not, even at an equal pointer value: the
    /// graph is then recaptured.
    pub fn reuse_graph(
        &mut self,
        driver: &mut dyn VmmDriver,
        graph: GraphId,
        key: GraphExecutionKey,
        resources: &[GraphResource],
    ) -> Result<(), VmmError> {
        self.require_graph_quiescent(driver, graph)?;
        let record = self
            .graphs
            .get(&graph)
            .ok_or(VmmError::UnknownGraph { graph })?
            .clone();
        let refuse = |mismatch| VmmError::GraphIncompatible { graph, mismatch };
        if let Some(mismatch) = key_mismatch(&record.key, &key) {
            return Err(refuse(mismatch));
        }
        if record.resources.as_slice() != resources {
            return Err(refuse(GraphMismatch::Resources));
        }
        let mut current = Vec::with_capacity(resources.len());
        for (index, (resource, captured)) in resources.iter().zip(&record.bound).enumerate() {
            let bound = match self.resolve(record.process, *resource) {
                Ok(bound) => bound,
                Err(VmmError::NotCallable { reason, .. }) => {
                    return Err(refuse(GraphMismatch::Unavailable {
                        resource: index,
                        reason,
                    }))
                }
                Err(VmmError::WorkspaceFreed { workspace }) => {
                    return Err(refuse(GraphMismatch::Workspace { workspace }))
                }
                Err(error) => return Err(error),
            };
            match bound_mismatch(captured, &bound, index) {
                None | Some(GraphMismatch::Generation { .. }) => current.push(bound),
                Some(mismatch) => return Err(refuse(mismatch)),
            }
        }
        if record.attached {
            self.unhold(graph, record.process, &record.bound);
        }
        self.hold(graph, record.process, &current);
        if let Some(entry) = self.graphs.get_mut(&graph) {
            entry.bound = current;
            entry.attached = true;
        }
        Ok(())
    }

    /// Drops a quiescent graph's holds on memory and workspaces but keeps its record, so
    /// a park can release the memory; the graph must pass [`Self::reuse_graph`] before it
    /// launches again.
    pub fn detach_graph(
        &mut self,
        driver: &mut dyn VmmDriver,
        graph: GraphId,
    ) -> Result<(), VmmError> {
        self.require_graph_quiescent(driver, graph)?;
        let Some(record) = self.graphs.get(&graph).cloned() else {
            return Err(VmmError::UnknownGraph { graph });
        };
        if record.attached {
            self.unhold(graph, record.process, &record.bound);
        }
        if let Some(entry) = self.graphs.get_mut(&graph) {
            entry.attached = false;
        }
        Ok(())
    }

    /// Destroys a quiescent graph and drops its holds.
    pub fn destroy_graph(
        &mut self,
        driver: &mut dyn VmmDriver,
        graph: GraphId,
    ) -> Result<(), VmmError> {
        self.require_graph_quiescent(driver, graph)?;
        let record = self
            .graphs
            .remove(&graph)
            .ok_or(VmmError::UnknownGraph { graph })?;
        if record.attached {
            self.unhold(graph, record.process, &record.bound);
        }
        Ok(())
    }

    /// Whether a graph holds its resources; `None` for an unknown graph.
    pub fn graph_attached(&self, graph: GraphId) -> Option<bool> {
        self.graphs.get(&graph).map(|record| record.attached)
    }

    fn require_graph_quiescent(
        &mut self,
        driver: &mut dyn VmmDriver,
        graph: GraphId,
    ) -> Result<(), VmmError> {
        if !self.graphs.contains_key(&graph) {
            return Err(VmmError::UnknownGraph { graph });
        }
        let pending = self.pending(driver, |_, work| work.graph == Some(graph))?;
        if !pending.is_empty() {
            return Err(VmmError::NotQuiescent { events: pending });
        }
        Ok(())
    }

    /// Resolves one resource of `process` now, refusing anything not usable.
    fn resolve(&self, process: ProcessId, resource: GraphResource) -> Result<Bound, VmmError> {
        match resource {
            GraphResource::Artifact {
                artifact,
                offset_bytes,
                length_bytes,
            } => {
                let key = MappingKey { process, artifact };
                let entry = self.artifact(key)?;
                let end = entry.check_range(key, offset_bytes, length_bytes)?;
                if let Some(reason) = entry
                    .not_callable(offset_bytes, end)
                    .or_else(|| self.exporter_gone(entry, offset_bytes, end))
                {
                    return Err(VmmError::NotCallable { key, reason });
                }
                let covered = entry.covered(offset_bytes, end);
                let backing = covered
                    .iter()
                    .filter_map(|(_, slot)| Some((slot.state.physical()?, slot.generation?)))
                    .collect::<Vec<_>>();
                let (start, binding) = match entry.backing {
                    Backing::Vmm { reservation, .. } => (
                        reservation.start,
                        AddressBinding::Reservation {
                            start: reservation.start,
                        },
                    ),
                    Backing::Pool { .. } | Backing::Legacy => {
                        let slot = entry.slot(key, 0)?;
                        let (Some(start), Some(&(physical, generation))) =
                            (slot.address, backing.first())
                        else {
                            return Err(VmmError::NotCallable {
                                key,
                                reason: NotCallableReason::Unmapped { batch: 0 },
                            });
                        };
                        (
                            start,
                            AddressBinding::Allocation {
                                physical,
                                generation,
                            },
                        )
                    }
                };
                Ok(Bound::Artifact {
                    range: AddressRange::new(
                        start
                            .checked_add(offset_bytes)
                            .ok_or(VmmError::SizeOverflow)?,
                        length_bytes,
                    ),
                    binding,
                    backing,
                })
            }
            GraphResource::Workspace { workspace } => {
                let entry = self
                    .workspaces
                    .get(&workspace)
                    .filter(|entry| entry.process == process)
                    .ok_or(VmmError::UnknownWorkspace { workspace })?;
                if !entry.live {
                    return Err(VmmError::WorkspaceFreed { workspace });
                }
                Ok(Bound::Workspace {
                    workspace,
                    size_bytes: entry.size_bytes,
                    generation: entry.generation,
                })
            }
        }
    }

    /// Takes the graph's holds on the memory and workspaces in `bound`.
    fn hold(&mut self, graph: GraphId, process: ProcessId, bound: &[Bound]) {
        for resource in bound {
            match resource {
                Bound::Artifact { backing, .. } => {
                    for (physical, _) in backing {
                        if let Some(handle) = self
                            .physical
                            .get_mut(physical)
                            .and_then(|entry| entry.handles.get_mut(&process))
                        {
                            handle.graphs.insert(graph);
                        }
                    }
                }
                Bound::Workspace { workspace, .. } => {
                    if let Some(entry) = self.workspaces.get_mut(workspace) {
                        entry.graphs.insert(graph);
                    }
                }
            }
        }
    }

    /// Drops the graph's holds on the memory and workspaces in `bound`.
    fn unhold(&mut self, graph: GraphId, process: ProcessId, bound: &[Bound]) {
        for resource in bound {
            match resource {
                Bound::Artifact { backing, .. } => {
                    for (physical, _) in backing {
                        if let Some(handle) = self
                            .physical
                            .get_mut(physical)
                            .and_then(|entry| entry.handles.get_mut(&process))
                        {
                            handle.graphs.remove(&graph);
                        }
                    }
                }
                Bound::Workspace { workspace, .. } => {
                    if let Some(entry) = self.workspaces.get_mut(workspace) {
                        entry.graphs.remove(&graph);
                    }
                }
            }
        }
    }
}
