//! The per-request state machine of execute-while-load (GPU-W07 items 3 and 7; GPU §2.6
//! line 432; §3.6 lines 599–601).
//!
//! A [`StreamingExecution`] serves exactly one assigned request under one preparation
//! generation. It records when every tensor and buffer becomes usable and when every group
//! starts and finishes, stamped by the injected clock. It refuses:
//!
//! - computing a group before every tensor and buffer it reads is usable (§4.4: layers
//!   never compute before their own weights exist);
//! - computing out of the exact model order, or two groups at once;
//! - a tensor from another generation (§3.6 line 599: no request mixes generations);
//! - any request but the assigned one (§3.6 line 601);
//! - a compute for another request shape than the plan's;
//! - a dense first-token claim before every required layer and the output head computed
//!   (§2.6 line 432), or after cancellation or an out-of-memory failure.
//!
//! Cancellation and an out-of-memory failure stop new work at once; a group already
//! computing finishes, because a running kernel is not preemptible, and nothing is
//! published. A late group simply keeps the stream waiting: its stall is recorded, and
//! nothing computes early.

use crate::foundation::ids::{Clock, ModelActivationGeneration, MonotonicTime, OperationId};
use crate::model_memory::executor::{DependencyId, TransferExecutor};

use super::architecture::{dependency_id, PlannedRequest, RequestShape};
use super::{ExecutionRefusal, StreamingError};

/// What happened, in recording order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamingEventKind {
    TensorUsable { tensor: usize },
    BufferReady { buffer: usize },
    ComputeStarted { group: usize },
    ComputeFinished { group: usize },
    Cancelled,
    OutOfMemory { group: usize, requested_bytes: u64 },
}

/// One recorded event (GPU-W07 item 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamingEvent {
    pub sequence: u64,
    pub at: MonotonicTime,
    pub kind: StreamingEventKind,
}

/// Where the request is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionStatus {
    Running,
    /// Every group, the output head last, computed.
    Completed {
        at: MonotonicTime,
    },
    Cancelled {
        at: MonotonicTime,
    },
    OutOfMemory {
        group: usize,
        requested_bytes: u64,
        at: MonotonicTime,
    },
}

/// One group's availability and compute events.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GroupRecord {
    /// When the last tensor or buffer it reads became usable.
    pub usable_at: Option<MonotonicTime>,
    pub started_at: Option<MonotonicTime>,
    pub finished_at: Option<MonotonicTime>,
}

/// What a stopped request leaves behind, for the caller to cancel transfers and release
/// reservations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StopReport {
    pub computed_groups: Vec<usize>,
    /// Still computing; it finishes, and its buffers are released after its completion.
    pub running_group: Option<usize>,
    /// Usable tensors that no remaining group will consume.
    pub usable_tensors: Vec<usize>,
    /// Tensors not yet usable, whose transfers should be cancelled.
    pub pending_tensors: Vec<usize>,
}

/// A dense first token: every group, the output head last, computed under one generation
/// for the assigned request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DenseFirstToken {
    pub request: OperationId,
    pub generation: ModelActivationGeneration,
    pub at: MonotonicTime,
}

/// Why no first token may be claimed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FirstTokenRefusal {
    /// GPU §2.6 line 432: the token depends on every required layer and the output head.
    MissingGroups {
        groups: Vec<usize>,
        output_head_missing: bool,
    },
    Cancelled,
    OutOfMemory,
}

/// Whether a transfer dependency was published as usable (GPU §3.5 step 7).
pub trait DependencyAvailability {
    fn is_usable(&self, dependency: DependencyId) -> bool;
}

/// The transfer executor's publication, across the jobs that carry one request's reads.
pub struct ExecutorAvailability<'a, C: Clock> {
    pub executor: &'a TransferExecutor<C>,
    pub operations: &'a [OperationId],
}

impl<C: Clock> DependencyAvailability for ExecutorAvailability<'_, C> {
    fn is_usable(&self, dependency: DependencyId) -> bool {
        self.operations
            .iter()
            .any(|operation| self.executor.is_usable(operation, dependency))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Needs {
    tensors: Vec<usize>,
    buffers: Vec<usize>,
}

/// One request's execute-while-load run.
pub struct StreamingExecution<C: Clock> {
    clock: C,
    request: OperationId,
    generation: ModelActivationGeneration,
    shape: RequestShape,
    needs: Vec<Needs>,
    tensor_usable: Vec<Option<MonotonicTime>>,
    buffer_ready: Vec<Option<MonotonicTime>>,
    records: Vec<GroupRecord>,
    events: Vec<StreamingEvent>,
    next_group: usize,
    running: Option<usize>,
    status: ExecutionStatus,
}

impl<C: Clock> StreamingExecution<C> {
    /// A run of `planned` for the assigned `request` under the preparation `generation`.
    /// `tensors` is the model's tensor count.
    pub fn new(
        clock: C,
        request: OperationId,
        generation: ModelActivationGeneration,
        planned: &PlannedRequest,
        tensors: usize,
    ) -> Result<Self, StreamingError> {
        let needs: Vec<Needs> = planned
            .groups
            .iter()
            .map(|group| Needs {
                tensors: group.tensors().collect(),
                buffers: group.buffers.clone(),
            })
            .collect();
        if needs.is_empty() {
            return Err(StreamingError::Invalid {
                field: "groups",
                reason: "a request has groups",
            });
        }
        for need in &needs {
            if let Some(tensor) = need.tensors.iter().find(|tensor| **tensor >= tensors) {
                return Err(StreamingError::Unknown {
                    field: "tensors",
                    index: *tensor,
                });
            }
            if let Some(buffer) = need.buffers.iter().find(|b| **b >= planned.buffers.len()) {
                return Err(StreamingError::Unknown {
                    field: "buffers",
                    index: *buffer,
                });
            }
        }
        Ok(Self {
            clock,
            request,
            generation,
            shape: planned.shape,
            records: vec![GroupRecord::default(); needs.len()],
            needs,
            tensor_usable: vec![None; tensors],
            buffer_ready: vec![None; planned.buffers.len()],
            events: Vec::new(),
            next_group: 0,
            running: None,
            status: ExecutionStatus::Running,
        })
    }

    fn record(&mut self, kind: StreamingEventKind) -> MonotonicTime {
        let at = self.clock.now();
        let sequence = self.events.len() as u64;
        self.events.push(StreamingEvent { sequence, at, kind });
        at
    }

    fn running_or_refuse(&self) -> Result<(), ExecutionRefusal> {
        match self.status {
            ExecutionStatus::Running => Ok(()),
            _ => Err(ExecutionRefusal::Ended),
        }
    }

    /// §3.6 line 601: only the explicitly assigned request is served.
    pub fn accept_request(&self, request: &OperationId) -> Result<(), ExecutionRefusal> {
        if *request == self.request {
            Ok(())
        } else {
            Err(ExecutionRefusal::UnrelatedRequest)
        }
    }

    fn missing(&self, group: usize) -> (Vec<usize>, Vec<usize>) {
        let Some(needs) = self.needs.get(group) else {
            return (Vec::new(), Vec::new());
        };
        let tensors = needs
            .tensors
            .iter()
            .copied()
            .filter(|tensor| {
                self.tensor_usable
                    .get(*tensor)
                    .is_none_or(|at| at.is_none())
            })
            .collect();
        let buffers = needs
            .buffers
            .iter()
            .copied()
            .filter(|buffer| self.buffer_ready.get(*buffer).is_none_or(|at| at.is_none()))
            .collect();
        (tensors, buffers)
    }

    fn refresh_usable(&mut self, at: MonotonicTime) {
        for group in 0..self.needs.len() {
            if self.records[group].usable_at.is_none() {
                let (tensors, buffers) = self.missing(group);
                if tensors.is_empty() && buffers.is_empty() {
                    self.records[group].usable_at = Some(at);
                }
            }
        }
    }

    /// Records that a tensor's transfer dependency was published under `generation`.
    pub fn tensor_usable(
        &mut self,
        tensor: usize,
        generation: ModelActivationGeneration,
    ) -> Result<(), StreamingError> {
        self.running_or_refuse()?;
        if generation != self.generation {
            return Err(ExecutionRefusal::MixedGenerations {
                expected: self.generation.get(),
                found: generation.get(),
            }
            .into());
        }
        let slot = self
            .tensor_usable
            .get(tensor)
            .ok_or(StreamingError::Unknown {
                field: "tensors",
                index: tensor,
            })?;
        if slot.is_some() {
            return Err(ExecutionRefusal::AlreadyUsable.into());
        }
        let at = self.record(StreamingEventKind::TensorUsable { tensor });
        self.tensor_usable[tensor] = Some(at);
        self.refresh_usable(at);
        Ok(())
    }

    /// Records that a nonpersistent buffer was built.
    pub fn buffer_ready(&mut self, buffer: usize) -> Result<(), StreamingError> {
        self.running_or_refuse()?;
        let slot = self
            .buffer_ready
            .get(buffer)
            .ok_or(StreamingError::Unknown {
                field: "buffers",
                index: buffer,
            })?;
        if slot.is_some() {
            return Err(ExecutionRefusal::AlreadyUsable.into());
        }
        let at = self.record(StreamingEventKind::BufferReady { buffer });
        self.buffer_ready[buffer] = Some(at);
        self.refresh_usable(at);
        Ok(())
    }

    /// Marks every tensor whose dependency `source` publishes as usable; returns them.
    pub fn observe(
        &mut self,
        source: &impl DependencyAvailability,
        generation: ModelActivationGeneration,
    ) -> Result<Vec<usize>, StreamingError> {
        let newly: Vec<usize> = (0..self.tensor_usable.len())
            .filter(|tensor| self.tensor_usable[*tensor].is_none())
            .filter(|tensor| source.is_usable(dependency_id(*tensor)))
            .collect();
        for tensor in &newly {
            self.tensor_usable(*tensor, generation)?;
        }
        Ok(newly)
    }

    /// The next group in model order, if any remains.
    pub fn next_group(&self) -> Option<usize> {
        (self.next_group < self.needs.len()).then_some(self.next_group)
    }

    /// Whether the next group may start now.
    pub fn can_start_next(&self) -> bool {
        self.status == ExecutionStatus::Running
            && self.running.is_none()
            && self
                .next_group()
                .is_some_and(|group| self.records[group].usable_at.is_some())
    }

    /// Starts `group` (GPU §2.6, §4.4). Refused before every tensor and buffer it reads is
    /// usable, out of order, while another group computes, for another shape, or after
    /// the request ended.
    pub fn start_group(&mut self, group: usize, shape: RequestShape) -> Result<(), StreamingError> {
        self.running_or_refuse()?;
        if shape != self.shape {
            return Err(ExecutionRefusal::ShapeMismatch.into());
        }
        if let Some(running) = self.running {
            return Err(ExecutionRefusal::ComputeBusy { running }.into());
        }
        if group != self.next_group {
            return Err(ExecutionRefusal::OutOfOrder {
                expected: self.next_group,
                requested: group,
            }
            .into());
        }
        if group >= self.needs.len() {
            return Err(StreamingError::Unknown {
                field: "groups",
                index: group,
            });
        }
        let (missing_tensors, missing_buffers) = self.missing(group);
        if !missing_tensors.is_empty() || !missing_buffers.is_empty() {
            return Err(ExecutionRefusal::ComputeBeforeUsable {
                group,
                missing_tensors,
                missing_buffers,
            }
            .into());
        }
        let at = self.record(StreamingEventKind::ComputeStarted { group });
        self.records[group].started_at = Some(at);
        self.running = Some(group);
        Ok(())
    }

    /// Records that the running group finished. A group started before a cancellation or
    /// failure still finishes; the request then stays stopped.
    pub fn finish_group(&mut self, group: usize) -> Result<(), StreamingError> {
        if self.running != Some(group) {
            return Err(ExecutionRefusal::NotRunningGroup { group }.into());
        }
        let at = self.record(StreamingEventKind::ComputeFinished { group });
        self.records[group].finished_at = Some(at);
        self.running = None;
        self.next_group += 1;
        if self.status == ExecutionStatus::Running && self.next_group == self.needs.len() {
            self.status = ExecutionStatus::Completed { at };
        }
        Ok(())
    }

    fn stop_report(&self) -> StopReport {
        let computed_groups: Vec<usize> = (0..self.needs.len())
            .filter(|group| self.records[*group].finished_at.is_some())
            .collect();
        let remaining: Vec<usize> = (self.next_group..self.needs.len())
            .filter(|group| Some(*group) != self.running)
            .flat_map(|group| self.needs[group].tensors.clone())
            .collect();
        let mut usable_tensors: Vec<usize> = remaining
            .iter()
            .copied()
            .filter(|tensor| self.tensor_usable[*tensor].is_some())
            .collect();
        usable_tensors.sort_unstable();
        usable_tensors.dedup();
        let pending_tensors = (0..self.tensor_usable.len())
            .filter(|tensor| self.tensor_usable[*tensor].is_none())
            .collect();
        StopReport {
            computed_groups,
            running_group: self.running,
            usable_tensors,
            pending_tensors,
        }
    }

    /// Cancels the request mid-prefill: nothing new starts and nothing is published.
    pub fn cancel(&mut self) -> Result<StopReport, StreamingError> {
        self.running_or_refuse()?;
        let at = self.record(StreamingEventKind::Cancelled);
        self.status = ExecutionStatus::Cancelled { at };
        Ok(self.stop_report())
    }

    /// Records that an allocation for `group` failed: the request fails without a result
    /// and without falling back to oversubscribed memory.
    pub fn out_of_memory(
        &mut self,
        group: usize,
        requested_bytes: u64,
    ) -> Result<StopReport, StreamingError> {
        self.running_or_refuse()?;
        if group >= self.needs.len() {
            return Err(StreamingError::Unknown {
                field: "groups",
                index: group,
            });
        }
        let at = self.record(StreamingEventKind::OutOfMemory {
            group,
            requested_bytes,
        });
        self.status = ExecutionStatus::OutOfMemory {
            group,
            requested_bytes,
            at,
        };
        Ok(self.stop_report())
    }

    /// A dense first token (GPU §2.6 line 432): refused unless every group, the output
    /// head last, computed and the request was neither cancelled nor failed.
    pub fn first_token(&self) -> Result<DenseFirstToken, FirstTokenRefusal> {
        match self.status {
            ExecutionStatus::Completed { at } => Ok(DenseFirstToken {
                request: self.request.clone(),
                generation: self.generation,
                at,
            }),
            ExecutionStatus::Cancelled { .. } => Err(FirstTokenRefusal::Cancelled),
            ExecutionStatus::OutOfMemory { .. } => Err(FirstTokenRefusal::OutOfMemory),
            ExecutionStatus::Running => {
                let groups: Vec<usize> = (0..self.records.len())
                    .filter(|group| self.records[*group].finished_at.is_none())
                    .collect();
                let head = self.records.len() - 1;
                Err(FirstTokenRefusal::MissingGroups {
                    output_head_missing: groups.contains(&head),
                    groups,
                })
            }
        }
    }

    /// Where the request is.
    pub fn status(&self) -> ExecutionStatus {
        self.status
    }

    /// Every availability and compute event, in recording order (GPU-W07 item 3).
    pub fn events(&self) -> &[StreamingEvent] {
        &self.events
    }

    /// Per group: when it became usable, started and finished.
    pub fn records(&self) -> &[GroupRecord] {
        &self.records
    }

    /// The request shape the plan was made for.
    pub fn shape(&self) -> RequestShape {
        self.shape
    }

    /// Seconds the stream waited before each started group: from `origin` for the first,
    /// from the previous group's finish for the rest.
    pub fn observed_waits_seconds(&self, origin: MonotonicTime) -> Vec<f64> {
        let mut previous = origin;
        let mut waits = Vec::new();
        for record in &self.records {
            let Some(started) = record.started_at else {
                break;
            };
            waits.push(started.saturating_duration_since(previous).as_secs_f64());
            match record.finished_at {
                Some(finished) => previous = finished,
                None => break,
            }
        }
        waits
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::ManualClock;
    use crate::model_memory::streaming::architecture::StreamingModel;
    use crate::model_memory::streaming::test_support::*;
    use std::collections::BTreeSet;
    use std::time::Duration;

    const GENERATION: ModelActivationGeneration = ModelActivationGeneration::FIRST;

    fn setup(
        clock: &ManualClock,
    ) -> (
        StreamingModel,
        PlannedRequest,
        StreamingExecution<&ManualClock>,
    ) {
        let model = StreamingModel::new(dense_spec(2, MIB)).unwrap();
        let planned = model.plan_request(shape(8), None).unwrap();
        let execution = StreamingExecution::new(
            clock,
            OperationId::new("op-request-1").unwrap(),
            GENERATION,
            &planned,
            model.tensors().len(),
        )
        .unwrap();
        (model, planned, execution)
    }

    fn deliver(execution: &mut StreamingExecution<&ManualClock>, tensors: &[usize]) {
        for tensor in tensors {
            execution.tensor_usable(*tensor, GENERATION).unwrap();
        }
    }

    #[test]
    fn a_layer_never_computes_before_its_own_weights() {
        let clock = ManualClock::new(MonotonicTime::ZERO);
        let (_, planned, mut execution) = setup(&clock);
        // The embedding (tensor 0) is not usable yet.
        assert_eq!(
            execution.start_group(0, planned.shape),
            Err(StreamingError::Execution(
                ExecutionRefusal::ComputeBeforeUsable {
                    group: 0,
                    missing_tensors: vec![0],
                    missing_buffers: vec![],
                }
            ))
        );
        deliver(&mut execution, &[0]);
        execution.start_group(0, planned.shape).unwrap();
        clock.advance(Duration::from_millis(1));
        execution.finish_group(0).unwrap();
        // Layer 1 needs tensors 1 and 2 and the rotary buffer.
        deliver(&mut execution, &[1]);
        assert_eq!(
            execution.start_group(1, planned.shape),
            Err(StreamingError::Execution(
                ExecutionRefusal::ComputeBeforeUsable {
                    group: 1,
                    missing_tensors: vec![2],
                    missing_buffers: vec![0],
                }
            ))
        );
        // Skipping ahead is refused too.
        assert!(matches!(
            execution.start_group(2, planned.shape),
            Err(StreamingError::Execution(
                ExecutionRefusal::OutOfOrder { .. }
            ))
        ));
    }

    #[test]
    fn a_dense_first_token_before_the_head_is_refused() {
        let clock = ManualClock::new(MonotonicTime::ZERO);
        let (model, planned, mut execution) = setup(&clock);
        deliver(
            &mut execution,
            &(0..model.tensors().len() - 1).collect::<Vec<_>>(),
        );
        execution.buffer_ready(0).unwrap();
        // Every layer computes; the head waits for the final norm (the last tensor).
        for group in 0..planned.groups.len() - 1 {
            execution.start_group(group, planned.shape).unwrap();
            clock.advance(Duration::from_millis(1));
            execution.finish_group(group).unwrap();
        }
        assert_eq!(
            execution.first_token(),
            Err(FirstTokenRefusal::MissingGroups {
                groups: vec![planned.groups.len() - 1],
                output_head_missing: true
            })
        );
        let head = planned.groups.len() - 1;
        assert!(execution.start_group(head, planned.shape).is_err());
        deliver(&mut execution, &[model.tensors().len() - 1]);
        execution.start_group(head, planned.shape).unwrap();
        clock.advance(Duration::from_millis(1));
        execution.finish_group(head).unwrap();
        let token = execution.first_token().unwrap();
        assert_eq!(token.at, MonotonicTime::from_nanos(4_000_000));
        assert_eq!(token.generation, GENERATION);
        // Availability and compute events are all recorded, in order.
        let started = execution
            .events()
            .iter()
            .filter(|e| matches!(e.kind, StreamingEventKind::ComputeStarted { .. }))
            .count();
        assert_eq!(started, planned.groups.len());
        assert!(execution.records().iter().all(|r| r.finished_at.is_some()));
    }

    #[test]
    fn generations_requests_and_shapes_never_mix() {
        let clock = ManualClock::new(MonotonicTime::ZERO);
        let (_, planned, mut execution) = setup(&clock);
        let other = ModelActivationGeneration::new(2);
        assert_eq!(
            execution.tensor_usable(0, other),
            Err(StreamingError::Execution(
                ExecutionRefusal::MixedGenerations {
                    expected: 1,
                    found: 2
                }
            ))
        );
        assert_eq!(
            execution.accept_request(&OperationId::new("op-unrelated").unwrap()),
            Err(ExecutionRefusal::UnrelatedRequest)
        );
        assert!(execution
            .accept_request(&OperationId::new("op-request-1").unwrap())
            .is_ok());
        deliver(&mut execution, &[0]);
        assert_eq!(
            execution.tensor_usable(0, GENERATION),
            Err(StreamingError::Execution(ExecutionRefusal::AlreadyUsable))
        );
        let longer = RequestShape {
            prompt_tokens: 9,
            batch_sequences: 1,
        };
        assert_eq!(
            execution.start_group(0, longer),
            Err(StreamingError::Execution(ExecutionRefusal::ShapeMismatch))
        );
        execution.start_group(0, planned.shape).unwrap();
        assert!(matches!(
            execution.start_group(1, planned.shape),
            Err(StreamingError::Execution(ExecutionRefusal::ComputeBusy {
                running: 0
            }))
        ));
    }

    #[test]
    fn cancellation_mid_prefill_stops_new_work_and_publishes_nothing() {
        let clock = ManualClock::new(MonotonicTime::ZERO);
        let (_, planned, mut execution) = setup(&clock);
        deliver(&mut execution, &[0, 1, 2, 3]);
        execution.buffer_ready(0).unwrap();
        execution.start_group(0, planned.shape).unwrap();
        clock.advance(Duration::from_millis(1));
        execution.finish_group(0).unwrap();
        execution.start_group(1, planned.shape).unwrap();
        let report = execution.cancel().unwrap();
        assert_eq!(report.computed_groups, vec![0]);
        assert_eq!(report.running_group, Some(1));
        // Tensor 3 belongs to layer 2, which will not run; 4 and 5 never arrived.
        assert_eq!(report.usable_tensors, vec![0, 3]);
        assert_eq!(report.pending_tensors, vec![4, 5]);
        // The running kernel finishes; nothing new starts and nothing is published.
        clock.advance(Duration::from_millis(1));
        execution.finish_group(1).unwrap();
        assert_eq!(
            execution.start_group(2, planned.shape),
            Err(StreamingError::Execution(ExecutionRefusal::Ended))
        );
        assert_eq!(
            execution.tensor_usable(4, GENERATION),
            Err(StreamingError::Execution(ExecutionRefusal::Ended))
        );
        assert_eq!(execution.first_token(), Err(FirstTokenRefusal::Cancelled));
    }

    #[test]
    fn out_of_memory_mid_prefill_fails_the_request() {
        let clock = ManualClock::new(MonotonicTime::ZERO);
        let (_, planned, mut execution) = setup(&clock);
        deliver(&mut execution, &[0]);
        execution.start_group(0, planned.shape).unwrap();
        execution.finish_group(0).unwrap();
        let report = execution.out_of_memory(1, 64 * MIB).unwrap();
        assert_eq!(report.computed_groups, vec![0]);
        assert!(matches!(
            execution.status(),
            ExecutionStatus::OutOfMemory {
                group: 1,
                requested_bytes,
                ..
            } if requested_bytes == 64 * MIB
        ));
        assert_eq!(execution.first_token(), Err(FirstTokenRefusal::OutOfMemory));
        assert!(execution.start_group(1, planned.shape).is_err());
    }

    #[test]
    fn a_late_group_mid_prefill_keeps_the_stream_waiting() {
        let clock = ManualClock::new(MonotonicTime::ZERO);
        let (model, planned, mut execution) = setup(&clock);
        deliver(&mut execution, &[0, 1, 2]);
        execution.buffer_ready(0).unwrap();
        for group in 0..2 {
            execution.start_group(group, planned.shape).unwrap();
            clock.advance(Duration::from_millis(1));
            execution.finish_group(group).unwrap();
        }
        // Layer 2's tensors arrive 5 ms late; nothing computes meanwhile.
        assert!(!execution.can_start_next());
        clock.advance(Duration::from_millis(5));
        deliver(&mut execution, &[3, 4, model.tensors().len() - 1]);
        assert!(execution.can_start_next());
        execution.start_group(2, planned.shape).unwrap();
        let waits = execution.observed_waits_seconds(MonotonicTime::ZERO);
        assert_eq!(waits.len(), 3);
        assert!((waits[2] - 0.005).abs() < 1e-12);
        assert_eq!(
            execution.records()[2].usable_at,
            Some(MonotonicTime::from_nanos(7_000_000))
        );
    }

    struct Published(BTreeSet<u64>);

    impl DependencyAvailability for Published {
        fn is_usable(&self, dependency: DependencyId) -> bool {
            self.0.contains(&dependency.0)
        }
    }

    #[test]
    fn executor_publication_marks_tensors_usable() {
        let clock = ManualClock::new(MonotonicTime::ZERO);
        let (_, _, mut execution) = setup(&clock);
        let newly = execution
            .observe(&Published([0, 2].into_iter().collect()), GENERATION)
            .unwrap();
        assert_eq!(newly, vec![0, 2]);
        let again = execution
            .observe(&Published([0, 1, 2].into_iter().collect()), GENERATION)
            .unwrap();
        assert_eq!(again, vec![1]);
        // A publication under another generation is refused.
        assert!(execution
            .observe(
                &Published([3].into_iter().collect()),
                ModelActivationGeneration::new(7)
            )
            .is_err());
    }
}
