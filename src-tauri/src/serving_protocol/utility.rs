//! Agent task utility, the third evidence level (S9 line 173; S11 BENCH-03 "two parallel
//! tools, a file edit, failing test and repair"; BENCH-04 "completed agent-task rate").
//!
//! An [`AgentTaskRecorder`] stamps each step of one scripted task attempt from the
//! injected clock and derives the outcome; a record cannot claim success it did not
//! show. Success needs real tool execution (only a validated turn counts), the declared
//! number of parallel calls in one turn, a file change, a failing test, a later change
//! and a final passing test, all within the declared budget. Task success is reported
//! with CORE-08's [`SuccessRate`] over original attempts and its [`RetryTally`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use serde::Serialize;

use crate::foundation::ids::{Clock, MonotonicTime, OperationId};
use crate::foundation::report::{FailureKind, Label, ReportError, RetryTally, SuccessRate};

use super::validation::ValidatedTurn;

/// The declared budget of one attempt (S9 line 173: "within a declared budget").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct TaskBudget {
    pub max_turns: u32,
    pub max_tool_calls: u32,
    pub max_elapsed_seconds: u64,
}

/// What the scripted task must show beyond the steps every task needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct TaskRequirements {
    /// Calls that must run together in one turn.
    pub min_parallel_calls: u32,
}

impl TaskRequirements {
    /// BENCH-03: "with two parallel tools" (S11 line 195).
    pub const BENCH_03: Self = Self {
        min_parallel_calls: 2,
    };
}

/// Whether an attempt is an original attempt or a retry of one (S9 line 175: task
/// success uses the original attempts denominator).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AttemptKind {
    Original,
    Retry { first_attempt: OperationId },
}

/// A step the harness observed (S9 line 173).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "step", rename_all = "snake_case")]
pub enum Milestone {
    /// A validated turn's calls ran.
    ToolsExecuted {
        calls: u32,
    },
    FileChanged,
    TestFailed,
    TestPassed,
}

/// A step and when the clock read it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct MilestoneAt {
    pub at: MonotonicTime,
    pub milestone: Milestone,
}

/// A required step that did not happen.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStep {
    ToolExecution,
    ParallelCalls,
    FileChange,
    FailingTest,
    /// A change after the failing test, then a final passing test.
    Repair,
}

/// The budget limit an attempt exceeded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetLimit {
    Turns,
    ToolCalls,
    ElapsedSeconds,
}

/// How an attempt ended (S9 line 173).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum TaskOutcome {
    Succeeded,
    OverBudget { limit: BudgetLimit },
    Incomplete { missing: Vec<TaskStep> },
    Aborted { reason: Label },
}

impl TaskOutcome {
    /// Whether the attempt succeeded.
    pub fn succeeded(&self) -> bool {
        matches!(self, Self::Succeeded)
    }

    /// The CORE-08 failure kind: a budget overrun is a deadline failure, missing steps
    /// an invalid result, an abort an early termination.
    pub fn failure_kind(&self) -> Option<FailureKind> {
        match self {
            Self::Succeeded => None,
            Self::OverBudget { .. } => Some(FailureKind::DeadlineFailure),
            Self::Incomplete { .. } => Some(FailureKind::InvalidResult),
            Self::Aborted { .. } => Some(FailureKind::EarlyTermination),
        }
    }
}

/// Records one scripted task attempt from an injected clock (S9 line 173).
#[derive(Debug)]
pub struct AgentTaskRecorder<C: Clock> {
    clock: C,
    task: Label,
    attempt: OperationId,
    kind: AttemptKind,
    budget: TaskBudget,
    requirements: TaskRequirements,
    started_at: MonotonicTime,
    turns: u32,
    tool_calls: u32,
    most_parallel_calls: u32,
    milestones: Vec<MilestoneAt>,
}

impl<C: Clock> AgentTaskRecorder<C> {
    /// Starts an attempt now, by `clock`.
    pub fn start(
        clock: C,
        task: Label,
        attempt: OperationId,
        kind: AttemptKind,
        budget: TaskBudget,
        requirements: TaskRequirements,
    ) -> Self {
        let started_at = clock.now();
        Self {
            clock,
            task,
            attempt,
            kind,
            budget,
            requirements,
            started_at,
            turns: 0,
            tool_calls: 0,
            most_parallel_calls: 0,
            milestones: Vec::new(),
        }
    }

    /// A model turn ended.
    pub fn turn(&mut self) {
        self.turns = self.turns.saturating_add(1);
    }

    /// A validated turn's calls ran. Only a validated turn can be recorded, so a partial
    /// call never counts as tool execution.
    pub fn tools_executed(&mut self, turn: &ValidatedTurn) {
        let calls = u32::try_from(turn.calls().len()).unwrap_or(u32::MAX);
        if calls == 0 {
            return;
        }
        self.tool_calls = self.tool_calls.saturating_add(calls);
        self.most_parallel_calls = self.most_parallel_calls.max(calls);
        self.mark(Milestone::ToolsExecuted { calls });
    }

    /// The task changed a file.
    pub fn file_changed(&mut self) {
        self.mark(Milestone::FileChanged);
    }

    /// The task ran its test, which passed or failed.
    pub fn test_run(&mut self, passed: bool) {
        self.mark(if passed {
            Milestone::TestPassed
        } else {
            Milestone::TestFailed
        });
    }

    /// Ends the attempt and derives its outcome.
    pub fn finish(self) -> AgentTaskRecord {
        let finished_at = self.clock.now();
        let outcome = self.derive_outcome(finished_at);
        self.into_record(finished_at, outcome)
    }

    /// Ends the attempt early.
    pub fn abort(self, reason: Label) -> AgentTaskRecord {
        let finished_at = self.clock.now();
        self.into_record(finished_at, TaskOutcome::Aborted { reason })
    }

    fn mark(&mut self, milestone: Milestone) {
        self.milestones.push(MilestoneAt {
            at: self.clock.now(),
            milestone,
        });
    }

    fn derive_outcome(&self, finished_at: MonotonicTime) -> TaskOutcome {
        let elapsed = finished_at.saturating_duration_since(self.started_at);
        if self.turns > self.budget.max_turns {
            return TaskOutcome::OverBudget {
                limit: BudgetLimit::Turns,
            };
        }
        if self.tool_calls > self.budget.max_tool_calls {
            return TaskOutcome::OverBudget {
                limit: BudgetLimit::ToolCalls,
            };
        }
        if elapsed > Duration::from_secs(self.budget.max_elapsed_seconds) {
            return TaskOutcome::OverBudget {
                limit: BudgetLimit::ElapsedSeconds,
            };
        }
        let steps: Vec<Milestone> = self.milestones.iter().map(|step| step.milestone).collect();
        let position = |wanted: fn(&Milestone) -> bool| steps.iter().position(wanted);
        let mut missing = Vec::new();
        if position(|step| matches!(step, Milestone::ToolsExecuted { .. })).is_none() {
            missing.push(TaskStep::ToolExecution);
        }
        if self.most_parallel_calls < self.requirements.min_parallel_calls {
            missing.push(TaskStep::ParallelCalls);
        }
        if position(|step| *step == Milestone::FileChanged).is_none() {
            missing.push(TaskStep::FileChange);
        }
        match position(|step| *step == Milestone::TestFailed) {
            None => missing.push(TaskStep::FailingTest),
            Some(first_failure) => {
                let last_test = steps.iter().rposition(|step| {
                    matches!(step, Milestone::TestFailed | Milestone::TestPassed)
                });
                let change_after_failure = steps
                    .iter()
                    .enumerate()
                    .skip(first_failure)
                    .find(|(_, step)| **step == Milestone::FileChanged)
                    .map(|(index, _)| index);
                let repaired = match (change_after_failure, last_test) {
                    (Some(change), Some(last)) => {
                        last > change && steps.get(last) == Some(&Milestone::TestPassed)
                    }
                    _ => false,
                };
                if !repaired {
                    missing.push(TaskStep::Repair);
                }
            }
        }
        if missing.is_empty() {
            TaskOutcome::Succeeded
        } else {
            TaskOutcome::Incomplete { missing }
        }
    }

    fn into_record(self, finished_at: MonotonicTime, outcome: TaskOutcome) -> AgentTaskRecord {
        AgentTaskRecord {
            task: self.task,
            attempt: self.attempt,
            kind: self.kind,
            budget: self.budget,
            requirements: self.requirements,
            started_at: self.started_at,
            finished_at,
            turns: self.turns,
            tool_calls: self.tool_calls,
            most_parallel_calls: self.most_parallel_calls,
            milestones: self.milestones,
            outcome,
        }
    }
}

/// One scripted task attempt and its derived outcome (S9 line 173). Only an
/// [`AgentTaskRecorder`] makes one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AgentTaskRecord {
    task: Label,
    attempt: OperationId,
    kind: AttemptKind,
    budget: TaskBudget,
    requirements: TaskRequirements,
    started_at: MonotonicTime,
    finished_at: MonotonicTime,
    turns: u32,
    tool_calls: u32,
    most_parallel_calls: u32,
    milestones: Vec<MilestoneAt>,
    outcome: TaskOutcome,
}

impl AgentTaskRecord {
    /// The scripted task.
    pub fn task(&self) -> &Label {
        &self.task
    }

    /// This attempt's operation.
    pub fn attempt(&self) -> &OperationId {
        &self.attempt
    }

    /// Original attempt or retry.
    pub fn kind(&self) -> &AttemptKind {
        &self.kind
    }

    /// The derived outcome.
    pub fn outcome(&self) -> &TaskOutcome {
        &self.outcome
    }

    /// Time from start to finish on the injected clock.
    pub fn elapsed(&self) -> Duration {
        self.finished_at.saturating_duration_since(self.started_at)
    }

    /// Model turns recorded.
    pub fn turns(&self) -> u32 {
        self.turns
    }

    /// Validated calls executed.
    pub fn tool_calls(&self) -> u32 {
        self.tool_calls
    }

    /// Every recorded step, in order.
    pub fn milestones(&self) -> &[MilestoneAt] {
        &self.milestones
    }
}

/// Task success over every original attempt, with retries reported apart (S9 line 175;
/// S13 line 250: the BENCH-04 all-attempt denominator).
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct TaskSuccess {
    pub original_attempts: SuccessRate,
    pub retries: RetryTally,
}

/// Why attempts cannot be tallied.
#[derive(Clone, Debug, PartialEq)]
pub enum TaskSuccessError {
    DuplicateAttempt {
        attempt: OperationId,
    },
    /// A retry names an attempt that is not an original attempt in the set.
    UnknownFirstAttempt {
        attempt: OperationId,
    },
    /// A retry of an original attempt that had already succeeded.
    RetryAfterSuccess {
        attempt: OperationId,
    },
    Report(ReportError),
}

impl fmt::Display for TaskSuccessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateAttempt { attempt } => write!(f, "attempt {attempt} appears twice"),
            Self::UnknownFirstAttempt { attempt } => {
                write!(f, "retry {attempt} names no original attempt in the set")
            }
            Self::RetryAfterSuccess { attempt } => {
                write!(
                    f,
                    "retry {attempt} follows an original attempt that succeeded"
                )
            }
            Self::Report(error) => write!(f, "{error:?}"),
        }
    }
}

impl std::error::Error for TaskSuccessError {}

/// Successful original attempts over all original attempts, whatever ended them; a
/// retry never adds to either number (S9 line 175).
pub fn task_success(records: &[AgentTaskRecord]) -> Result<TaskSuccess, TaskSuccessError> {
    let mut originals: BTreeMap<&OperationId, bool> = BTreeMap::new();
    for record in records {
        if record.kind == AttemptKind::Original
            && originals
                .insert(&record.attempt, record.outcome.succeeded())
                .is_some()
        {
            return Err(TaskSuccessError::DuplicateAttempt {
                attempt: record.attempt.clone(),
            });
        }
    }
    let mut retries = RetryTally::default();
    let mut recovered = BTreeSet::new();
    let mut retry_ids = BTreeSet::new();
    for record in records {
        let AttemptKind::Retry { first_attempt } = &record.kind else {
            continue;
        };
        if originals.contains_key(&record.attempt) || !retry_ids.insert(&record.attempt) {
            return Err(TaskSuccessError::DuplicateAttempt {
                attempt: record.attempt.clone(),
            });
        }
        match originals.get(first_attempt) {
            None => {
                return Err(TaskSuccessError::UnknownFirstAttempt {
                    attempt: record.attempt.clone(),
                })
            }
            Some(true) => {
                return Err(TaskSuccessError::RetryAfterSuccess {
                    attempt: record.attempt.clone(),
                })
            }
            Some(false) => {}
        }
        retries.retries = retries.retries.saturating_add(1);
        if record.outcome.succeeded() {
            retries.successful_retries = retries.successful_retries.saturating_add(1);
            recovered.insert(first_attempt);
        }
    }
    retries.recovered_first_attempts = recovered.len() as u64;
    let successes = originals.values().filter(|succeeded| **succeeded).count() as u64;
    let original_attempts =
        SuccessRate::new(successes, originals.len() as u64).map_err(TaskSuccessError::Report)?;
    Ok(TaskSuccess {
        original_attempts,
        retries,
    })
}
