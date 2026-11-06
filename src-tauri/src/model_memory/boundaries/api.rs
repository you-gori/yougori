//! Boundary 5 of GPU §3.1: the existing API, CLI and UI adapter.
//!
//! Responsibility: intent, progress, policy and diagnostics. Must not own: raw GPU handles
//! or a new product navigation hierarchy. The adapter hands the flow an [`Intent`] with
//! its [`RequestPolicy`], and receives only [`FlowEvent`]s, [`FlowError`]s and
//! [`RunnerDiagnostics`]. None of these has a field that can hold a
//! [`super::NativeHandle`], a lease, a ledger grant or the request's payload. The trait
//! has no method for pages, tabs or navigation.

use super::abi::CheckedRunner;
use super::flow::{FlowError, FlowEvent};
use super::governor::ReloadConsent;
use super::runner::RunnerDiagnostics;
use crate::foundation::ids::OperationId;
use crate::foundation::ledger::Priority;
use crate::model_memory::identity::ExecutionIdentity;
use crate::model_memory::placement::RequestShape;

/// Choices the caller makes for one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct RequestPolicy {
    /// Allow computing ahead for this request while later state loads (§3.6, line 601).
    pub execute_while_load: bool,
    /// The caller expects to resume the session, so its KV is worth keeping (§3.9).
    pub resume_session: bool,
    /// Whether serving may pause for a reload when the new generation cannot be resident
    /// beside the serving one (GPU-W05 line 110); by default the activation is refused.
    pub reload: ReloadConsent,
}

/// What a user asked for through the existing API, CLI or UI: an exact model, never a
/// name (GPU §1: "exact model and request").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Intent {
    pub model: ExecutionIdentity,
    pub shape: RequestShape,
    /// The priority of the request; it must be its runtime's (CORE-03 children take their
    /// parent's priority).
    pub priority: Priority,
    pub policy: RequestPolicy,
}

/// The API, CLI and UI adapter boundary.
pub trait ApiAdapter {
    /// One progress event (GPU §3.10 fields the flow knows).
    fn progress(&mut self, event: &FlowEvent);

    /// Why an operation was refused or failed.
    fn refusal(&mut self, operation: &OperationId, error: &FlowError);

    /// Runner state for diagnostics.
    fn diagnostics(&mut self, runners: &[RunnerDiagnostics]);
}

/// Sends every admitted runner's diagnostics to the adapter.
pub fn report_diagnostics(runners: &[CheckedRunner<'_>], api: &mut dyn ApiAdapter) {
    let diagnostics: Vec<RunnerDiagnostics> = runners
        .iter()
        .map(|checked| checked.runner().diagnostics())
        .collect();
    api.diagnostics(&diagnostics);
}
