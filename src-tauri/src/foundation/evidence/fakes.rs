//! Fake probe adapters for tests (CORE-01). They return scripted observations and touch
//! nothing on the host.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use super::envelope::{
    Capability, ConfigurationFingerprint, Observation, SourceClass, UnknownReason,
};
use super::registry::{HostChange, ProbeAdapter};
use super::subject::Subject;
use crate::foundation::ids::Digest;

/// A probe with scripted observations per subject. A subject without a script is
/// reported as not tested, never as supported (VM-CP-35).
pub struct FakeProbe {
    capability: Capability,
    source: SourceClass,
    scripted_only: bool,
    host_changes: Mutex<Vec<HostChange>>,
    responses: Mutex<BTreeMap<Digest, Observation>>,
    calls: AtomicUsize,
}

impl FakeProbe {
    pub fn new(capability: Capability, source: SourceClass) -> Self {
        Self {
            capability,
            source,
            scripted_only: false,
            host_changes: Mutex::new(Vec::new()),
            responses: Mutex::new(BTreeMap::new()),
            calls: AtomicUsize::new(0),
        }
    }

    /// Host probe of legacy CUDA IPC (`cudaIpcGetMemHandle`/`cudaIpcOpenMemHandle`).
    pub fn legacy_cuda_ipc() -> Self {
        Self::new(Capability::CudaIpcLegacy, SourceClass::HostProbe)
    }

    /// Host probe of CUDA VMM shareable handles, a different API family from legacy IPC
    /// (GPU part §1.1).
    pub fn cuda_vmm_shareable_handles() -> Self {
        Self::new(
            Capability::CudaIpcVmmShareableHandle,
            SourceClass::HostProbe,
        )
    }

    /// Host probe of hypervisor availability.
    pub fn hypervisor_availability() -> Self {
        Self::new(Capability::HypervisorAvailable, SourceClass::HostProbe)
    }

    /// Provider API check that a resource runs as a provider container (VM-D5).
    pub fn provider_container() -> Self {
        Self::new(Capability::ProviderContainer, SourceClass::ProviderApi)
    }

    /// A check of a runtime's execution category from `source`, such as a host probe for
    /// local runtimes or the provider API for pods (INT-07).
    pub fn runtime_category(source: SourceClass) -> Self {
        Self::new(Capability::RuntimeCategory, source)
    }

    /// A report relayed from inside a guest, pod or other runtime.
    pub fn guest_report(capability: Capability) -> Self {
        Self::new(capability, SourceClass::GuestReport)
    }

    /// Makes the probe observe only the subjects it has a script for, so it can share a
    /// capability with an adapter of another source.
    pub fn scripted_only(mut self) -> Self {
        self.scripted_only = true;
        self
    }

    /// What the next observations of `subject` return.
    pub fn respond(&self, subject: &Subject, observation: Observation) {
        lock(&self.responses).insert(subject.identity(), observation);
    }

    /// Makes the probe declare a host change, which the registry refuses.
    pub fn declare_host_change(&self, change: HostChange) {
        lock(&self.host_changes).push(change);
    }

    /// How many times the registry called [`ProbeAdapter::observe`].
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl ProbeAdapter for FakeProbe {
    fn capability(&self) -> Capability {
        self.capability
    }

    fn source(&self) -> SourceClass {
        self.source
    }

    fn host_changes(&self) -> Vec<HostChange> {
        lock(&self.host_changes).clone()
    }

    fn observes(&self, subject: &Subject) -> bool {
        !self.scripted_only || lock(&self.responses).contains_key(&subject.identity())
    }

    fn observe(&self, subject: &Subject) -> Observation {
        self.calls.fetch_add(1, Ordering::SeqCst);
        lock(&self.responses)
            .get(&subject.identity())
            .cloned()
            .unwrap_or_else(|| {
                Observation::unknown(
                    ConfigurationFingerprint::from_digest(Digest::from_bytes([0; 32])),
                    Duration::ZERO,
                    UnknownReason::NotTested,
                )
            })
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
