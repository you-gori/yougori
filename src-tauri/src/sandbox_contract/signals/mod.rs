//! M17A: host enforcement points feed sourced response signals, a slice of VM-W43 over
//! VM-W42 (docs/combined-gpu-memory-and-vm-sandbox-plan.md: the VM-W42 and VM-W43 rows;
//! VM part §8.2 "Detection and audit": "Keep authorization decisions, operation IDs,
//! budgets, lease events, launch facts and termination receipts outside the guest ...
//! label telemetry sources correctly"). Tier 0 only (§12.1): pure, synchronous library
//! code over fakes.
//!
//! Several host components already refuse things. Each refusal is a host observation, and
//! some of them are known violations that V14 ([`crate::sandbox_contract::response`])
//! should respond to. This module turns each enforcement point's refusal or observation
//! into a V14 [`SignalDraft`](crate::sandbox_contract::response::SignalDraft) with the
//! host observer that saw it, the V14 violation kind, a subject digest, the reading, the
//! observation time on the shared host clock and the violated grant where one is
//! compromised. The adapters are pure functions, and each classifies its point's outcomes
//! explicitly ([`Classification`]): a guest violation with a typed cause and its draft, a
//! host check that passed, a [`HostAnomaly`] with its [`AnomalyNotice`], or an ordinary
//! outcome with a typed reason ([`Ordinary`]) and no draft.
//!
//! The rule throughout: a signal may revoke or stop a sandbox only for something its guest
//! did. A host bug or wiring fault is ordinary; a host-side anomaly that may weaken the
//! sandbox's confinement gets V14's uncertain result (notify the user, deny new
//! high-impact operations) and never a revocation or a stop. A violation names a grant,
//! which V14 then also revokes in every sandbox holding it, only where the grant itself is
//! compromised, in exactly two cases: a file grant presented from another trust scope than
//! the one it binds, and the grant a canary credential was presented on. A guest's own
//! misuse of a shared grant, such as a route, stops that sandbox and names no grant.
//!
//! - [`file`]: M12 [`FileService`](crate::sandbox_contract::files::FileService) refusals.
//!   The grant presented from another trust scope is a file-root escape the supervisor
//!   saw. A link or device beneath the root is ordinary in a live workspace and a host
//!   anomaly beneath a read-only snapshot or quarantine output, which only the host and
//!   the service write; a case alias is an ordinary spelling refusal.
//! - [`broker`]: V02 destination broker refusals. A connection to an address outside the
//!   validated answer is a perimeter-rule violation the perimeter saw; a release overrun is
//!   a budget overrun the broker saw. A reservation the account never issued is host
//!   wiring.
//! - [`perimeter`]: V16 installer outcomes. A survey or read-back that finds the
//!   perimeter not holding what it installed is a perimeter-rule violation the perimeter
//!   saw; a foreign rule changed or a rule under the perimeter's tag that no transaction
//!   recorded is a host anomaly; a committed install whose read-back checked everything is
//!   a passed check.
//! - [`canary`]: V09 canary hits through V14's own mapping, and credentials refused at the
//!   vault, an executor or an import because they carry a canary, with the observer V14
//!   accepts for a canary use; both a signal and never proof.
//! - [`collector`]: a bounded per-sandbox collector that checks each draft with V14,
//!   merges repeats, lets a violation supersede its observer's earlier passed checks,
//!   keeps places for host observations that guest reports cannot take, keeps anomaly
//!   notices beside the signals, and counts every drop.
//! - [`resource`] (M17B), with [`release`], [`connection_rate`] and [`disk`]: resource
//!   readings for V14's sustained windows from the V02 release account, the connections
//!   gate and the file service's usage counts; the resources without a committed source
//!   stay open.
//! - [`job`] (M17C): CPU, memory and process-count readings from the job of a VM's host
//!   process (PX1); packets per second stays open.
//!
//! The sandbox a signal is about is the one the host knows from the channel, handle or
//! perimeter it served, and its time is a reading of the host clock V14 assesses against
//! ([`Observed`]); nothing the guest claims names either. Which process runs which
//! enforcement point (the supervisor, the broker, the relay, the perimeter installer), how
//! a refusal travels from it to the engine, and who assesses and applies the responses and
//! the anomaly notices is real process wiring and outside this module.

pub mod broker;
pub mod canary;
pub mod collector;
pub mod connection_rate;
pub mod disk;
pub mod file;
pub mod job;
pub mod observed;
pub mod perimeter;
pub mod release;
pub mod resource;

#[cfg(test)]
mod broker_tests;
#[cfg(test)]
mod canary_tests;
#[cfg(test)]
mod collector_tests;
#[cfg(test)]
mod file_tests;
#[cfg(test)]
mod fixtures;
#[cfg(test)]
mod job_tests;
#[cfg(test)]
mod kind_tests;
#[cfg(test)]
mod perimeter_tests;
#[cfg(test)]
mod resource_tests;

pub use broker::{
    classify_broker_refusal, destination_refusal_signal, route_subject, BrokerContext,
    BrokerRefusalClass, BrokerViolation, ROUTE_SUBJECT_DOMAIN,
};
pub use canary::{
    canary_credential_signal, canary_hit_signal, CanaryViolation, CredentialCheckpoint,
};
pub use collector::{
    CollectRefusal, Collected, CollectorBounds, CollectorProblem, CollectorTotals, SignalBatch,
    SignalCollector,
};
pub use connection_rate::{connection_rate_reading, ConnectionCount, CONNECTION_RATE_OBSERVER};
pub use disk::{disk_reading, RootUsage, DISK_OBSERVER};
pub use file::{
    file_refusal_signal, file_subject, FileServiceContext, FileViolation, FILE_SERVICE_OBSERVER,
    FILE_SUBJECT_DOMAIN, FILE_VIOLATION_KIND,
};
pub use job::{
    cpu_reading, memory_reading, process_count_reading, JobCoverage, JobSnapshot, CPU_OBSERVER,
    MEMORY_OBSERVER, MIN_CPU_WINDOW, PROCESS_COUNT_OBSERVER,
};
pub use observed::{AnomalyNotice, Classification, HostAnomaly, Observed, Ordinary, ScopeMismatch};
pub use perimeter::{
    install_refusal_signal, install_signal, recovery_signal, PerimeterContext, PerimeterViolation,
    PERIMETER_OBSERVER, PERIMETER_VIOLATION_KIND,
};
pub use release::{release_spent_reading, RELEASE_OBSERVER};
pub use resource::{ResourceReading, MEASURED_RESOURCES, OPEN_RESOURCES};
