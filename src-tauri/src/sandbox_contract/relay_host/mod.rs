//! M09F: the broker starts and supervises one confined relay per sandbox
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md, VM part §3.1 "Separate authority from
//! guest-facing parsing"; VM-W11 "Confined guest relay and restricted transport broker";
//! VM-W03). What joins M09's committed pieces: M09E's launch, admission and handoff
//! ([`relay_process`](crate::sandbox_contract::relay_process)), M09C's sealed link over the
//! named pipe ([`relay_link`](crate::sandbox_contract::relay_link)) and M09D's broker loop
//! ([`relay_broker`](crate::sandbox_contract::relay_broker)), for the life of one sandbox's
//! relay.
//!
//! - [`host`]: [`RelayHost`], one sandbox's relay from launch to its end. `start` launches
//!   the relay through the [`RelayBackend`], admits it on its pipe within a bound (the
//!   handoff goes with the admission, as M09E wrote it), bridges the blocking link onto a
//!   thread and serves it with [`RelayBroker::serve`] on a thread of its own with a
//!   current-thread runtime. `poll` notices a relay that exited or a link that ended; `stop`
//!   closes the link with the reason ([`StopReason::Revoked`] when the sandbox's CORE-04
//!   authority ended, [`StopReason::Teardown`] otherwise), joins the serving thread within a
//!   bound or abandons it, ends the relay through the backend (which revokes the executable
//!   grant and deletes the AppContainer profile) and records the life. A stop is idempotent.
//!   **No automatic restart**: a relay that ends on its own stays down with its typed
//!   reason until its owner launches again. A relay's death is a fault or an attack on the
//!   guest-facing parser, and a restart would hand a new key to a process of the same
//!   sandbox without anyone having decided that; the owner of the sandbox decides.
//! - [`backend`]: the [`RelayBackend`] port (launch, admit, observe the end, end and clean
//!   up) and its Windows implementation over `relay_process` ([`WindowsRelayBackend`]).
//!   Elsewhere every start is refused with [`StartError::Unsupported`].
//! - [`registry`]: [`RelayHosts`], at most one running relay per sandbox: a second start for
//!   a running sandbox is refused, not replaced; an ended one may be replaced.
//! - [`RelayLife`]: the typed record of one relay's life for the audit sink: the sandbox,
//!   the relay's PX1 identity, whether it was admitted, how it ended, the broker's exchange
//!   records, whether the host has proof of the end and whether cleanup succeeded. No
//!   credential, key or guest body is in any record, `Debug`, `Display` or error.
//!
//! Outside this module: who creates a host per sandbox (the engine's executor process wiring,
//! `sandbox_vm`), the guest transport that feeds the relay (M06, the guest-facing pipe), the
//! `sandbox-host` binary or hidden mode that runs `relay_main` (the backend only names the
//! executable and its arguments), Unix and macOS, live validation (E01).

pub mod backend;
pub mod host;
pub mod registry;

#[cfg(test)]
mod tests;
#[cfg(all(test, windows))]
mod windows_tests;

#[cfg(windows)]
pub use backend::WindowsRelayBackend;
pub use backend::{EndOutcome, RelayBackend, RelayHandle};
pub use host::{
    RelayEndReason, RelayFacts, RelayHost, RelayHostSettings, RelayLife, RelayLifeSummary,
    RelayStatus, StartError, StopReason,
};
pub use registry::RelayHosts;
