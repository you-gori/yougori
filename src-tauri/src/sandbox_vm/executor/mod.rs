//! The sandbox executor: the process that holds the sandbox vault and brokers every
//! sandbox's confined relay, separate from the engine (M09/M11/M12 at the first production
//! boundary; docs/combined-gpu-memory-and-vm-sandbox-plan.md, VM part §3.1 "Separate
//! authority from guest-facing parsing" and line 3063 "the same binary started in distinct
//! modes under distinct OS restrictions ... executor with vault access and no guest-facing
//! parser beyond provider responses"; §4.5 and VM-W28 "Avoid unnecessary secret copies
//! through the engine"; VM-W11, VM-W12).
//!
//! Three processes of one binary:
//!
//! - the **engine** (`sandbox_vm`), which runs the VM, owns the sandbox lifecycle and serves
//!   each relay's guest pipe as the VM service's egress port ([`pipe_port`]), and holds no
//!   credential and no broker;
//! - the **executor** ([`process`]), started by the engine as `--sandbox-executor PIPE
//!   ENGINE_PID` in its kill-on-close job, admitted on an owner-only control pipe by PX1
//!   identity ([`relay_link::control_pipe`](crate::sandbox_contract::relay_link::control_pipe)),
//!   which builds each sandbox's V02 destination policy and M09D broker from the engine's
//!   route declarations ([`broker_build`]) over a vault of its own granted exactly those
//!   routes' credentials (M11B's store under the OS credential manager), launches and
//!   supervises the relay through M09F ([`relay_host`](crate::sandbox_contract::relay_host)),
//!   and stops every relay when the engine goes;
//! - the **relay** ([`relay_mode`]), M09E's confined AppContainer process with no
//!   capabilities, which parses the guest's HTTP from the guest pipe and forwards typed
//!   requests over its sealed link to the executor's broker.
//!
//! The control protocol ([`protocol`]) is JSON lines, strict on both sides. A credential
//! crosses the engine once, at `credential enroll`, from the CLI's stdin through the engine's
//! transient copy to the executor's store (both copies overwritten after use); at use the
//! executor reads its own store and injects the header on the upstream connection, and
//! nothing of the value returns. The engine's `sandbox_vm` method reaches all of it: a
//! `launch` with `routes` starts the relay beside the VM and attaches the guest pipe as the
//! sandbox's egress port; `status` shows the relay; `stop` and `revoke` end it with the
//! matching close reason; `credential` enrolls, removes or checks a credential.
//!
//! **Recorded gaps.** The executor runs under the engine's own token (not yet a restricted
//! one); the host's interface addresses are not enumerated into the policy (loopback only,
//! the broker's address classes refuse the rest of the local space); the relays' upstream TLS
//! uses the host's roots, so a local test upstream must be public-addressed or plaintext.

// The protocol is read on every platform (the engine parses route declarations with it);
// the executor's processes and pipes run on Windows only (module docs in `sandbox_vm`).
#[cfg(windows)]
pub mod broker_build;
#[cfg(windows)]
pub mod client;
#[cfg(windows)]
pub mod pipe_port;
#[cfg(windows)]
pub mod process;
pub mod protocol;
#[cfg(windows)]
pub mod relay_mode;
#[cfg(windows)]
pub mod resolver;

#[cfg(all(test, windows))]
mod tests;

/// The argument that runs this binary as the sandbox executor.
#[cfg(windows)]
pub const EXECUTOR_MODE: &str = "--sandbox-executor";

/// The argument that runs this binary as the confined guest relay.
#[cfg(windows)]
pub const RELAY_MODE: &str = "--sandbox-relay";

#[cfg(windows)]
pub use client::ExecutorClient;
#[cfg(windows)]
pub use pipe_port::PipeEgressPort;
pub use protocol::RouteDeclaration;
#[cfg(windows)]
pub use protocol::{ExecutorReply, ExecutorRequest};
