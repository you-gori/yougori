//! M09E: the confined guest relay process: its launch, its handoff and its guest-facing
//! loop (docs/combined-gpu-memory-and-vm-sandbox-plan.md, VM part §3.1 "Separate authority
//! from guest-facing parsing": the guest relay parses bounded frames and forwards typed
//! requests, with no provider secret, no arbitrary host path and no lifecycle privilege,
//! as its own confined process; §16.1: relay at the lowest privilege; VM-W11 "Confined
//! guest relay and restricted transport broker ... No vault values in the generic relay";
//! VM-W03; VM-W28 "No credential in relay"; VM-R17). The relay half of M09.
//!
//! - [`relay_core`]: [`RelayCore`], sans-IO. Guest bytes go through a fresh
//!   [`RequestReader`](crate::sandbox_contract::relay::RequestReader) per guest
//!   connection; the route comes from the sandbox's [`RouteTable`] (policy data: no budget,
//!   no credential); the request is rebuilt from the parsed request, as the fixed point the
//!   broker's relay step expects ([`forward_bytes`]), and forwarded as
//!   [`RelayMessage::Forward`](crate::sandbox_contract::relay_link::RelayMessage::Forward)
//!   with exchanges numbered upward, at most
//!   [`MAX_OPEN_EXCHANGES`](crate::sandbox_contract::relay_link::MAX_OPEN_EXCHANGES) held.
//!   The broker's response bytes go to the guest; a refusal or a closed link gives the
//!   guest the fixed [`GUEST_ERROR_RESPONSE`].
//! - [`serve`]: the loop between a [`GuestPort`] (byte streams per guest connection; the
//!   real transport is M06's) and a [`RelayLinkPort`] (the link pipe on Windows).
//! - [`handoff`]: one strict, bounded, versioned message, never in argv, the environment
//!   or an inherited handle: the link key, the
//!   [`LinkBinding`](crate::sandbox_contract::relay_link::LinkBinding), the broker's PX1
//!   identity, the route table and the reader limits, written by the broker on the relay's
//!   own link pipe once it has admitted the relay by PX1 identity, ahead of the link. The
//!   key never appears in `Debug`, `Display` or an error, and its buffers are overwritten
//!   after use, best effort.
//! - [`entry`]: [`relay_main`], which refuses to run unless the process is confined (on
//!   Windows an AppContainer token at low integrity with no capability SID), then opens
//!   its link pipe by its own PX1 identity, admits the server only if it is its creator,
//!   reads the handoff, checks it binds this process, opens the link and serves.
//! - [`launch`] (Windows): [`launch_relay`] starts the relay through PX1 in a kill-on-close
//!   job, in a per-sandbox AppContainer profile with no capabilities, inheriting no handle,
//!   with read and execute granted on its executable only, and removes the profile and the
//!   grant when the relay ends.
//!
//! The relay knows nothing of the guest's TLS: the guest transport hands it plaintext
//! HTTP per guest connection, and the forward frame carries no SNI. The broker takes the
//! facts of the guest's TLS connection from its own port (M06).
//!
//! Outside this module: the engine's hidden mode or binary that calls [`relay_main`] and
//! the broker starting a relay per sandbox; Unix and macOS confinement (the relay refuses
//! to run there); the guest transport (M06); the broker's side (M09D); live validation
//! (E01).

pub mod entry;
pub mod handoff;
#[cfg(windows)]
pub mod launch;
pub mod relay_core;
pub mod serve;
#[cfg(windows)]
pub mod token;

#[cfg(all(test, windows))]
mod launch_tests;
#[cfg(test)]
mod tests;

pub use entry::{
    check_confined, relay_main, relay_main_with, ConfinementError, RelayExit, CONNECT_WITHIN,
};
pub use handoff::{
    decode_handoff, GuestPipeHandoff, Handoff, HandoffError, HANDOFF_VERSION, MAX_HANDOFF_BYTES,
};
#[cfg(windows)]
pub use launch::{
    launch_relay, profile_name, LaunchError, LaunchStep, LaunchedRelay, RelayEnd, RelayLaunch,
    END_ESCALATION, EXECUTABLE_ACCESS, LOCALAPPDATA_PLACEHOLDER, PROFILE_NAME_DOMAIN,
    PROFILE_NAME_PREFIX, RELAY_KEY_BYTES,
};
pub use relay_core::{
    forward_bytes, GuestConnection, GuestEndpoint, GuestRefusal, RelayAction, RelayCore,
    RouteEntry, RouteTable, RouteTableError, CONTINUE_RESPONSE, GUEST_ERROR_RESPONSE, MAX_ROUTES,
};
pub use serve::{
    serve, GuestEvent, GuestPort, GuestPortError, LinkPortError, RelayLinkPort, ServeEnd,
    ServeTiming,
};
#[cfg(windows)]
pub use token::{
    own_creator_pid, own_token_facts, process_token_facts, token_facts, TokenFacts,
    LOW_INTEGRITY_RID,
};
