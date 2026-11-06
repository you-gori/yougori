//! The engine binary as the confined guest relay (module docs in `mod.rs`): M09E's
//! [`relay_main_with`] with the guest port that opens the engine's guest pipe named in the
//! handoff, admitting only the engine the executor named. The process reads nothing from
//! argv or the environment; the exit code is [`RelayExit::code`].

use std::time::Duration;

use crate::sandbox_contract::relay_link::guest_pipe::PipeGuestPort;
use crate::sandbox_contract::relay_link::RelayPipeName;
use crate::sandbox_contract::relay_process::{relay_main_with, GuestPipeHandoff, CONNECT_WITHIN};

/// How long one write to the guest pipe may take before the relay treats the engine as gone.
pub const GUEST_SEND_WITHIN: Duration = Duration::from_secs(30);

/// Opens the guest pipe `handoff` names (the relay's own guest port).
pub fn open_guest_pipe(handoff: Option<&GuestPipeHandoff>) -> Result<PipeGuestPort, String> {
    let handoff = handoff.ok_or_else(|| "the handoff names no guest pipe".to_owned())?;
    let name = RelayPipeName::new(handoff.name.clone())
        .map_err(|error| format!("the guest pipe's name was refused: {error}"))?;
    PipeGuestPort::connect(&name, handoff.engine_pid, CONNECT_WITHIN, GUEST_SEND_WITHIN)
        .map_err(|error| error.to_string())
}

/// Runs this process as the confined relay; the exit code.
pub fn run_relay() -> i32 {
    relay_main_with(open_guest_pipe).code()
}
