//! Host process handles on platforms that have none here yet (S04). Every call is refused
//! with a typed error and no process is started; Linux pidfds and macOS framework VM
//! objects (VM part §6.4) are still to come.

use std::process::Command;
use std::time::Duration;

use super::handle::ProcessError;
use super::identity::ProcessIdentity;
use super::proof::{Ended, NoProof};
use super::usage::JobUsage;

/// No process handle exists on this platform, so the type has no values.
pub(super) enum Process {}

fn unsupported() -> ProcessError {
    ProcessError::Unsupported {
        platform: std::env::consts::OS.to_owned(),
    }
}

/// Refused: nothing is started.
pub(super) fn spawn(_command: &mut Command) -> Result<(Process, ProcessIdentity), ProcessError> {
    Err(unsupported())
}

/// Refused: no process is looked up.
pub(super) fn holder_of(_pid: u32) -> Result<Option<ProcessIdentity>, ProcessError> {
    Err(unsupported())
}

/// Refused: no process is looked up.
pub(super) fn running(_identity: &ProcessIdentity) -> Result<bool, ProcessError> {
    Err(unsupported())
}

impl Process {
    pub(super) fn observe(&self, _within: Duration) -> Result<Ended, NoProof> {
        match *self {}
    }

    pub(super) fn kill(&self, _code: u32) -> Result<(), NoProof> {
        match *self {}
    }

    pub(super) fn usage(&self) -> Result<JobUsage, ProcessError> {
        match *self {}
    }
}

#[cfg(test)]
mod tests {
    use super::super::{HostProcess, ProcessIdentity, ProcessRole};
    use super::*;
    use crate::foundation::coordination::VmInstanceId;
    use crate::foundation::ids::{digest, ExecutionId, SandboxBootGeneration};

    #[test]
    fn nothing_is_started_or_looked_up_without_a_process_handle() {
        let role = ProcessRole::VmHost {
            execution: ExecutionId::new("exe-unsupported").unwrap(),
            vm: VmInstanceId::new(digest("yougori/test/vm/v1", &[b"vm"])),
            boot: SandboxBootGeneration::FIRST,
        };
        let spawned = HostProcess::spawn(&mut Command::new("unused"), role);
        assert!(matches!(spawned, Err(ProcessError::Unsupported { .. })));
        assert!(matches!(
            ProcessIdentity::holder_of(1),
            Err(ProcessError::Unsupported { .. })
        ));
    }
}
