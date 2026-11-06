//! Bounded engine management carried inside an owner-pinned SSH channel.
//! These DTOs are remote reports, never this computer's host observations.
use serde::{Deserialize, Serialize};

use crate::foundation::evidence::{ConfigurationFingerprint, HypervisorKind};
use crate::foundation::ids::{Digest, ExecutionId, SandboxBootGeneration};
use crate::foundation::process::ProcessIdentity;
use crate::sandbox::backend::BackendIdentity;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteVmBinding {
    pub run: Digest,
    pub execution: ExecutionId,
    pub boot: SandboxBootGeneration,
}

impl RemoteVmBinding {
    pub fn workload_identity(&self) -> Digest {
        crate::foundation::ids::DigestBuilder::new("yougori/remote/vm-workload/v1")
            .digest(&self.run)
            .str(self.execution.as_str())
            .bytes(&self.boot.get().to_be_bytes())
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteVmObservation {
    pub binding: RemoteVmBinding,
    pub engine_sha256: Digest,
    pub process: ProcessIdentity,
    pub backend: BackendIdentity,
    pub accelerator: HypervisorKind,
    pub configuration: ConfigurationFingerprint,
    pub guest_image: Digest,
    pub launch_record: Digest,
}

/// A command is started once, then polled without blocking the lease-control
/// owner. A lost start/result reply is uncertain; callers never replay commands.
#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum RemoteManagementRequest {
    Launch {
        run: Digest,
        memory_mib: u64,
        lifetime_seconds: u64,
    },
    Probe {
        binding: RemoteVmBinding,
    },
    Start {
        binding: RemoteVmBinding,
        input_hex: String,
        output_bytes: usize,
        deadline_seconds: u64,
    },
    Outcome {
        binding: RemoteVmBinding,
        command: u32,
    },
    Cancel {
        binding: RemoteVmBinding,
        command: u32,
    },
    Stop {
        binding: RemoteVmBinding,
    },
    Reconcile {
        run: Digest,
    },
}

impl std::fmt::Debug for RemoteManagementRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Workload input can contain secrets. Never derive its Debug output.
        f.write_str("RemoteManagementRequest([redacted])")
    }
}

impl RemoteManagementRequest {
    pub fn run(&self) -> Digest {
        match self {
            Self::Launch { run, .. } | Self::Reconcile { run } => *run,
            Self::Probe { binding }
            | Self::Start { binding, .. }
            | Self::Outcome { binding, .. }
            | Self::Cancel { binding, .. }
            | Self::Stop { binding } => binding.run,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn binding() -> RemoteVmBinding {
        RemoteVmBinding {
            run: crate::foundation::ids::digest("remote-management-test", &[b"one"]),
            execution: ExecutionId::new("exe-management-test").unwrap(),
            boot: SandboxBootGeneration::new(1),
        }
    }

    #[test]
    fn a_workload_binding_changes_with_each_execution_dimension() {
        let original = binding();
        let identity = original.workload_identity();
        let mut changed = original.clone();
        changed.run = crate::foundation::ids::digest("remote-management-test", &[b"two"]);
        assert_ne!(changed.workload_identity(), identity);
        changed = original.clone();
        changed.execution = ExecutionId::new("exe-other").unwrap();
        assert_ne!(changed.workload_identity(), identity);
        changed = original.clone();
        changed.boot = SandboxBootGeneration::new(2);
        assert_ne!(changed.workload_identity(), identity);
    }

    #[test]
    fn the_wire_refuses_extra_authority_and_debug_redacts_workload_input() {
        let mut value = json!({"op":"start","binding":binding(),"input_hex":"534543524554",
            "output_bytes":4096,"deadline_seconds":10});
        let parsed: RemoteManagementRequest = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(parsed.run(), binding().run);
        assert!(!format!("{parsed:?}").contains("534543524554"));
        value["routes"] = json!(["unexpected-authority"]);
        assert!(serde_json::from_value::<RemoteManagementRequest>(value.clone()).is_err());
        value.as_object_mut().unwrap().remove("routes");
        value["binding"]["replacement"] = json!(true);
        assert!(serde_json::from_value::<RemoteManagementRequest>(value).is_err());
        assert!(serde_json::from_value::<RemoteManagementRequest>(
            json!({"op":"shell","binding":binding()})
        )
        .is_err());
    }
}
