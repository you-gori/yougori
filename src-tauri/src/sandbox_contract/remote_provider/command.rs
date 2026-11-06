//! The exact runpodctl argv for each operation, built from typed values only, and the
//! time and output limits each call runs under (VM-W39; VM part §6.2: bounded calls).
//!
//! The commands are the ones neocloud's reviewed RunPod code already runs
//! (`neocloud/runpod.rs`, `neocloud.rs`): `pod create`, `pod list --all`, `pod get`,
//! `pod delete`, `ssh list-keys` and `ssh add-key`, each with `--output json` so a format
//! set in a person's own runpodctl configuration cannot change what is read. No value
//! starts with `-`, the account key is never an argument, and no environment value is
//! passed as an argument (runpodctl's `--env` is never used).

use std::fmt;
use std::time::Duration;

use serde::Serialize;

use super::values::{PodId, PodName, PodSpec};
use crate::sandbox_contract::remote::RegionName;
use crate::sandbox_contract::remote_ssh::{
    ManagementPublicKey, SshLimit, SshLimitsRefusal, MAX_DEADLINE, MAX_OUTPUT_BYTES,
};

/// The program the reviewed install provides (`install::installed_program("runpod")`).
pub const RUNPODCTL_PROGRAM: &str = "runpodctl";

/// The port the pod exposes for management SSH.
pub const SSH_PORT_SPEC: &str = "22/tcp";

/// One runpodctl operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandKind {
    CreatePod,
    ListPods,
    GetPod,
    DeletePod,
    ListSshKeys,
    AddSshKey,
}

/// One runpodctl call, with every value typed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunPodCommand {
    /// `pod create` for one GPU pod named after the attempt, in one data center.
    CreatePod {
        name: PodName,
        spec: PodSpec,
        region: RegionName,
    },
    /// `pod list --all`: every pod of the account, stopped and terminated ones included.
    ListPods,
    /// `pod get <id>`.
    GetPod { pod: PodId },
    /// `pod delete <id>`.
    DeletePod { pod: PodId },
    /// `ssh list-keys`: the account's SSH public keys, which RunPod installs in its pods.
    ListSshKeys,
    /// `ssh add-key --key <authorized_keys line>`: a public key, never a secret.
    AddSshKey { key: ManagementPublicKey },
}

impl RunPodCommand {
    /// Which operation this is.
    pub fn kind(&self) -> CommandKind {
        match self {
            Self::CreatePod { .. } => CommandKind::CreatePod,
            Self::ListPods => CommandKind::ListPods,
            Self::GetPod { .. } => CommandKind::GetPod,
            Self::DeletePod { .. } => CommandKind::DeletePod,
            Self::ListSshKeys => CommandKind::ListSshKeys,
            Self::AddSshKey { .. } => CommandKind::AddSshKey,
        }
    }

    /// The exact arguments after the program, ending in `--output json`.
    pub fn arguments(&self) -> Vec<String> {
        let mut words: Vec<String> = match self {
            Self::CreatePod { name, spec, region } => vec![
                "pod".into(),
                "create".into(),
                "--name".into(),
                name.as_str().into(),
                "--image".into(),
                spec.image.as_str().into(),
                "--compute-type".into(),
                "GPU".into(),
                "--gpu-id".into(),
                spec.gpu.as_str().into(),
                "--gpu-count".into(),
                spec.gpu_count.to_string(),
                "--cloud-type".into(),
                spec.cloud.flag().into(),
                "--data-center-ids".into(),
                region.as_str().into(),
                "--container-disk-in-gb".into(),
                spec.container_disk_gb.to_string(),
                "--ports".into(),
                SSH_PORT_SPEC.into(),
            ],
            Self::ListPods => vec!["pod".into(), "list".into(), "--all".into()],
            Self::GetPod { pod } => vec!["pod".into(), "get".into(), pod.as_str().into()],
            Self::DeletePod { pod } => vec!["pod".into(), "delete".into(), pod.as_str().into()],
            Self::ListSshKeys => vec!["ssh".into(), "list-keys".into()],
            Self::AddSshKey { key } => vec![
                "ssh".into(),
                "add-key".into(),
                "--key".into(),
                key.authorized_keys_line(),
            ],
        };
        words.extend(["--output".into(), "json".into()]);
        words
    }
}

/// The deadline and per-stream output bounds of one call. The port stops runpodctl at
/// the deadline and reads at most one byte more than each bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct RunpodctlLimits {
    deadline: Duration,
    max_stdout_bytes: u64,
    max_stderr_bytes: u64,
}

impl RunpodctlLimits {
    /// Lookups (`pod list`, `pod get`, `ssh list-keys`): 40 s, as neocloud allows.
    pub const QUERY: Self = Self {
        deadline: Duration::from_secs(40),
        max_stdout_bytes: 4 * 1024 * 1024,
        max_stderr_bytes: 256 * 1024,
    };
    /// `pod create`: 240 s, as neocloud allows.
    pub const CREATE: Self = Self {
        deadline: Duration::from_secs(240),
        max_stdout_bytes: 1024 * 1024,
        max_stderr_bytes: 256 * 1024,
    };
    /// `pod delete` and `ssh add-key`: 90 s.
    pub const CHANGE: Self = Self {
        deadline: Duration::from_secs(90),
        max_stdout_bytes: 1024 * 1024,
        max_stderr_bytes: 256 * 1024,
    };

    /// Checks the deadline against 1 s to `remote_ssh`'s [`MAX_DEADLINE`] and each bound
    /// against 1 byte to [`MAX_OUTPUT_BYTES`], with the SSH limits' refusal type.
    pub fn new(
        deadline: Duration,
        max_stdout_bytes: u64,
        max_stderr_bytes: u64,
    ) -> Result<Self, SshLimitsRefusal> {
        if deadline < Duration::from_secs(1) || deadline > MAX_DEADLINE {
            return Err(SshLimitsRefusal::OutOfRange {
                limit: SshLimit::Deadline,
                min: 1,
                max: MAX_DEADLINE.as_secs(),
            });
        }
        for (limit, value) in [
            (SshLimit::MaxStdout, max_stdout_bytes),
            (SshLimit::MaxStderr, max_stderr_bytes),
        ] {
            if !(1..=MAX_OUTPUT_BYTES).contains(&value) {
                return Err(SshLimitsRefusal::OutOfRange {
                    limit,
                    min: 1,
                    max: MAX_OUTPUT_BYTES,
                });
            }
        }
        Ok(Self {
            deadline,
            max_stdout_bytes,
            max_stderr_bytes,
        })
    }

    /// When the port stops runpodctl, counted from its start.
    pub fn deadline(&self) -> Duration {
        self.deadline
    }

    /// The most stdout accepted.
    pub fn max_stdout_bytes(&self) -> u64 {
        self.max_stdout_bytes
    }

    /// The most stderr accepted.
    pub fn max_stderr_bytes(&self) -> u64 {
        self.max_stderr_bytes
    }
}

/// One call as the port runs it: the command and its limits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunpodctlInvocation {
    command: RunPodCommand,
    limits: RunpodctlLimits,
}

impl RunpodctlInvocation {
    /// Pairs `command` with the limits it runs under.
    pub fn new(command: RunPodCommand, limits: RunpodctlLimits) -> Self {
        Self { command, limits }
    }

    pub fn command(&self) -> &RunPodCommand {
        &self.command
    }

    pub fn limits(&self) -> RunpodctlLimits {
        self.limits
    }

    /// The exact arguments after the program.
    pub fn arguments(&self) -> Vec<String> {
        self.command.arguments()
    }
}

/// How the transport runs: the limits per kind of call and how long after a pod could
/// have been created a listing without it is believed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct RunPodSettings {
    pub create: RunpodctlLimits,
    pub query: RunpodctlLimits,
    pub change: RunpodctlLimits,
    /// RunPod may list a pod it has just made only later (neocloud looks for one over
    /// about two minutes), so a pod missing from a listing is taken as absent only this
    /// long after a create for it was last sent, or, for an attempt this transport never
    /// sent, after the transport was made.
    pub listing_settle: Duration,
}

impl RunPodSettings {
    /// The limits above and a two-minute settle window, neocloud's.
    pub const STANDARD: Self = Self {
        create: RunpodctlLimits::CREATE,
        query: RunpodctlLimits::QUERY,
        change: RunpodctlLimits::CHANGE,
        listing_settle: Duration::from_secs(120),
    };

    /// The limits a call of `kind` runs under.
    pub fn limits(&self, kind: CommandKind) -> RunpodctlLimits {
        match kind {
            CommandKind::CreatePod => self.create,
            CommandKind::ListPods | CommandKind::GetPod | CommandKind::ListSshKeys => self.query,
            CommandKind::DeletePod | CommandKind::AddSshKey => self.change,
        }
    }
}

impl fmt::Display for CommandKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CreatePod => "runpodctl pod create",
            Self::ListPods => "runpodctl pod list",
            Self::GetPod => "runpodctl pod get",
            Self::DeletePod => "runpodctl pod delete",
            Self::ListSshKeys => "runpodctl ssh list-keys",
            Self::AddSshKey => "runpodctl ssh add-key",
        })
    }
}
