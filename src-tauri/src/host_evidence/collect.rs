//! The separate real-hardware execution (GPU-W00): a fixed plan of bounded, read-only
//! host queries.
//!
//! Each program is spawned directly, never through a shell, with no window, no input and
//! no error stream; its output is read up to a bound and it must finish within a
//! deadline, or it is killed and reaped. Nothing here changes host state (S7, S13):
//! the queries read the registry, kernel files and `nvidia-smi`'s report. [`plan`]
//! describes exactly what [`collect`] would run, without running it.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use serde::Serialize;
use tokio::io::AsyncReadExt;

use super::inventory::{
    machine_digest, parse_gpus, parse_os_release, parse_registry_value, CudaRuntimeFacts,
    GpuInventory, HostInventory, InventoryProblem, MachineIdentity, OsFacts,
};
use crate::foundation::ids::MonotonicTime;

/// The fields of the GPU query, in the order [`parse_gpus`] reads them.
pub(super) const GPU_FIELDS: &str = "uuid,driver_version,compute_cap,driver_model.current,mig.mode.current,memory.total,memory.used,memory.free";
/// How long one query may run.
pub const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
/// The most output one query may write.
pub const QUERY_MAX_OUTPUT: usize = 16 * 1024;
/// How long a killed query is waited for, so it is reaped rather than left behind.
const REAP_WAIT: Duration = Duration::from_secs(2);
/// Windows `CREATE_NO_WINDOW`: a query never flashes a console.
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// One of the host queries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Query {
    MachineIdentity,
    OsBuild,
    Gpus,
}

/// What a query would run, for a dry run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryDescription {
    pub query: Query,
    pub purpose: &'static str,
    /// The program or file read; `None` where the query does not exist on this platform.
    pub reads: Option<String>,
    pub arguments: Vec<String>,
    pub timeout_ms: u64,
    pub max_output_bytes: usize,
}

/// The raw answer of one query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QueryOutcome {
    Output(String),
    Problem(InventoryProblem),
}

enum Source {
    Program { program: PathBuf, args: Vec<String> },
    File { path: PathBuf },
    NotOnThisPlatform,
}

/// How the answer is read from the output.
enum Extract {
    /// The `REG_SZ` value of this name.
    RegistryValue(&'static str),
    Text,
}

struct Spec {
    query: Query,
    purpose: &'static str,
    source: Source,
    extract: Extract,
}

#[cfg(windows)]
fn system_program(name: &str) -> PathBuf {
    std::env::var_os("SystemRoot")
        .map(|root| PathBuf::from(root).join("System32").join(name))
        .filter(|path| path.is_file())
        .unwrap_or_else(|| PathBuf::from(name))
}

#[cfg(windows)]
fn nvidia_smi() -> PathBuf {
    std::env::var_os("ProgramFiles")
        .map(|root| PathBuf::from(root).join("NVIDIA Corporation/NVSMI/nvidia-smi.exe"))
        .filter(|path| path.is_file())
        .unwrap_or_else(|| system_program("nvidia-smi.exe"))
}

fn gpu_source() -> Source {
    #[cfg(any(windows, target_os = "linux"))]
    {
        #[cfg(windows)]
        let program = nvidia_smi();
        #[cfg(target_os = "linux")]
        let program = PathBuf::from("nvidia-smi");
        Source::Program {
            program,
            args: vec![
                format!("--query-gpu={GPU_FIELDS}"),
                "--format=csv,noheader,nounits".to_owned(),
            ],
        }
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        Source::NotOnThisPlatform
    }
}

fn specs() -> [Spec; 3] {
    #[cfg(windows)]
    let (machine, machine_extract, build, build_extract) = {
        let reg = system_program("reg.exe");
        (
            Source::Program {
                program: reg.clone(),
                args: vec![
                    "query".into(),
                    r"HKLM\SOFTWARE\Microsoft\Cryptography".into(),
                    "/v".into(),
                    "MachineGuid".into(),
                ],
            },
            Extract::RegistryValue("MachineGuid"),
            Source::Program {
                program: reg,
                args: vec![
                    "query".into(),
                    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion".into(),
                    "/v".into(),
                    "CurrentBuildNumber".into(),
                ],
            },
            Extract::RegistryValue("CurrentBuildNumber"),
        )
    };
    #[cfg(target_os = "linux")]
    let (machine, machine_extract, build, build_extract) = (
        Source::File {
            path: PathBuf::from("/etc/machine-id"),
        },
        Extract::Text,
        Source::File {
            path: PathBuf::from("/proc/sys/kernel/osrelease"),
        },
        Extract::Text,
    );
    #[cfg(target_os = "macos")]
    let (machine, machine_extract, build, build_extract) = (
        Source::NotOnThisPlatform,
        Extract::Text,
        Source::Program {
            program: PathBuf::from("/usr/bin/sw_vers"),
            args: vec!["-productVersion".into()],
        },
        Extract::Text,
    );
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    let (machine, machine_extract, build, build_extract) = (
        Source::NotOnThisPlatform,
        Extract::Text,
        Source::NotOnThisPlatform,
        Extract::Text,
    );
    [
        Spec {
            query: Query::MachineIdentity,
            purpose: "Names this computer by a digest of its machine identity, as host admission does.",
            source: machine,
            extract: machine_extract,
        },
        Spec {
            query: Query::OsBuild,
            purpose: "Reads the operating system build that evidence depends on.",
            source: build,
            extract: build_extract,
        },
        Spec {
            query: Query::Gpus,
            purpose: "Lists NVIDIA GPUs with driver, compute capability, driver model, MIG mode and memory.",
            source: gpu_source(),
            extract: Extract::Text,
        },
    ]
}

impl Spec {
    fn describe(&self) -> QueryDescription {
        let (reads, arguments) = match &self.source {
            Source::Program { program, args } => {
                (Some(program.display().to_string()), args.clone())
            }
            Source::File { path } => (Some(path.display().to_string()), Vec::new()),
            Source::NotOnThisPlatform => (None, Vec::new()),
        };
        QueryDescription {
            query: self.query,
            purpose: self.purpose,
            reads,
            arguments,
            timeout_ms: u64::try_from(QUERY_TIMEOUT.as_millis()).unwrap_or(u64::MAX),
            max_output_bytes: QUERY_MAX_OUTPUT,
        }
    }

    async fn run(&self) -> QueryOutcome {
        let raw = match &self.source {
            Source::Program { program, args } => run_program(program, args).await,
            Source::File { path } => read_file(path).await,
            Source::NotOnThisPlatform => {
                return QueryOutcome::Problem(InventoryProblem::NotOnThisPlatform)
            }
        };
        match raw {
            QueryOutcome::Output(text) => match self.extract {
                Extract::Text => QueryOutcome::Output(text),
                Extract::RegistryValue(name) => match parse_registry_value(&text, name) {
                    Some(value) => QueryOutcome::Output(value.to_owned()),
                    None => QueryOutcome::Problem(InventoryProblem::QueryFailed),
                },
            },
            problem => problem,
        }
    }
}

/// What [`collect`] would run on this platform, without running anything.
pub fn plan() -> Vec<QueryDescription> {
    specs().iter().map(Spec::describe).collect()
}

fn text(bytes: Vec<u8>) -> QueryOutcome {
    if bytes.len() > QUERY_MAX_OUTPUT {
        return QueryOutcome::Problem(InventoryProblem::OutputTooLong);
    }
    match String::from_utf8(bytes) {
        Ok(text) => QueryOutcome::Output(text),
        Err(_) => QueryOutcome::Problem(InventoryProblem::NotUtf8),
    }
}

async fn run_program(program: &PathBuf, args: &[String]) -> QueryOutcome {
    let mut command = tokio::process::Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    #[cfg(windows)]
    command.creation_flags(CREATE_NO_WINDOW);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return QueryOutcome::Problem(InventoryProblem::ToolMissing)
        }
        Err(_) => return QueryOutcome::Problem(InventoryProblem::QueryFailed),
    };
    let Some(output) = child.stdout.take() else {
        let _ = child.start_kill();
        let _ = tokio::time::timeout(REAP_WAIT, child.wait()).await;
        return QueryOutcome::Problem(InventoryProblem::QueryFailed);
    };
    let bound = u64::try_from(QUERY_MAX_OUTPUT)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let work = async {
        let mut bytes = Vec::new();
        if output.take(bound).read_to_end(&mut bytes).await.is_err() {
            return QueryOutcome::Problem(InventoryProblem::QueryFailed);
        }
        if bytes.len() > QUERY_MAX_OUTPUT {
            return QueryOutcome::Problem(InventoryProblem::OutputTooLong);
        }
        match child.wait().await {
            Ok(status) if status.success() => text(bytes),
            _ => QueryOutcome::Problem(InventoryProblem::QueryFailed),
        }
    };
    let outcome = match tokio::time::timeout(QUERY_TIMEOUT, work).await {
        Ok(outcome) => outcome,
        Err(_) => QueryOutcome::Problem(InventoryProblem::TimedOut),
    };
    if matches!(outcome, QueryOutcome::Problem(_)) {
        let _ = child.start_kill();
        let _ = tokio::time::timeout(REAP_WAIT, child.wait()).await;
    }
    outcome
}

async fn read_file(path: &PathBuf) -> QueryOutcome {
    let bound = u64::try_from(QUERY_MAX_OUTPUT)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let work = async {
        let file = match tokio::fs::File::open(path).await {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return QueryOutcome::Problem(InventoryProblem::ToolMissing)
            }
            Err(_) => return QueryOutcome::Problem(InventoryProblem::QueryFailed),
        };
        let mut bytes = Vec::new();
        match file.take(bound).read_to_end(&mut bytes).await {
            Ok(_) => text(bytes),
            Err(_) => QueryOutcome::Problem(InventoryProblem::QueryFailed),
        }
    };
    tokio::time::timeout(QUERY_TIMEOUT, work)
        .await
        .unwrap_or(QueryOutcome::Problem(InventoryProblem::TimedOut))
}

/// Builds an inventory from the three answers; pure, so recorded answers are checked
/// exactly as live ones are.
pub(super) fn assemble(
    machine: QueryOutcome,
    build: QueryOutcome,
    gpus: QueryOutcome,
    cuda_runtime: Option<CudaRuntimeFacts>,
    started_at: MonotonicTime,
) -> HostInventory {
    let machine = MachineIdentity::from_result(match machine {
        QueryOutcome::Output(text) => machine_digest(&text),
        QueryOutcome::Problem(InventoryProblem::NotOnThisPlatform) => {
            Err(InventoryProblem::NotOnThisPlatform)
        }
        QueryOutcome::Problem(_) => Err(InventoryProblem::MachineIdentity),
    });
    let build = match build {
        QueryOutcome::Output(text) => parse_os_release(&text).ok(),
        QueryOutcome::Problem(_) => None,
    };
    let gpus = match gpus {
        QueryOutcome::Output(csv) => match parse_gpus(&csv) {
            Ok(devices) => GpuInventory::Devices { devices },
            Err(problem) => GpuInventory::Unavailable { problem },
        },
        QueryOutcome::Problem(problem) => GpuInventory::Unavailable { problem },
    };
    HostInventory {
        machine,
        os: OsFacts::this_platform(build),
        gpus,
        cuda_runtime,
        started_at,
    }
}

/// Runs the [`plan`] once, its queries in parallel, and returns what they found.
/// `started_at` is the evidence service's clock reading taken before the queries start;
/// `cuda_runtime` is the engine's own report of its CUDA runtime, when it has one.
pub async fn collect(
    started_at: MonotonicTime,
    cuda_runtime: Option<CudaRuntimeFacts>,
) -> HostInventory {
    let [machine, build, gpus] = specs();
    let (machine, build, gpus) = tokio::join!(machine.run(), build.run(), gpus.run());
    assemble(machine, build, gpus, cuda_runtime, started_at)
}
