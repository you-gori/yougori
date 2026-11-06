//! Test doubles (tests only): a runpodctl port that plays one RunPod account, answering in
//! the JSON shapes `parse` documents and recording every call with the key it was given,
//! and a key source. Nothing here starts a process or touches a network.

use std::collections::VecDeque;
use std::time::Duration;

use serde_json::{json, Value};

use super::command::{CommandKind, RunPodSettings, RunpodctlInvocation, RunpodctlLimits};
use super::process::{RunpodctlOutput, RunpodctlPort};
use super::secret::{ApiKeySource, KeyUnavailable};
use super::values::{CloudType, ContainerImage, GpuTypeId, PodSpec, RunPodCatalog};
use crate::foundation::evidence::ProviderKind;
use crate::sandbox_contract::provider::SecretValue;
use crate::sandbox_contract::remote::{
    AttemptId, OfferingKind, OfferingName, ProvisionRequest, RegionName, RemoteOffering,
};
use crate::sandbox_contract::remote_ssh::{SshOutput, SshTermination};

/// The fixture account key.
pub const KEY: &str = "rpa_FIXTURE0KEY1never2in3argv4or5errors6789";
/// The data center the fixture offering asks for.
pub const REGION: &str = "EU-RO-1";
/// The fixture offering.
pub const OFFERING: &str = "pod-a40";
/// Its GPU type.
pub const GPU: &str = "NVIDIA A40";

pub fn region(name: &str) -> RegionName {
    RegionName::new(name).unwrap()
}

pub fn offering_name(name: &str) -> OfferingName {
    OfferingName::new(name).unwrap()
}

pub fn spec(gpu: &str, count: u32) -> PodSpec {
    PodSpec {
        gpu: GpuTypeId::new(gpu).unwrap(),
        gpu_count: count,
        cloud: CloudType::Secure,
        image: ContainerImage::new("runpod/pytorch:2.4.0-py3.11-cuda12.4.1").unwrap(),
        container_disk_gb: 40,
    }
}

/// `pod-a40` (1 × A40) and `pod-h100` (1 × H100).
pub fn catalog() -> RunPodCatalog {
    RunPodCatalog::new([
        (offering_name(OFFERING), spec(GPU, 1)),
        (offering_name("pod-h100"), spec("NVIDIA H100 80GB HBM3", 1)),
    ])
    .unwrap()
}

/// Standard limits with a 60 s settle window.
pub fn settings() -> RunPodSettings {
    RunPodSettings {
        listing_settle: Duration::from_secs(60),
        ..RunPodSettings::STANDARD
    }
}

/// The V12 offering the fixture catalog launches: a RunPod provider container.
pub fn runpod_offering() -> RemoteOffering {
    let mut offering = crate::sandbox_contract::remote::fakes::container_offering();
    offering.region = region(REGION);
    offering.offering = offering_name(OFFERING);
    offering
}

/// A provisioning request for `attempt` on the fixture offering.
pub fn request(attempt: AttemptId) -> ProvisionRequest {
    ProvisionRequest {
        attempt,
        provider: ProviderKind::RunPod,
        region: region(REGION),
        offering: offering_name(OFFERING),
        kind: OfferingKind::ProviderContainer,
        account: crate::sandbox_contract::remote::fakes::account(),
    }
}

/// A key source holding `key`, or none.
#[derive(Debug, Clone)]
pub struct FixedKey(pub Option<&'static str>);

impl FixedKey {
    pub fn fixture() -> Self {
        Self(Some(KEY))
    }
}

impl ApiKeySource for FixedKey {
    fn api_key(&mut self) -> Result<SecretValue, KeyUnavailable> {
        self.0
            .map(|key| SecretValue::new(key.as_bytes().to_vec()))
            .ok_or(KeyUnavailable::NotConfigured)
    }
}

/// One pod of the fake account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FakePod {
    pub id: String,
    pub name: String,
    pub status: String,
    pub gpu: String,
    pub count: u32,
    pub region: String,
    pub ssh: Option<(String, u16)>,
}

/// One call the fake received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Call {
    pub kind: CommandKind,
    pub arguments: Vec<String>,
    pub limits: RunpodctlLimits,
    pub key: Vec<u8>,
}

/// A scripted answer for the next call of `kind`. With `apply`, the account changes as
/// the call would change it before the scripted output is returned.
#[derive(Clone, Debug)]
pub struct Script {
    pub kind: CommandKind,
    pub apply: bool,
    pub output: SshOutput,
}

pub fn exited(code: i32, stdout: &str, stderr: &str) -> SshOutput {
    SshOutput {
        termination: SshTermination::Exited { code },
        stdout: stdout.as_bytes().to_vec(),
        stderr: stderr.as_bytes().to_vec(),
    }
}

pub fn ended(termination: SshTermination) -> SshOutput {
    SshOutput {
        termination,
        stdout: Vec::new(),
        stderr: Vec::new(),
    }
}

/// A runpodctl port playing one RunPod account.
#[derive(Debug, Default)]
pub struct FakeRunpodctl {
    pub pods: Vec<FakePod>,
    /// The account's SSH key lines.
    pub keys: Vec<String>,
    /// Delivers this data center instead of the one asked for.
    pub deliver_region: Option<String>,
    /// Delivers this GPU type and count instead of the ones asked for.
    pub deliver_gpu: Option<(String, u32)>,
    pub scripts: VecDeque<Script>,
    pub calls: Vec<Call>,
    next: u32,
}

fn value_after(arguments: &[String], flag: &str) -> String {
    arguments
        .iter()
        .position(|word| word == flag)
        .and_then(|index| arguments.get(index + 1))
        .cloned()
        .unwrap_or_default()
}

fn json_output(value: &Value) -> SshOutput {
    exited(0, &value.to_string(), "")
}

fn not_found(id: &str) -> SshOutput {
    exited(
        1,
        "",
        &json!({ "error": format!("pod {id} not found") }).to_string(),
    )
}

impl FakeRunpodctl {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a running pod named `name` on 1 × A40 in [`REGION`]; returns its id.
    pub fn add_pod(&mut self, name: &str, status: &str) -> String {
        self.next += 1;
        let id = format!("fakepod{:04}", self.next);
        self.pods.push(FakePod {
            id: id.clone(),
            name: name.to_owned(),
            status: status.to_owned(),
            gpu: GPU.to_owned(),
            count: 1,
            region: REGION.to_owned(),
            ssh: Some(("194.68.245.20".to_owned(), 22_101)),
        });
        id
    }

    pub fn script(&mut self, kind: CommandKind, apply: bool, output: SshOutput) {
        self.scripts.push_back(Script {
            kind,
            apply,
            output,
        });
    }

    pub fn pod(&self, id: &str) -> Option<&FakePod> {
        self.pods.iter().find(|pod| pod.id == id)
    }

    pub fn count(&self, kind: CommandKind) -> usize {
        self.calls.iter().filter(|call| call.kind == kind).count()
    }

    pub fn kinds(&self) -> Vec<CommandKind> {
        self.calls.iter().map(|call| call.kind).collect()
    }

    fn row(pod: &FakePod) -> Value {
        json!({
            "id": pod.id,
            "name": pod.name,
            "desiredStatus": pod.status,
            "costPerHr": 0.44,
            "imageName": "runpod/pytorch:2.4.0-py3.11-cuda12.4.1",
        })
    }

    fn detail(pod: &FakePod) -> Value {
        let mut value = Self::row(pod);
        value["gpuTypeId"] = json!(pod.gpu);
        value["gpuCount"] = json!(pod.count);
        value["machine"] = json!({ "dataCenterId": pod.region, "location": "RO" });
        if let Some((ip, port)) = &pod.ssh {
            value["ssh"] = json!({ "ip": ip, "port": port, "ssh_command": "ssh root@host" });
        }
        value
    }

    /// What the call does to the account and what runpodctl prints for it.
    fn act(&mut self, kind: CommandKind, arguments: &[String]) -> SshOutput {
        match kind {
            CommandKind::CreatePod => {
                self.next += 1;
                let id = format!("fakepod{:04}", self.next);
                let (gpu, count) = self.deliver_gpu.clone().unwrap_or_else(|| {
                    (
                        value_after(arguments, "--gpu-id"),
                        value_after(arguments, "--gpu-count").parse().unwrap_or(0),
                    )
                });
                let pod = FakePod {
                    id: id.clone(),
                    name: value_after(arguments, "--name"),
                    status: "RUNNING".to_owned(),
                    gpu,
                    count,
                    region: self
                        .deliver_region
                        .clone()
                        .unwrap_or_else(|| value_after(arguments, "--data-center-ids")),
                    ssh: Some(("194.68.245.20".to_owned(), 22_101)),
                };
                let answer = json!({ "id": id, "name": pod.name, "desiredStatus": "CREATED" });
                self.pods.push(pod);
                json_output(&answer)
            }
            CommandKind::ListPods => {
                json_output(&Value::Array(self.pods.iter().map(Self::row).collect()))
            }
            CommandKind::GetPod => {
                let id = arguments.get(2).cloned().unwrap_or_default();
                match self.pod(&id) {
                    Some(pod) => json_output(&Self::detail(pod)),
                    None => not_found(&id),
                }
            }
            CommandKind::DeletePod => {
                let id = arguments.get(2).cloned().unwrap_or_default();
                match self.pods.iter_mut().find(|pod| pod.id == id) {
                    Some(pod) if pod.status != "TERMINATED" => {
                        pod.status = "TERMINATED".to_owned();
                        json_output(&json!({ "id": id, "deleted": true }))
                    }
                    _ => not_found(&id),
                }
            }
            CommandKind::ListSshKeys => json_output(&json!({
                "keys": self
                    .keys
                    .iter()
                    .map(|key| json!({ "key": key, "name": "fixture" }))
                    .collect::<Vec<_>>()
            })),
            CommandKind::AddSshKey => {
                self.keys.push(value_after(arguments, "--key"));
                json_output(&json!({ "added": true }))
            }
        }
    }
}

impl RunpodctlPort for FakeRunpodctl {
    fn run(&mut self, invocation: &RunpodctlInvocation, key: &SecretValue) -> RunpodctlOutput {
        let kind = invocation.command().kind();
        let arguments = invocation.arguments();
        self.calls.push(Call {
            kind,
            arguments: arguments.clone(),
            limits: invocation.limits(),
            key: key.expose_to_transport().to_vec(),
        });
        match self.scripts.iter().position(|script| script.kind == kind) {
            Some(index) => {
                let script = self.scripts.remove(index).unwrap();
                if script.apply {
                    let _ = self.act(kind, &arguments);
                }
                script.output
            }
            None => self.act(kind, &arguments),
        }
    }
}
