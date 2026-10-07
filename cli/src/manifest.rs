//! One strict project format shared by the public CLI and Desktop engine.
use crate::workload::{self, Options, Volume};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
pub mod compose;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Project {
    pub project: String,
    pub environments: BTreeMap<String, Environment>,
    #[serde(default)]
    pub connections: Vec<Connection>,
    #[serde(default)]
    pub publish: BTreeMap<String, Publication>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Environment {
    #[serde(default = "container", rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub image: String,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default = "cpu")]
    pub cpu: f64,
    #[serde(default = "memory")]
    pub memory: Value,
    #[serde(default)]
    pub gpu: bool,
    #[serde(default)]
    pub command: Option<Command>,
    #[serde(default)]
    pub entrypoint: Option<Command>,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    /// Environment variable -> OS-vault reference. Values never belong in project YAML.
    #[serde(default)]
    pub secrets: BTreeMap<String, String>,
    #[serde(default)]
    pub files: Vec<FileSource>,
    #[serde(default)]
    pub automatic_start: bool,
    #[serde(default)]
    pub health: Option<HealthCheck>,
    #[serde(default)]
    pub setup: Option<Setup>,
    #[serde(default)]
    pub working_dir: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub volumes: Vec<Mount>,
    #[serde(default = "storage")]
    pub storage: Value,
    #[serde(default)]
    pub storage_drive: Option<String>,
    #[serde(default)]
    pub ports: Vec<Port>,
    #[serde(default = "internet_enabled")]
    pub internet: bool,
    #[serde(default)]
    pub pc_access: Vec<PcAccess>,
    #[serde(default)]
    pub permissions: Permissions,
    #[serde(default)]
    pub depends_on: Vec<String>,
    #[serde(default)]
    pub restart: String,
    #[serde(default)]
    pub cloud: Option<Value>,
    #[serde(default)]
    pub shared: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FileSource { pub source: String, pub target: String }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Setup {
    #[serde(default)] pub python_minimum: Option<String>,
    #[serde(default)] pub pip: Vec<String>,
    #[serde(default)] pub verify_command: Option<String>,
}
impl Setup{
    pub fn validate(&self)->Result<(),String>{
        if self.python_minimum.as_ref().is_some_and(|v|{let parts=v.split('.').collect::<Vec<_>>();parts.len()!=2||parts.iter().any(|p|p.parse::<u16>().is_err())}) || self.pip.len()>128 || self.pip.iter().any(|requirement|requirement.split_once("==").is_none_or(|(name,version)|name.is_empty()||version.is_empty()||name.len()>128||version.len()>128||!name.bytes().all(|b|b.is_ascii_alphanumeric()||b"_.-[]".contains(&b))||!version.bytes().all(|b|b.is_ascii_alphanumeric()||b"._+-".contains(&b)))) || self.verify_command.as_ref().is_some_and(|s|s.is_empty()||s.contains('\0')||s.len()>32768) || serde_json::to_string(&self.pip).map(|s|s.len()>16384).unwrap_or(true){return Err("Setup accepts python_minimum like 3.12, pinned pip packages name==version, and an optional verification command".into())}
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HealthCheck {
    pub port: u16,
    #[serde(default = "health_path")]
    pub path: String,
    #[serde(default = "health_method")]
    pub method: String,
    #[serde(default)]
    pub body: Option<Value>,
    #[serde(default = "health_status")]
    pub expected_status: u16,
    #[serde(default = "health_timeout")]
    pub timeout_seconds: u64,
    #[serde(default)]
    pub bearer_secret: Option<String>,
    #[serde(default = "health_wait")]
    pub wait_seconds: u64,
}
fn health_path() -> String { "/".into() }
fn health_method() -> String { "GET".into() }
fn health_status() -> u16 { 200 }
fn health_timeout() -> u64 { 10 }
fn health_wait()->u64{120}
impl HealthCheck {
    pub fn validate(&self) -> Result<(), String> {
        if self.port == 0 || self.port == 7443 || !self.path.starts_with('/') || self.path.starts_with("//") || self.path.len() > 4096 || self.path.chars().any(char::is_control) || self.path.contains(['#', '\\'])
            || !["GET", "HEAD", "POST"].contains(&self.method.as_str()) || !(100..=599).contains(&self.expected_status) || !(1..=60).contains(&self.timeout_seconds)
            || !(1..=600).contains(&self.wait_seconds) || self.body.as_ref().is_some_and(|v| v.to_string().len() > 65536) || self.bearer_secret.as_ref().is_some_and(|s| !workload::identifier(s)) {
            return Err("Health check requires a valid application port, local path, GET/HEAD/POST, expected status 100–599, timeout 1–60 seconds, and a vault reference for authentication".into())
        }
        if self.body.is_some() && self.method != "POST" { return Err("Only POST health checks accept a body".into()) }
        Ok(())
    }
}
fn internet_enabled() -> bool { true }
fn container() -> String {
    "container".into()
}
fn cpu() -> f64 {
    2.0
}
fn memory() -> Value {
    json!(2)
}
fn storage() -> Value {
    json!(20)
}
impl Default for Environment {
    fn default() -> Self {
        serde_json::from_value(json!({})).expect("valid defaults")
    }
}
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Permissions {
    #[serde(default)]
    pub pc: bool,
    #[serde(default)]
    pub edit: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum Command {
    Shell(String),
    Args(Vec<String>),
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Mount {
    pub source: String,
    pub target: String,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default)]
    pub bind: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PcAccess {
    pub path: String,
    #[serde(default = "yes")]
    pub read_only: bool,
    #[serde(default)]
    pub target: Option<String>,
}
fn yes() -> bool {
    true
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum Port {
    Number(u16),
    Mapping(String),
    Detailed { target: u16, published: Option<u16> },
}
impl Port {
    pub fn values(&self) -> Result<(u16, Option<u16>), String> {
        let pair = match self {
            Self::Number(p) => (*p, None),
            Self::Detailed { target, published } => (*target, *published),
            Self::Mapping(s) => {
                let s = s.strip_suffix("/tcp").unwrap_or(s);
                let parts = s.split(':').collect::<Vec<_>>();
                let n = |s: &str| {
                    s.parse::<u16>()
                        .map_err(|_| "Ports must be between 1 and 65535".to_string())
                };
                match parts.as_slice() {
                    [p] => (n(p)?, None),
                    [h, p] => (n(p)?, Some(n(h)?)),
                    ["127.0.0.1", h, p] => (n(p)?, Some(n(h)?)),
                    _ => return Err(
                        "Use TCP ports as guest or host:guest; published ports are loopback-only"
                            .into(),
                    ),
                }
            }
        };
        if pair.0 == 0 || pair.1 == Some(0) {
            return Err("Port zero is not valid".into());
        }
        Ok(pair)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum Connection {
    Arrow(String),
    Detailed {
        from: String,
        to: String,
        #[serde(default)]
        ports: Vec<u16>,
        #[serde(default)]
        permissions: Vec<String>,
    },
}
impl Connection {
    pub fn endpoints(&self) -> Result<(&str, &str), String> {
        match self {
            Self::Arrow(s) => s
                .split_once("->")
                .map(|(a, b)| (a.trim(), b.trim()))
                .ok_or("Connections use 'frontend -> database'".into()),
            Self::Detailed { from, to, .. } => Ok((from, to)),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum Publication {
    Hostname(String),
    Detailed {
        port: u16,
        #[serde(default)]
        hostname: Option<String>,
        #[serde(default)]
        token_env: Option<String>,
        #[serde(default)]
        domain: Option<String>,
    },
}
pub fn gib(value: &Value) -> Result<f64, String> {
    if let Some(n) = value.as_f64() {
        return if n.is_finite() && n > 0.0 {
            Ok(n)
        } else {
            Err("Resource values must be positive".into())
        };
    }
    let s = value
        .as_str()
        .ok_or("Use a number in GiB, or a size such as 512MB / 4GB")?
        .trim()
        .to_ascii_lowercase();
    for (suffix, factor) in [
        ("gib", 1.0),
        ("gb", 1.0),
        ("g", 1.0),
        ("mib", 1.0 / 1024.0),
        ("mb", 1.0 / 1024.0),
        ("m", 1.0 / 1024.0),
    ] {
        if let Some(n) = s.strip_suffix(suffix) {
            return gib(&json!(
                n.trim()
                    .parse::<f64>()
                    .map_err(|_| "Invalid resource size")?
                    * factor
            ));
        }
    }
    Err("Use a number in GiB, or a size such as 512MB / 4GB".into())
}
impl Environment {
    pub fn options(&self, project: &str) -> Result<Options, String> {
        let command = |v: &Command| match v {
            Command::Shell(s) => vec!["/bin/sh".into(), "-lc".into(), s.clone()],
            Command::Args(v) => v.clone(),
        };
        let o = Options {
            hosts: BTreeMap::new(),
            environment: self.environment.clone(),
            secret_environment: self.secrets.clone(),
            args: self.command.as_ref().map(command),
            entrypoint: self.entrypoint.as_ref().map(command),
            working_dir: self.working_dir.clone(),
            user: self.user.clone(),
            restart: self.restart.clone(),
            binds: self
                .volumes
                .iter()
                .filter(|v| v.bind)
                .map(|v| Volume {
                    source: v.source.clone(),
                    target: v.target.clone(),
                    read_only: v.read_only,
                })
                .collect(),
            volumes: self
                .volumes
                .iter()
                .filter(|v| !v.bind)
                .map(|v| Volume {
                    source: format!("{project}-{}", v.source),
                    target: v.target.clone(),
                    read_only: v.read_only,
                })
                .collect(),
        };
        o.validate()?;
        Ok(o)
    }
    pub fn create_request(&self, project: &str, key: &str) -> Result<Value, String> {
        let range = |n: f64| json!({"min":n,"preferred":n,"max":n,"current":0});
        let kind =
            match self.kind.as_str() {
                "container" | "gpu" => "container",
                "microvm" => "microVm",
                "vm" => "fullVm",
                _ => return Err(
                    "This environment uses its cloud/shared connection instead of local creation"
                        .into(),
                ),
            };
        let gpu = self.gpu || self.kind == "gpu";
        let image = if self.kind == "microvm" {
            self.source.as_deref().unwrap_or("builtin:alpine")
        } else {
            self.source.as_deref().unwrap_or(&self.image)
        };
        Ok(
            json!({"name":format!("{project}-{key}"),"kind":kind,"provider":if kind!="container"{"qemu"}else if gpu{"yougoriCuda"}else{"yougoriOci"},"runtime":image,"description":format!("Project {project} · {key}"),"containerCommand":"","workload":if kind=="container"{Some(self.options(project)?)}else{None},"gpuAccess":gpu,"networkAccess":self.internet,"storageGb":gib(&self.storage)?,"storageDrive":self.storage_drive,"resourcePolicy":{"cpu":range(self.cpu),"memoryGb":range(gib(&self.memory)?),"priority":"normal","dynamic":false}}),
        )
    }
}
impl Project {
    pub fn validate(&self) -> Result<(), String> {
        if !workload::identifier(&self.project) || self.project.len() > 40 {
            return Err(
                "Project name must use 1–40 letters, digits, dots, dashes or underscores".into(),
            );
        }
        if self.environments.is_empty() || self.environments.len() > 64 {
            return Err("Define 1–64 environments".into());
        }
        let mut host_ports = BTreeSet::new();
        for (key, e) in &self.environments {
            if !workload::identifier(key) || self.project.len() + key.len() + 1 > 80 {
                return Err(format!("Invalid environment name: {key}"));
            }
            if !["container", "gpu", "microvm", "vm", "cloud", "shared"].contains(&e.kind.as_str())
            {
                return Err(format!("{key}: unknown environment type"));
            }
            if !e.cpu.is_finite() || e.cpu <= 0.0 || e.cpu > 255.0 || gib(&e.memory)? > 1024.0 {
                return Err(format!("{key}: invalid CPU/memory"));
            }
            let storage = gib(&e.storage)?;
            let minimum = if e.kind == "microvm" { 6.0 } else { 1.0 };
            if !(minimum..=16380.0).contains(&storage) || storage.fract() != 0.0 {
                return Err(format!(
                    "{key}: storage must be whole GiB between {minimum:.0} and 16380"
                ));
            }
            if matches!(e.kind.as_str(), "container" | "gpu")
                && (e.image.is_empty()
                    || e.image.starts_with('-')
                    || e.image.len() > 512
                    || e.image.chars().any(char::is_whitespace))
            {
                return Err(format!("{key}: an OCI image is required"));
            }
            if e.kind == "vm" && e.source.as_ref().unwrap_or(&e.image).is_empty() {
                return Err(format!("{key}: VM source is required"));
            }
            if e.kind == "cloud" && e.cloud.is_none() {
                return Err(format!("{key}: cloud SSH configuration is required"));
            }
            if e.kind == "shared" && e.shared.is_none() {
                return Err(format!("{key}: shared invitation is required"));
            }
            if matches!(e.kind.as_str(), "vm" | "cloud" | "shared")
                && (e.command.is_some()
                    || e.entrypoint.is_some()
                    || !e.environment.is_empty()
                    || !e.volumes.is_empty()
                    || e.working_dir.is_some()
                    || e.user.is_some()
                    || !e.restart.is_empty())
            {
                return Err(format!("{key}: OCI startup, environment and volume options require a container or an OCI microVM workload"));
            }
            if e.kind == "microvm"
                && e.image.is_empty()
                && (e.command.is_some() || !e.environment.is_empty() || !e.volumes.is_empty())
            {
                return Err(format!(
                    "{key}: set image to configure an OCI workload inside the microVM"
                ));
            }
            e.options(&self.project)?;
            if let Some(probe) = &e.health { probe.validate()?; }
            if let Some(setup)=&e.setup{setup.validate()?;if !matches!(e.kind.as_str(),"container"|"gpu"){return Err(format!("{key}: dependency setup currently requires a container"))}}
            if !e.secrets.is_empty()&&!matches!(e.kind.as_str(),"container"|"gpu"|"microvm"){return Err(format!("{key}: protected application secret bindings require a local container or microVM"))}
            if e.kind=="microvm"&&e.image.is_empty()&&!e.secrets.is_empty(){return Err(format!("{key}: protected environment bindings require an OCI workload image inside the microVM"))}
            if !e.files.is_empty() && !matches!(e.kind.as_str(), "container" | "gpu" | "microvm") { return Err(format!("{key}: managed file copies require a container or microVM")); }
            if e.kind=="microvm" && !e.image.is_empty() && !e.files.is_empty(){return Err(format!("{key}: managed code copies in a nested OCI microVM are not supported; use a container or a built-in microVM guest without an OCI image"))}
            let mut file_targets = BTreeSet::new();
            if e.files.len() > 64 || e.files.iter().any(|f| f.source.is_empty() || f.source.contains('\0') || !workload::guest_path(&f.target) || !file_targets.insert(&f.target)) { return Err(format!("{key}: files require at most 64 source paths and unique absolute guest targets")); }
            for mount in &e.volumes {
                if !workload::guest_path(&mount.target) {
                    return Err(format!("{key}: invalid volume target"));
                }
                if mount.bind && !e.permissions.pc {
                    return Err(format!("{key}: bind volumes require permissions.pc: true"));
                }
                if mount.bind && !mount.read_only && !e.permissions.edit {
                    return Err(format!(
                        "{key}: writable PC volumes require permissions.edit: true"
                    ));
                }
            }
            if !e.pc_access.is_empty() && !e.permissions.pc {
                return Err(format!("{key}: PC access requires permissions.pc: true"));
            }
            if e.pc_access.iter().any(|p| !p.read_only) && !e.permissions.edit {
                return Err(format!(
                    "{key}: View & Edit requires permissions.edit: true"
                ));
            }
            for p in &e.ports {
                if let Some(h) = p.values()?.1 {
                    if !host_ports.insert(h) {
                        return Err(format!("Host port {h} is declared more than once"));
                    }
                }
            }
            for d in &e.depends_on {
                if d == key || !self.environments.contains_key(d) {
                    return Err(format!("{key}: unknown/self dependency {d}"));
                }
            }
        }
        for c in &self.connections {
            let (a, b) = c.endpoints()?;
            if a == b || !self.environments.contains_key(a) || !self.environments.contains_key(b) {
                return Err("Connection refers to an unknown environment or itself".into());
            }
            if let Connection::Detailed {
                ports, permissions, ..
            } = c
            {
                if ports.contains(&0)
                    || permissions.iter().any(|s| {
                        !["network", "ports", "files", "volumes", "data", "secrets"]
                            .contains(&s.as_str())
                    })
                {
                    return Err("Invalid connection ports/permissions".into());
                }
            }
        }
        for (key, p) in &self.publish {
            if !self.environments.contains_key(key) {
                return Err(format!("Unknown published environment {key}"));
            }
            if let Publication::Detailed { port, hostname, domain, token_env } = p {
                if *port == 0 {
                    return Err("Publication port must be nonzero".into());
                }
                if domain.as_ref().is_some_and(|name|name.trim().is_empty()||name.len()>253) || (domain.is_some()&&(hostname.is_some()||token_env.is_some())) { return Err("Publication domain uses an existing saved domain; do not combine it with hostname or token_env".into()); }
            }
        }
        self.order()?;
        Ok(())
    }
    pub fn order(&self) -> Result<Vec<String>, String> {
        let mut result = Vec::new();
        while result.len() < self.environments.len() {
            let before = result.len();
            for (key, e) in &self.environments {
                if !result.contains(key) && e.depends_on.iter().all(|d| result.contains(d)) {
                    result.push(key.clone())
                }
            }
            if result.len() == before {
                return Err("Environment dependencies contain a cycle".into());
            }
        }
        Ok(result)
    }
}
pub fn parse(text: &str) -> Result<Project, String> {
    if text.len() > 1024 * 1024 {
        return Err("Project file exceeds 1 MiB".into());
    }
    let p: Project =
        serde_yaml_ng::from_str(text).map_err(|e| format!("Invalid yougori.yaml: {e}"))?;
    p.validate()?;
    Ok(p)
}
pub fn locate(directory: &Path) -> Result<PathBuf, String> {
    for parent in directory.ancestors() {
        for name in ["yougori.yaml", "yougori.yml"] {
            let p = parent.join(name);
            if p.is_file() {
                return p.canonicalize().map_err(|e| e.to_string());
            }
        }
    }
    Err("No yougori.yaml found in this directory or its parents".into())
}
pub fn read(path: &Path) -> Result<String, String> {
    use std::io::Read;
    let mut s = String::new();
    std::fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(1024 * 1024 + 1)
        .read_to_string(&mut s)
        .map_err(|e| e.to_string())?;
    if s.len() > 1024 * 1024 {
        return Err("Project file exceeds 1 MiB".into());
    }
    Ok(s.trim_start_matches('\u{feff}').to_owned())
}

pub fn to_yaml(project: &Project) -> Result<String, String> {
    serde_yaml_ng::to_string(project).map_err(|e| e.to_string())
}

#[cfg(test)]mod deployment_tests{
    #[test]fn internet_defaults_on_but_explicit_off_is_preserved(){
        assert!(super::Environment::default().internet);
        let offline:super::Environment=serde_json::from_value(serde_json::json!({"internet":false})).unwrap();
        assert!(!offline.internet);
    }
    use super::*;
    #[test]fn complete_deployment_roundtrips_protected_references_and_pinned_sdk(){
        let text=r#"project: verified-api
environments:
  api:
    image: python:3.12-slim
    command: [python, /app/api.py]
    files: [{source: ./code, target: /app}]
    volumes: [{source: model-data, target: /models}]
    secrets: {API_TOKEN: qualification-token}
    setup:
      python_minimum: '3.12'
      pip: [fastapi==0.115.0]
      verify_command: python -c 'import fastapi'
    automatic_start: true
    health:
      port: 3000
      path: /qualify
      method: POST
      body: {sample: qualification}
      bearer_secret: qualification-token
      wait_seconds: 180
publish:
  api: {port: 3000, domain: saved-api-domain}
"#;
        let project=parse(text).unwrap();let spec=&project.environments["api"];
        assert_eq!(spec.options("verified-api").unwrap().secret_environment["API_TOKEN"],"qualification-token");
        assert!(spec.automatic_start);assert_eq!(spec.health.as_ref().unwrap().method,"POST");
        assert_eq!(parse(&to_yaml(&project).unwrap()).unwrap(),project);
    }
    #[test]fn invalid_health_paths_secret_values_and_unpinned_sdks_fail_before_creation(){
        for path in ["//other.example/health","/health\r\nAuthorization: leaked","health","/health#fragment","/\\other.example/health","/health\\subpath"]{
            let probe:HealthCheck=serde_json::from_value(json!({"port":3000,"path":path})).unwrap();assert!(probe.validate().is_err());
        }
        for path in ["/health%23literal","/health%5Cliteral","/health check/λ?label=hello world"] {
            let probe:HealthCheck=serde_json::from_value(json!({"port":3000,"path":path})).unwrap();assert!(probe.validate().is_ok());
        }
        for requirement in ["fastapi", "git+https://example.com/package", "package==1.0; echo malicious"]{
            let setup:Setup=serde_json::from_value(json!({"pip":[requirement]})).unwrap();assert!(setup.validate().is_err());
        }
        let mut project=parse("project: refs\nenvironments:\n  api:\n    image: alpine:latest\n    secrets: {API_TOKEN: protected-token}\n").unwrap();
        project.environments.get_mut("api").unwrap().environment.insert("API_TOKEN".into(),"plain-value".into());assert!(project.validate().is_err());
        project.environments.get_mut("api").unwrap().environment.clear();project.environments.get_mut("api").unwrap().secrets.insert("API_TOKEN".into(),"literal secret with spaces".into());assert!(project.validate().is_err());
    }
    #[test]fn unsupported_target_features_are_rejected_during_manifest_preflight(){
        for kind in ["cloud", "vm", "shared"] {
            let project:Project=serde_json::from_value(json!({"project":"preflight","environments":{"api":{"type":kind,"source":"guest.qcow2","cloud":{},"shared":"test-invitation","files":[{"source":"./code","target":"/app"}]}}})).unwrap();
            assert!(project.validate().unwrap_err().contains("managed file copies"),"{kind} must not accept managed copies without a supported guest API");
            let project:Project=serde_json::from_value(json!({"project":"preflight","environments":{"api":{"type":kind,"source":"guest.qcow2","cloud":{},"shared":"test-invitation","setup":{"python_minimum":"3.12","pip":["fastapi==0.115.0"]}}}})).unwrap();
            assert!(project.validate().unwrap_err().contains("dependency setup"),"{kind} must not accept local dependency setup");
        }
        let built_in:Project=serde_json::from_value(json!({"project":"preflight","environments":{"guest":{"type":"microvm","storage":6,"secrets":{"API_TOKEN":"protected-token"}}}})).unwrap();
        assert!(built_in.validate().unwrap_err().contains("OCI workload image"));
        let nested:Project=serde_json::from_value(json!({"project":"preflight","environments":{"guest":{"type":"microvm","image":"alpine:latest","storage":6,"files":[{"source":"./code","target":"/app"}]}}})).unwrap();
        assert!(nested.validate().unwrap_err().contains("nested OCI microVM"));
    }
}
