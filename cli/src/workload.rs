use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Options {
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    #[serde(default)]
    pub secret_environment: BTreeMap<String, String>,
    #[serde(default)]
    pub hosts: BTreeMap<String, String>,
    /// None preserves the image CMD; Some([]) clears it.
    #[serde(default)]
    pub args: Option<Vec<String>>,
    #[serde(default)]
    pub entrypoint: Option<Vec<String>>,
    #[serde(default)]
    pub working_dir: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub volumes: Vec<Volume>,
    #[serde(default)]
    pub binds: Vec<Volume>,
    #[serde(default)]
    pub restart: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Volume {
    pub source: String,
    pub target: String,
    #[serde(default)]
    pub read_only: bool,
}
pub fn guest_path(path: &str) -> bool {
    path.starts_with('/')
        && path != "/"
        && path.len() <= 4096
        && !path.chars().any(char::is_control)
        && !path.contains([',', ':', '\\'])
        && !path.split('/').any(|v| v == ".." || v == ".")
        // The agent's own mounts, matching appliance/agent/workload_options.go. The
        // user's imported project area under /yougori stays usable.
        && path != "/yougori"
        && ![
            "/proc",
            "/sys",
            "/dev",
            "/yougori/bin",
            "/yougori/secrets",
            "/yougori/shared",
            crate::legacy_names::CONTAINER_MOUNT_ROOT,
        ]
        .iter()
        .any(|p| path == *p || path.starts_with(&format!("{p}/")))
}

#[cfg(test)]
mod guest_path_tests {
    use super::guest_path;

    #[test]
    fn agent_mounts_are_reserved_and_the_project_area_is_not() {
        for reserved in ["/proc", "/sys/kernel", "/dev", "/yougori", "/yougori/shared/my-pc",
            "/yougori/secrets/token", "/yougori/bin", crate::legacy_names::CONTAINER_MOUNT_ROOT] {
            assert!(!guest_path(reserved), "{reserved}");
        }
        for allowed in ["/yougori/project-files", "/yougori/project-files/app", "/data", "/app"] {
            assert!(guest_path(allowed), "{allowed}");
        }
    }
}
pub fn identifier(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 80
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}
impl Options {
    pub fn validate(&self) -> Result<(), String> {
        if self.secret_environment.len() > 128 || self.secret_environment.iter().any(|(name, reference)| !identifier(reference) || self.environment.contains_key(name) || name.is_empty() || name.len() > 256 || !name.bytes().enumerate().all(|(i,b)| b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit()))) {
            return Err("Secret bindings require unique environment variable names and OS-vault references; do not specify their values in environment".into());
        }
        if self.hosts.len() > 256
            || self
                .hosts
                .iter()
                .any(|(name, ip)| !identifier(name) || ip.parse::<std::net::Ipv4Addr>().is_err())
        {
            return Err("Invalid project host aliases".into());
        }
        if self.environment.len() > 512
            || self.environment.iter().any(|(k, v)| {
                k.is_empty()
                    || k.len() > 256
                    || !k.bytes().enumerate().all(|(i, b)| {
                        b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit())
                    })
                    || v.contains('\0')
                    || v.len() > 65536
            })
        {
            return Err("Invalid environment variable name/value (maximum 512 variables)".into());
        }
        for args in [&self.args, &self.entrypoint].into_iter().flatten() {
            if args.len() > 512 || args.iter().any(|v| v.contains('\0') || v.len() > 65536) {
                return Err("Invalid command arguments".into());
            }
        }
        if self
            .working_dir
            .as_ref()
            .is_some_and(|v| v != "/" && !guest_path(v))
        {
            return Err("working_dir must be an absolute guest directory".into());
        }
        if self.user.as_ref().is_some_and(|v| {
            v.is_empty()
                || v.starts_with('-')
                || v.len() > 128
                || !v
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_:.-".contains(&c))
        }) {
            return Err("Invalid container user".into());
        }
        if !["", "no", "always", "unless-stopped", "on-failure"].contains(&self.restart.as_str()) {
            return Err("Invalid restart policy".into());
        }
        let mut targets = std::collections::BTreeSet::new();
        if self.volumes.len() > 64 {
            return Err("At most 64 volumes per workload".into());
        }
        for volume in &self.volumes {
            if !identifier(&volume.source)
                || !guest_path(&volume.target)
                || !targets.insert(&volume.target)
            {
                return Err(
                    "Volumes require unique absolute targets and managed volume names".into(),
                );
            }
        }
        for bind in &self.binds {
            if bind.source.is_empty()
                || bind.source.contains('\0')
                || !guest_path(&bind.target)
                || !targets.insert(&bind.target)
            {
                return Err(
                    "Bind mounts require an existing PC folder and a unique absolute guest target"
                        .into(),
                );
            }
        }
        if serde_json::to_vec(self).map_err(|e| e.to_string())?.len() > 256 * 1024 {
            return Err("Workload options exceed 256 KiB".into());
        }
        Ok(())
    }
}
