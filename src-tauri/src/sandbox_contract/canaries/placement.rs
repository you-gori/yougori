//! Placement rules (VM part §8.2 line 2274: "Avoid planting files that break normal SDK
//! auto-discovery").
//!
//! A canary is planted as a file under the workload user's home or the workspace, or as
//! an environment variable. [`SDK_DISCOVERY_LOCATIONS`] lists where tools look for
//! credentials and configuration on their own; [`check_placement`] refuses every location
//! on, under or above one of them, comparing ASCII case-insensitively. Paths are relative
//! to a typed root and refused unless already normal, so `..`, `.`, empty components and
//! absolute paths are not representable. The guest agent still checks symbolic links and
//! existing files when it plants (later work).

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use super::canary::CanaryKind;
use crate::foundation::ids::DigestBuilder;

/// Longest accepted guest path, in bytes.
pub const MAX_GUEST_PATH_BYTES: usize = 255;
/// Most components in a guest path.
pub const MAX_GUEST_PATH_COMPONENTS: usize = 16;
/// Longest accepted environment variable name, in bytes.
const MAX_ENV_NAME_BYTES: usize = 128;

/// Why a path or a variable name was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocationError {
    /// Nothing was given.
    Empty,
    /// Longer than its bound.
    TooLong {
        /// The bound.
        max_bytes: usize,
    },
    /// More path components than [`MAX_GUEST_PATH_COMPONENTS`].
    TooManyComponents {
        /// The bound.
        max: usize,
    },
    /// An empty component: a leading, trailing or doubled `/`.
    EmptyComponent,
    /// A `.` or `..` component.
    DotComponent,
    /// Only ASCII letters, digits, `.`, `_` and `-` are accepted in a path component.
    InvalidPathCharacter,
    /// A variable name is an ASCII letter or `_` followed by letters, digits or `_`.
    InvalidEnvName,
}

impl fmt::Display for LocationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("the location is empty"),
            Self::TooLong { max_bytes } => {
                write!(f, "the location is longer than {max_bytes} bytes")
            }
            Self::TooManyComponents { max } => write!(f, "the path has more than {max} components"),
            Self::EmptyComponent => f.write_str("the path has an empty component"),
            Self::DotComponent => f.write_str("the path has a '.' or '..' component"),
            Self::InvalidPathCharacter => f.write_str(
                "a path component may hold only ASCII letters, digits, '.', '_' and '-'",
            ),
            Self::InvalidEnvName => f.write_str(
                "a variable name is an ASCII letter or '_' followed by letters, digits or '_'",
            ),
        }
    }
}

impl std::error::Error for LocationError {}

/// A normal relative path inside the guest, below a [`FileRoot`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct GuestPath(String);

impl GuestPath {
    /// Accepts only an already normal relative path; see [`LocationError`].
    pub fn new(value: impl Into<String>) -> Result<Self, LocationError> {
        let value = value.into();
        if value.is_empty() {
            return Err(LocationError::Empty);
        }
        if value.len() > MAX_GUEST_PATH_BYTES {
            return Err(LocationError::TooLong {
                max_bytes: MAX_GUEST_PATH_BYTES,
            });
        }
        let mut count = 0usize;
        for component in value.split('/') {
            count = count.saturating_add(1);
            if component.is_empty() {
                return Err(LocationError::EmptyComponent);
            }
            if component == "." || component == ".." {
                return Err(LocationError::DotComponent);
            }
            if !component
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            {
                return Err(LocationError::InvalidPathCharacter);
            }
        }
        if count > MAX_GUEST_PATH_COMPONENTS {
            return Err(LocationError::TooManyComponents {
                max: MAX_GUEST_PATH_COMPONENTS,
            });
        }
        Ok(Self(value))
    }

    /// The path as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The path's components, in order.
    pub fn components(&self) -> impl Iterator<Item = &str> {
        self.0.split('/')
    }
}

impl<'de> Deserialize<'de> for GuestPath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for GuestPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An environment variable name.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct EnvName(String);

impl EnvName {
    /// Accepts an ASCII letter or `_` followed by letters, digits or `_`, up to 128 bytes.
    pub fn new(value: impl Into<String>) -> Result<Self, LocationError> {
        let value = value.into();
        if value.is_empty() {
            return Err(LocationError::Empty);
        }
        if value.len() > MAX_ENV_NAME_BYTES {
            return Err(LocationError::TooLong {
                max_bytes: MAX_ENV_NAME_BYTES,
            });
        }
        let mut bytes = value.bytes();
        let starts_well = bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_');
        if !starts_well || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_') {
            return Err(LocationError::InvalidEnvName);
        }
        Ok(Self(value))
    }

    /// The name as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for EnvName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for EnvName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The root a guest path is relative to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileRoot {
    /// The workload user's home directory.
    Home,
    /// The workspace the workload runs in.
    Workspace,
}

impl FileRoot {
    /// The label used in folded keys, digests and messages.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Home => "home",
            Self::Workspace => "workspace",
        }
    }
}

/// A file inside the guest.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileLocation {
    /// The root the path is relative to.
    pub root: FileRoot,
    /// The path below the root.
    pub path: GuestPath,
}

impl FileLocation {
    /// A file at `path` below `root`.
    pub fn new(root: FileRoot, path: GuestPath) -> Self {
        Self { root, path }
    }
}

strict_canary_enum! {
    /// Where a canary is planted.
    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum PlacementLocation tag "location" {
        /// A file inside the guest.
        File {
            /// The root the path is relative to.
            root: FileRoot,
            /// The path below the root.
            path: GuestPath,
        },
        /// An environment variable of the workload.
        EnvironmentVariable {
            /// The variable's name.
            name: EnvName,
        },
    }
}

impl PlacementLocation {
    /// A file location.
    pub fn file(file: FileLocation) -> Self {
        Self::File {
            root: file.root,
            path: file.path,
        }
    }

    /// A file under the home directory.
    pub fn home(path: &str) -> Result<Self, LocationError> {
        Ok(Self::File {
            root: FileRoot::Home,
            path: GuestPath::new(path)?,
        })
    }

    /// A file under the workspace.
    pub fn workspace(path: &str) -> Result<Self, LocationError> {
        Ok(Self::File {
            root: FileRoot::Workspace,
            path: GuestPath::new(path)?,
        })
    }

    /// An environment variable.
    pub fn env(name: &str) -> Result<Self, LocationError> {
        Ok(Self::EnvironmentVariable {
            name: EnvName::new(name)?,
        })
    }

    /// The file, when this is one.
    pub fn as_file(&self) -> Option<FileLocation> {
        match self {
            Self::File { root, path } => Some(FileLocation::new(*root, path.clone())),
            Self::EnvironmentVariable { .. } => None,
        }
    }

    /// The case-folded form two locations collide under.
    pub(super) fn folded(&self) -> String {
        match self {
            Self::File { root, path } => {
                format!("{}:{}", root.label(), path.as_str().to_ascii_lowercase())
            }
            Self::EnvironmentVariable { name } => {
                format!("env:{}", name.as_str().to_ascii_uppercase())
            }
        }
    }

    pub(super) fn feed(&self, builder: DigestBuilder) -> DigestBuilder {
        match self {
            Self::File { root, path } => builder.str(root.label()).str(path.as_str()),
            Self::EnvironmentVariable { name } => builder.str("env").str(name.as_str()),
        }
    }
}

impl fmt::Display for PlacementLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File { root, path } => write!(f, "{} file {path}", root.label()),
            Self::EnvironmentVariable { name } => write!(f, "environment variable {name}"),
        }
    }
}

/// How one discovery location is matched. Paths are lowercase, `/`-separated and relative
/// to their root; names and prefixes compare ASCII case-insensitively.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoveryRule {
    /// This path under the home directory; anything on, under or above it is refused. It
    /// applies under the workspace root too, since a workspace may be the home directory.
    HomePath(&'static str),
    /// A file or directory with this name at any depth under either root.
    NameAnywhere(&'static str),
    /// A file or directory whose name starts with this prefix at any depth.
    NamePrefixAnywhere(&'static str),
    /// This environment variable.
    EnvName(&'static str),
    /// Every environment variable whose name starts with this prefix.
    EnvPrefix(&'static str),
}

/// One location a tool reads by itself, and the tool (§8.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SdkDiscoveryLocation {
    /// The tool that reads it.
    pub tool: &'static str,
    /// How the location is matched.
    pub rule: DiscoveryRule,
}

const fn home(path: &'static str, tool: &'static str) -> SdkDiscoveryLocation {
    SdkDiscoveryLocation {
        tool,
        rule: DiscoveryRule::HomePath(path),
    }
}

const fn named(name: &'static str, tool: &'static str) -> SdkDiscoveryLocation {
    SdkDiscoveryLocation {
        tool,
        rule: DiscoveryRule::NameAnywhere(name),
    }
}

const fn env(name: &'static str, tool: &'static str) -> SdkDiscoveryLocation {
    SdkDiscoveryLocation {
        tool,
        rule: DiscoveryRule::EnvName(name),
    }
}

const fn env_prefix(prefix: &'static str, tool: &'static str) -> SdkDiscoveryLocation {
    SdkDiscoveryLocation {
        tool,
        rule: DiscoveryRule::EnvPrefix(prefix),
    }
}

/// Locations never used for planting (§8.2 "Avoid planting files that break normal SDK
/// auto-discovery"): standard SDK and CLI credential and configuration discovery paths,
/// files tools pick up from any directory, and the environment variables tools read, by
/// name or by namespace prefix. Planting there could shadow a real credential, break a
/// tool, or make benign tooling touch the canary.
pub const SDK_DISCOVERY_LOCATIONS: &[SdkDiscoveryLocation] = &[
    home(".aws", "AWS CLI and SDKs"),
    home(".azure", "Azure CLI and SDKs"),
    home(".config/gcloud", "Google Cloud CLI and client libraries"),
    home(".kube", "kubectl and Kubernetes clients"),
    home(".docker", "Docker CLI"),
    home(".ssh", "OpenSSH and Git over SSH"),
    home(".gnupg", "GnuPG"),
    home(".config/gh", "GitHub CLI"),
    home(".config/git", "Git"),
    home(".config/github-copilot", "GitHub Copilot"),
    home(".cache/huggingface", "Hugging Face Hub"),
    home(".huggingface", "Hugging Face Hub"),
    home(".cargo/credentials", "Cargo"),
    home(".cargo/credentials.toml", "Cargo"),
    home(".cargo/config", "Cargo"),
    home(".cargo/config.toml", "Cargo"),
    home(".terraform.d", "Terraform"),
    home(".m2/settings.xml", "Maven"),
    home(".gradle/gradle.properties", "Gradle"),
    home(".gem/credentials", "RubyGems"),
    home(".config/containers", "Podman and Buildah"),
    home(".oci", "Oracle Cloud CLI"),
    home(".config/pip", "pip"),
    home(".pip", "pip"),
    home(".local/share/keyrings", "GNOME Keyring"),
    home(".password-store", "pass"),
    home(".config/rclone", "rclone"),
    home(".claude", "Claude Code"),
    home(".codex", "OpenAI Codex CLI"),
    home(".yougori", "Yougori guest agent"),
    home(".config/yougori", "Yougori guest agent"),
    named(".env", "dotenv loaders"),
    SdkDiscoveryLocation {
        tool: "dotenv loaders",
        rule: DiscoveryRule::NamePrefixAnywhere(".env."),
    },
    named(".git", "Git"),
    named(".gitconfig", "Git"),
    named(".git-credentials", "Git credential store"),
    named(".netrc", "curl, Git and Python netrc"),
    named("_netrc", "curl and Git on Windows"),
    named(".npmrc", "npm"),
    named(".yarnrc", "Yarn"),
    named(".yarnrc.yml", "Yarn"),
    named(".pypirc", "twine"),
    named("pip.conf", "pip"),
    named(".pgpass", "PostgreSQL clients"),
    named(".my.cnf", "MySQL clients"),
    named(".terraformrc", "Terraform"),
    named(".dockercfg", "Docker CLI"),
    named(".boto", "boto and gsutil"),
    named(".s3cfg", "s3cmd"),
    named(".vault-token", "HashiCorp Vault CLI"),
    named(".databrickscfg", "Databricks CLI"),
    named(
        "application_default_credentials.json",
        "Google client libraries",
    ),
    env("HOME", "every process"),
    env("PATH", "every process"),
    env("LD_PRELOAD", "the dynamic loader"),
    env("LD_LIBRARY_PATH", "the dynamic loader"),
    env("PYTHONPATH", "Python"),
    env("NODE_OPTIONS", "Node.js"),
    env("NODE_PATH", "Node.js"),
    env("NODE_EXTRA_CA_CERTS", "Node.js"),
    env("NODE_AUTH_TOKEN", "npm and setup-node"),
    env("NPM_TOKEN", "npm"),
    env("HTTP_PROXY", "HTTP clients"),
    env("HTTPS_PROXY", "HTTP clients"),
    env("ALL_PROXY", "HTTP clients"),
    env("NO_PROXY", "HTTP clients"),
    env("SSL_CERT_FILE", "OpenSSL"),
    env("SSL_CERT_DIR", "OpenSSL"),
    env("REQUESTS_CA_BUNDLE", "Python requests"),
    env("CURL_CA_BUNDLE", "curl"),
    env("CURL_HOME", "curl"),
    env("NETRC", "curl"),
    env("DATABASE_URL", "database clients and ORMs"),
    env("REDIS_URL", "Redis clients"),
    env("PGPASSWORD", "PostgreSQL clients"),
    env("PGPASSFILE", "PostgreSQL clients"),
    env("PGSERVICEFILE", "PostgreSQL clients"),
    env("MYSQL_PWD", "MySQL clients"),
    env("REGISTRY_AUTH_FILE", "Podman and Buildah"),
    env("TWINE_USERNAME", "twine"),
    env("TWINE_PASSWORD", "twine"),
    env("SSH_AUTH_SOCK", "the OpenSSH agent"),
    env("SSH_ASKPASS", "OpenSSH"),
    env_prefix("AWS_", "AWS CLI and SDKs"),
    env_prefix("AZURE_", "Azure CLI and SDKs"),
    env_prefix("ARM_", "Terraform AzureRM provider"),
    env_prefix("GOOGLE_", "Google client libraries"),
    env_prefix("GCLOUD_", "Google Cloud CLI"),
    env_prefix("CLOUDSDK_", "Google Cloud CLI"),
    env_prefix("GEMINI_", "Gemini SDKs"),
    env_prefix("GITHUB_", "GitHub CLI and Actions"),
    env_prefix("GH_", "GitHub CLI"),
    env_prefix("GITLAB_", "GitLab CLI"),
    env_prefix("GIT_", "Git"),
    env_prefix("HF_", "Hugging Face Hub"),
    env_prefix("HUGGING_FACE_", "Hugging Face Hub"),
    env_prefix("HUGGINGFACE_", "Hugging Face Hub"),
    env_prefix("OPENAI_", "OpenAI SDKs"),
    env_prefix("ANTHROPIC_", "Anthropic SDKs"),
    env_prefix("CLAUDE_", "Claude Code"),
    env_prefix("NPM_CONFIG_", "npm"),
    env_prefix("YARN_", "Yarn"),
    env_prefix("PIP_", "pip"),
    env_prefix("UV_", "uv"),
    env_prefix("POETRY_", "Poetry"),
    env_prefix("CARGO_", "Cargo"),
    env_prefix("DOCKER_", "Docker CLI"),
    env_prefix("KUBE", "kubectl and Kubernetes clients"),
    env_prefix("VAULT_", "HashiCorp Vault CLI"),
    env_prefix("TF_", "Terraform"),
    env_prefix("DIGITALOCEAN_", "DigitalOcean CLI"),
    env_prefix("OCI_", "Oracle Cloud CLI"),
    env_prefix("DATABRICKS_", "Databricks CLI"),
    env_prefix("SNOWFLAKE_", "Snowflake connectors"),
    env_prefix("WANDB_", "Weights & Biases"),
    env_prefix("KAGGLE_", "Kaggle CLI"),
    env_prefix("XDG_", "XDG base directories"),
    env_prefix("YOUGORI_", "Yougori guest agent"),
];

impl SdkDiscoveryLocation {
    /// Whether planting at `location` would touch this discovery location.
    pub fn covers(&self, location: &PlacementLocation) -> bool {
        match (self.rule, location) {
            (DiscoveryRule::HomePath(rule), PlacementLocation::File { path, .. }) => {
                on_under_or_above(path, rule)
            }
            (DiscoveryRule::NameAnywhere(name), PlacementLocation::File { path, .. }) => path
                .components()
                .any(|component| component.eq_ignore_ascii_case(name)),
            (DiscoveryRule::NamePrefixAnywhere(prefix), PlacementLocation::File { path, .. }) => {
                path.components()
                    .any(|component| starts_with_folded(component, prefix))
            }
            (DiscoveryRule::EnvName(rule), PlacementLocation::EnvironmentVariable { name }) => {
                name.as_str().eq_ignore_ascii_case(rule)
            }
            (DiscoveryRule::EnvPrefix(prefix), PlacementLocation::EnvironmentVariable { name }) => {
                starts_with_folded(name.as_str(), prefix)
            }
            _ => false,
        }
    }
}

fn starts_with_folded(text: &str, prefix: &str) -> bool {
    text.get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

/// Whether one path is a prefix of the other, component by component: planting on a
/// discovery path, inside it, or at one of its ancestors (which would shadow it).
fn on_under_or_above(path: &GuestPath, rule: &str) -> bool {
    path.components()
        .zip(rule.split('/'))
        .all(|(component, expected)| component.eq_ignore_ascii_case(expected))
}

strict_canary_enum! {
    /// Why a placement was refused.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum PlacementRefusal tag "refusal" {
        /// The location is, contains or lies under a location `tool` discovers by itself.
        SdkDiscovery {
            /// The tool that discovers it.
            tool: String,
            /// The refused location.
            location: PlacementLocation,
        },
        /// A document marker lives in a fake document, never in a variable.
        KindNeedsFile {
            /// The kind requested.
            kind: CanaryKind,
            /// The refused location.
            location: PlacementLocation,
        },
        /// Two canaries of one plan at one location, compared case-insensitively.
        DuplicateLocation {
            /// The location named twice.
            location: PlacementLocation,
        },
    }
}

impl fmt::Display for PlacementRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SdkDiscovery { tool, location } => write!(
                f,
                "{location} is a location {tool} discovers by itself; a canary there could \
                 break it"
            ),
            Self::KindNeedsFile { kind, location } => {
                write!(f, "a {kind} canary needs a file, not {location}")
            }
            Self::DuplicateLocation { location } => {
                write!(f, "two canaries of one plan at {location}")
            }
        }
    }
}

impl std::error::Error for PlacementRefusal {}

/// Checks one placement against the kind's needs and every [`SDK_DISCOVERY_LOCATIONS`]
/// entry (§8.2).
pub fn check_placement(
    kind: CanaryKind,
    location: &PlacementLocation,
) -> Result<(), PlacementRefusal> {
    if kind.needs_file() && location.as_file().is_none() {
        return Err(PlacementRefusal::KindNeedsFile {
            kind,
            location: location.clone(),
        });
    }
    match SDK_DISCOVERY_LOCATIONS
        .iter()
        .find(|entry| entry.covers(location))
    {
        Some(entry) => Err(PlacementRefusal::SdkDiscovery {
            tool: entry.tool.to_owned(),
            location: location.clone(),
        }),
        None => Ok(()),
    }
}
