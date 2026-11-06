//! Typed values of the RunPod transport (VM-W39; VM-D5): the pod launch specification
//! an offering stands for, the catalog that maps V12's offering names to it, the pod name
//! that carries an attempt's idempotency key, and the pod identity and status read back
//! from RunPod.
//!
//! Every value that reaches runpodctl's argv is checked here first, so the argv is built
//! from typed values only and no value can be read by runpodctl as a flag: each starts
//! with an ASCII letter or digit. Pod ids and statuses come from the provider and are
//! checked before use; anything else is refused, never guessed.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::foundation::ids::DigestBuilder;
use crate::sandbox_contract::remote::{AttemptId, OfferingName};

/// The longest RunPod GPU type id accepted, such as `NVIDIA GeForce RTX 4090`.
pub const MAX_GPU_TYPE_BYTES: usize = 128;
/// The longest container image reference accepted.
pub const MAX_IMAGE_BYTES: usize = 512;
/// The longest RunPod pod id accepted.
pub const MAX_POD_ID_BYTES: usize = 64;
/// The most GPUs one pod may ask for.
pub const MAX_GPU_COUNT: u32 = 8;
/// The smallest container disk RunPod accepts, in GB.
pub const MIN_CONTAINER_DISK_GB: u32 = 5;
/// The largest container disk accepted, in GB.
pub const MAX_CONTAINER_DISK_GB: u32 = 4_000;
/// The prefix of every pod name this transport gives.
pub const POD_NAME_PREFIX: &str = "yougori-";
/// How many bytes of the attempt's digest a pod name carries, in hexadecimal.
pub const POD_NAME_KEY_BYTES: usize = 16;
/// The prefix of an offering name made for a delivered GPU no configured offering has.
pub const UNLISTED_OFFERING_PREFIX: &str = "unlisted-";
/// Domain of the digest an unlisted offering's name is made from.
pub const UNLISTED_OFFERING_DOMAIN: &str = "yougori/sandbox/remote-provider/runpod-unlisted/v1";

/// Why a typed value was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum ValueProblem {
    Empty,
    TooLong {
        max_bytes: u64,
    },
    /// A character outside the value's alphabet.
    InvalidCharacter,
    /// The first or last character is not an ASCII letter or digit.
    InvalidEdge,
}

impl fmt::Display for ValueProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("the value is empty"),
            Self::TooLong { max_bytes } => write!(f, "the value is longer than {max_bytes} bytes"),
            Self::InvalidCharacter => f.write_str("the value holds a character it may not hold"),
            Self::InvalidEdge => f.write_str(
                "the value must start (and, where required, end) with a letter or digit",
            ),
        }
    }
}

impl std::error::Error for ValueProblem {}

fn check_text(
    text: &str,
    max_bytes: usize,
    allowed: impl Fn(u8) -> bool,
    alphanumeric_end: bool,
) -> Result<(), ValueProblem> {
    if text.is_empty() {
        return Err(ValueProblem::Empty);
    }
    if text.len() > max_bytes {
        return Err(ValueProblem::TooLong {
            max_bytes: u64::try_from(max_bytes).unwrap_or(u64::MAX),
        });
    }
    if !text
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || allowed(byte))
    {
        return Err(ValueProblem::InvalidCharacter);
    }
    let first = text
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric());
    let last = text
        .bytes()
        .last()
        .is_some_and(|byte| byte.is_ascii_alphanumeric());
    if !first || (alphanumeric_end && !last) {
        return Err(ValueProblem::InvalidEdge);
    }
    Ok(())
}

/// Declares a checked text value: `new` applies `$check`, serde reads through `new`.
macro_rules! checked_text {
    ($(#[$doc:meta])* $name:ident, $check:expr) => {
        $(#[$doc])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Accepts the value's grammar (see the type's notes).
            pub fn new(value: impl Into<String>) -> Result<Self, ValueProblem> {
                let value = value.into();
                let check: fn(&str) -> Result<(), ValueProblem> = $check;
                check(&value)?;
                Ok(Self(value))
            }

            /// The value as text.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
            }
        }
    };
}

checked_text!(
    /// A RunPod GPU type id, such as `NVIDIA A40`: 1 to [`MAX_GPU_TYPE_BYTES`] ASCII
    /// letters, digits, spaces, `-`, `_` and `.`, starting and ending with a letter or
    /// digit.
    GpuTypeId,
    |text| check_text(
        text,
        MAX_GPU_TYPE_BYTES,
        |byte| matches!(byte, b' ' | b'-' | b'_' | b'.'),
        true
    )
);

checked_text!(
    /// A container image reference, such as `runpod/pytorch:2.4.0-py3.11`: 1 to
    /// [`MAX_IMAGE_BYTES`] ASCII letters, digits, `-`, `_`, `.`, `:`, `/` and `@`,
    /// starting with a letter or digit.
    ContainerImage,
    |text| check_text(
        text,
        MAX_IMAGE_BYTES,
        |byte| matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@'),
        false
    )
);

checked_text!(
    /// A RunPod pod id as the provider reported it: 1 to [`MAX_POD_ID_BYTES`] ASCII
    /// letters and digits.
    PodId,
    |text| check_text(text, MAX_POD_ID_BYTES, |_| false, true)
);

/// RunPod's two clouds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudType {
    Secure,
    Community,
}

impl CloudType {
    /// The value runpodctl's `--cloud-type` takes.
    pub const fn flag(self) -> &'static str {
        match self {
            Self::Secure => "SECURE",
            Self::Community => "COMMUNITY",
        }
    }
}

/// What one offering launches: a GPU pod of `gpu_count` × `gpu` on `cloud`, running
/// `image` with `container_disk_gb` of container disk. The region comes from the
/// provisioning request.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PodSpec {
    pub gpu: GpuTypeId,
    pub gpu_count: u32,
    pub cloud: CloudType,
    pub image: ContainerImage,
    pub container_disk_gb: u32,
}

/// Why a catalog was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum CatalogRefusal {
    /// No offering was given.
    Empty,
    /// The offering name appears twice.
    Duplicate { offering: OfferingName },
    /// The name starts with [`UNLISTED_OFFERING_PREFIX`], which names delivered GPUs
    /// no configured offering has.
    ReservedName { offering: OfferingName },
    /// The GPU count is outside 1 to [`MAX_GPU_COUNT`].
    GpuCount { offering: OfferingName, count: u32 },
    /// The container disk is outside [`MIN_CONTAINER_DISK_GB`] to
    /// [`MAX_CONTAINER_DISK_GB`].
    ContainerDisk { offering: OfferingName, gb: u32 },
}

impl fmt::Display for CatalogRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("the RunPod catalog has no offering"),
            Self::Duplicate { offering } => write!(f, "the offering {offering} appears twice"),
            Self::ReservedName { offering } => write!(
                f,
                "the offering name {offering} starts with the reserved prefix \
                 {UNLISTED_OFFERING_PREFIX}"
            ),
            Self::GpuCount { offering, count } => write!(
                f,
                "the offering {offering} asks for {count} GPUs; 1 to {MAX_GPU_COUNT} are allowed"
            ),
            Self::ContainerDisk { offering, gb } => write!(
                f,
                "the offering {offering} asks for {gb} GB of container disk; \
                 {MIN_CONTAINER_DISK_GB} to {MAX_CONTAINER_DISK_GB} are allowed"
            ),
        }
    }
}

impl std::error::Error for CatalogRefusal {}

/// The offerings this transport can launch, by V12 offering name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunPodCatalog {
    offerings: BTreeMap<OfferingName, PodSpec>,
}

impl RunPodCatalog {
    /// Checks every entry: a unique name without the reserved prefix, 1 to
    /// [`MAX_GPU_COUNT`] GPUs and a container disk within the allowed range.
    pub fn new(
        entries: impl IntoIterator<Item = (OfferingName, PodSpec)>,
    ) -> Result<Self, CatalogRefusal> {
        let mut offerings = BTreeMap::new();
        for (offering, spec) in entries {
            if offering.as_str().starts_with(UNLISTED_OFFERING_PREFIX) {
                return Err(CatalogRefusal::ReservedName { offering });
            }
            if !(1..=MAX_GPU_COUNT).contains(&spec.gpu_count) {
                return Err(CatalogRefusal::GpuCount {
                    offering,
                    count: spec.gpu_count,
                });
            }
            if !(MIN_CONTAINER_DISK_GB..=MAX_CONTAINER_DISK_GB).contains(&spec.container_disk_gb) {
                return Err(CatalogRefusal::ContainerDisk {
                    offering,
                    gb: spec.container_disk_gb,
                });
            }
            if offerings.contains_key(&offering) {
                return Err(CatalogRefusal::Duplicate { offering });
            }
            offerings.insert(offering, spec);
        }
        if offerings.is_empty() {
            return Err(CatalogRefusal::Empty);
        }
        Ok(Self { offerings })
    }

    /// The launch specification of `offering`, if configured.
    pub fn spec(&self, offering: &OfferingName) -> Option<&PodSpec> {
        self.offerings.get(offering)
    }

    /// The offering name for a pod delivered with `count` × `gpu` when `requested` was
    /// asked for: `requested` when its GPU type and count match; otherwise the one other
    /// configured offering with that GPU type and count; otherwise a name made from the
    /// delivered GPU under [`UNLISTED_OFFERING_PREFIX`]. A delivered GPU other than the
    /// requested one therefore always shows as another offering. `None` only if the made
    /// name were refused by the identifier grammar, which its form rules out.
    pub fn delivered_offering(
        &self,
        requested: &OfferingName,
        gpu: &GpuTypeId,
        count: u32,
    ) -> Option<OfferingName> {
        let matches = |spec: &PodSpec| spec.gpu == *gpu && spec.gpu_count == count;
        if self.offerings.get(requested).is_some_and(matches) {
            return Some(requested.clone());
        }
        let mut others = self
            .offerings
            .iter()
            .filter(|(name, spec)| *name != requested && matches(spec));
        if let (Some((name, _)), None) = (others.next(), others.next()) {
            return Some(name.clone());
        }
        unlisted_offering(gpu, count)
    }
}

/// The offering name for a delivered GPU no configured offering has: the prefix and the
/// first eight bytes, in hexadecimal, of a digest of the GPU type and count.
fn unlisted_offering(gpu: &GpuTypeId, count: u32) -> Option<OfferingName> {
    let digest = DigestBuilder::new(UNLISTED_OFFERING_DOMAIN)
        .str(gpu.as_str())
        .u64(u64::from(count))
        .finish();
    let short: Vec<u8> = digest.as_bytes().iter().take(8).copied().collect();
    OfferingName::new(format!("{UNLISTED_OFFERING_PREFIX}{}", hex::encode(short))).ok()
}

/// The name of the pod made for one attempt: [`POD_NAME_PREFIX`] and the first
/// [`POD_NAME_KEY_BYTES`] bytes of the attempt's digest in lowercase hexadecimal, so a
/// lookup after a crash finds the pod by the attempt alone. The key is cut to 128 bits
/// so the whole name stays within the 51 characters neocloud's pod names already use.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct PodName(String);

impl PodName {
    /// The pod name for `attempt`.
    pub fn for_attempt(attempt: &AttemptId) -> Self {
        let key: Vec<u8> = attempt
            .digest()
            .as_bytes()
            .iter()
            .take(POD_NAME_KEY_BYTES)
            .copied()
            .collect();
        Self(format!("{POD_NAME_PREFIX}{}", hex::encode(key)))
    }

    /// The name as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether a name RunPod listed is this one, compared as RunPod may store it:
    /// trimmed and in any letter case.
    pub fn carried_by(&self, listed: &str) -> bool {
        listed.trim().eq_ignore_ascii_case(&self.0)
    }
}

impl fmt::Debug for PodName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PodName({})", self.0)
    }
}

impl fmt::Display for PodName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A pod's `desiredStatus` as RunPod reports it. Any other value is unknown, and a
/// lookup that depends on it is uncertain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PodStatus {
    Created,
    Running,
    Restarting,
    Exited,
    Paused,
    Dead,
    Terminated,
}

impl PodStatus {
    const ALL: [Self; 7] = [
        Self::Created,
        Self::Running,
        Self::Restarting,
        Self::Exited,
        Self::Paused,
        Self::Dead,
        Self::Terminated,
    ];

    /// RunPod's word for the status.
    pub const fn word(self) -> &'static str {
        match self {
            Self::Created => "CREATED",
            Self::Running => "RUNNING",
            Self::Restarting => "RESTARTING",
            Self::Exited => "EXITED",
            Self::Paused => "PAUSED",
            Self::Dead => "DEAD",
            Self::Terminated => "TERMINATED",
        }
    }

    /// Reads RunPod's word, in any letter case; `None` for any other text.
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|status| status.word().eq_ignore_ascii_case(text))
    }

    /// Whether a pod in this status still exists and may bill. Only `TERMINATED` is gone:
    /// a stopped (`EXITED`) or `DEAD` pod keeps its disk and needs removing.
    pub const fn exists(self) -> bool {
        !matches!(self, Self::Terminated)
    }
}
