//! The reproducible build record of one guest image build (VM-W05, line 2590: "Pinned
//! guest image profiles and build records ... reproducibility differences recorded";
//! VM-W46, line 2669: "reproducible inputs"; §8.3, line 2459: reproducibility "improves
//! provenance" and proves no absence of malicious code; VM-R89, line 2954).
//!
//! A record names every input of the build by content key and true length: the
//! repository commit, the fixed source date, the upstream sources, the toolchain, the
//! kernel configuration and the package lock, then the build commands as data (each
//! step's program, argument vector and environment, in order) and the artifacts the
//! build produced (root image, kernel, initrd, firmware and profile) by version, content
//! key and length. A record describes a build; nothing here runs one.
//!
//! [`BuildRecord::build_inputs`] gives the `sandbox::trust` [`BuildInputs`] a pinned
//! configuration row carries for each guest component: the commit, and one digest each
//! over the toolchain, the configuration inputs and the steps. Outputs are not part of
//! it, so a rebuild from the same inputs has the same build inputs
//! ([`compare_rebuild`](super::compare_rebuild)).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize, Serializer};

use super::canonical::{self, DocumentError, GUEST_IMAGE_FORMAT};
use super::text::{
    BuildArgument, EnvironmentName, EnvironmentValue, ImageName, InputName, InputVersion,
};
use crate::foundation::ids::{ContentKey, Digest, DigestBuilder};
use crate::foundation::report::CommitHash;
use crate::sandbox::trust::{
    Architecture, BuildInputs, ComponentKind, ComponentVersion, UnixSeconds,
};

/// Largest build record read.
pub const MAX_RECORD_BYTES: usize = 1 << 20;
/// Most upstream sources one record lists.
pub const MAX_SOURCES: usize = 256;
/// Most tools one record lists.
pub const MAX_TOOLS: usize = 128;
/// Most packages one package lock lists.
pub const MAX_PACKAGES: usize = 4096;
/// Most build steps one record lists.
pub const MAX_STEPS: usize = 256;
/// Most arguments one step lists.
pub const MAX_STEP_ARGUMENTS: usize = 256;
/// Most environment variables one step sets.
pub const MAX_STEP_ENVIRONMENT: usize = 64;

/// Domain of the toolchain digest in [`BuildInputs::toolchain`].
pub const TOOLCHAIN_DOMAIN: &str = "yougori/sandbox/guest-image/toolchain/v1";
/// Domain of the configuration digest in [`BuildInputs::configuration`].
pub const CONFIGURATION_DOMAIN: &str = "yougori/sandbox/guest-image/configuration/v1";
/// Domain of the builder digest (the steps) in [`BuildInputs::builder`].
pub const BUILDER_DOMAIN: &str = "yougori/sandbox/guest-image/builder/v1";

/// What one produced artifact is to the guest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactRole {
    /// The read-only root image the guest boots from.
    RootImage,
    /// The guest kernel the hypervisor loads.
    Kernel,
    /// The initial ramdisk loaded with the kernel.
    Initrd,
    /// The firmware that boots the guest, for firmware boot only.
    Firmware,
    /// A profile document shipped beside the image, such as the sealed guest policies
    /// its agent installs (`sandbox_contract::guest_policy`).
    Profile,
}

impl ArtifactRole {
    /// Every role.
    pub const ALL: [Self; 5] = [
        Self::RootImage,
        Self::Kernel,
        Self::Initrd,
        Self::Firmware,
        Self::Profile,
    ];

    /// The roles every build produces.
    pub const REQUIRED: [Self; 2] = [Self::RootImage, Self::Kernel];

    pub const fn tag(self) -> &'static str {
        match self {
            Self::RootImage => "root_image",
            Self::Kernel => "kernel",
            Self::Initrd => "initrd",
            Self::Firmware => "firmware",
            Self::Profile => "profile",
        }
    }

    /// The component of a pinned configuration row that pins this role. Every role has
    /// one, so a row pins each artifact a release ships, the initrd and the profile
    /// included (VM-W46, line 2669).
    pub const fn pinned_kind(self) -> ComponentKind {
        match self {
            Self::RootImage => ComponentKind::GuestImage,
            Self::Kernel => ComponentKind::GuestKernel,
            Self::Initrd => ComponentKind::GuestInitrd,
            Self::Firmware => ComponentKind::Firmware,
            Self::Profile => ComponentKind::GuestProfile,
        }
    }

    /// [`Self::pinned_kind`], kept for existing callers; it is `Some` for every role.
    pub const fn component(self) -> Option<ComponentKind> {
        Some(self.pinned_kind())
    }
}

impl fmt::Display for ArtifactRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.tag())
    }
}

/// One input held as bytes, by content key and true length.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileInput {
    pub content_key: ContentKey,
    pub length_bytes: u64,
}

/// One upstream source, such as a kernel source archive or a base root filesystem.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceInput {
    pub name: InputName,
    pub content_key: ContentKey,
    pub length_bytes: u64,
}

/// One tool of the toolchain, such as a compiler or `mkfs.erofs`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolInput {
    pub name: InputName,
    pub version: InputVersion,
    pub content_key: ContentKey,
    pub length_bytes: u64,
}

/// One locked package installed into the image.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageInput {
    pub name: InputName,
    pub version: InputVersion,
    pub content_key: ContentKey,
    pub length_bytes: u64,
}

/// One build command as data: the tool it runs, its argument vector, run without a
/// shell, and the environment it is given (nothing else is inherited).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildStep {
    pub name: InputName,
    /// A tool of the record's toolchain.
    pub program: InputName,
    pub arguments: Vec<BuildArgument>,
    pub environment: BTreeMap<EnvironmentName, EnvironmentValue>,
}

/// Every input of one build.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildInputSet {
    /// The repository commit the build ran from; it covers the build scripts, the
    /// guest agent's sources and the image recipes.
    pub repository: CommitHash,
    /// The fixed time every step builds with (`SOURCE_DATE_EPOCH`).
    pub source_date_epoch: UnixSeconds,
    /// Upstream sources, sorted by name.
    pub sources: Vec<SourceInput>,
    /// The toolchain, sorted by name.
    pub toolchain: Vec<ToolInput>,
    /// The kernel configuration file the kernel was built with.
    pub kernel_configuration: FileInput,
    /// The package lock: every package installed, sorted by name.
    pub packages: Vec<PackageInput>,
}

/// One artifact the build produced.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProducedArtifact {
    pub version: ComponentVersion,
    pub content_key: ContentKey,
    pub length_bytes: u64,
}

/// The data of a build record, as written. [`BuildRecord::new`] checks it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordDocument {
    pub format: u64,
    pub image: ImageName,
    pub architecture: Architecture,
    pub inputs: BuildInputSet,
    /// The build steps, in the order they run.
    pub steps: Vec<BuildStep>,
    pub artifacts: BTreeMap<ArtifactRole, ProducedArtifact>,
}

/// A list of a record that names its entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordList {
    Sources,
    Toolchain,
    Packages,
    Steps,
}

impl RecordList {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Sources => "sources",
            Self::Toolchain => "toolchain",
            Self::Packages => "packages",
            Self::Steps => "steps",
        }
    }
}

/// Why a build record was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum RecordError {
    Document {
        error: DocumentError,
    },
    /// A list holds more entries than its bound.
    TooMany {
        list: RecordList,
        max: usize,
    },
    /// A name appears twice in one list.
    Duplicate {
        list: RecordList,
        name: InputName,
    },
    /// The record lists no build step.
    NoSteps,
    /// A step runs a program the toolchain does not list.
    UnknownProgram {
        step: InputName,
        program: InputName,
    },
    /// A step has more arguments or environment variables than the bounds.
    StepTooLarge {
        step: InputName,
    },
    /// The build produced no artifact in a role every build produces.
    MissingArtifact {
        role: ArtifactRole,
    },
    /// An artifact or input of zero bytes.
    Empty {
        what: &'static str,
    },
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Document { error } => write!(f, "{error}"),
            Self::TooMany { list, max } => {
                write!(
                    f,
                    "the record's {} list holds more than {max} entries",
                    list.tag()
                )
            }
            Self::Duplicate { list, name } => {
                write!(
                    f,
                    "{name} appears twice in the record's {} list",
                    list.tag()
                )
            }
            Self::NoSteps => f.write_str("the record lists no build step"),
            Self::UnknownProgram { step, program } => write!(
                f,
                "build step {step} runs {program}, which the toolchain does not list"
            ),
            Self::StepTooLarge { step } => write!(
                f,
                "build step {step} has more than {MAX_STEP_ARGUMENTS} arguments or \
                 {MAX_STEP_ENVIRONMENT} environment variables"
            ),
            Self::MissingArtifact { role } => write!(f, "the build produced no {role}"),
            Self::Empty { what } => write!(f, "the record's {what} is empty"),
        }
    }
}

impl std::error::Error for RecordError {}

impl From<DocumentError> for RecordError {
    fn from(error: DocumentError) -> Self {
        Self::Document { error }
    }
}

/// A checked build record with its canonical bytes and content key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildRecord {
    document: RecordDocument,
    bytes: Vec<u8>,
    key: ContentKey,
}

impl BuildRecord {
    /// Checks `document`: the format, the list bounds, unique names (lists are sorted
    /// by name here), at least one step, every step's program in the toolchain, the
    /// root image and kernel produced, and nothing of zero bytes.
    pub fn new(mut document: RecordDocument) -> Result<Self, RecordError> {
        if document.format != GUEST_IMAGE_FORMAT {
            return Err(DocumentError::UnsupportedFormat {
                found: document.format,
            }
            .into());
        }
        let inputs = &mut document.inputs;
        sort_unique(
            &mut inputs.sources,
            RecordList::Sources,
            MAX_SOURCES,
            |source| &source.name,
        )?;
        sort_unique(
            &mut inputs.toolchain,
            RecordList::Toolchain,
            MAX_TOOLS,
            |tool| &tool.name,
        )?;
        sort_unique(
            &mut inputs.packages,
            RecordList::Packages,
            MAX_PACKAGES,
            |package| &package.name,
        )?;
        if inputs.kernel_configuration.length_bytes == 0 {
            return Err(RecordError::Empty {
                what: "kernel configuration",
            });
        }
        let empty_input = inputs
            .sources
            .iter()
            .map(|source| source.length_bytes)
            .chain(inputs.toolchain.iter().map(|tool| tool.length_bytes))
            .chain(inputs.packages.iter().map(|package| package.length_bytes))
            .any(|length| length == 0);
        if empty_input {
            return Err(RecordError::Empty { what: "input" });
        }
        check_steps(&document.steps, &document.inputs.toolchain)?;
        for role in ArtifactRole::REQUIRED {
            if !document.artifacts.contains_key(&role) {
                return Err(RecordError::MissingArtifact { role });
            }
        }
        if document
            .artifacts
            .values()
            .any(|artifact| artifact.length_bytes == 0)
        {
            return Err(RecordError::Empty { what: "artifact" });
        }
        let bytes = canonical::encode(&document)?;
        let key = ContentKey::of(&bytes);
        Ok(Self {
            document,
            bytes,
            key,
        })
    }

    /// Reads a record from its canonical bytes, strictly ([`canonical`](super::canonical)).
    pub fn from_canonical(bytes: &[u8]) -> Result<Self, RecordError> {
        let document: RecordDocument = canonical::decode(bytes, MAX_RECORD_BYTES)?;
        let record = Self::new(document)?;
        canonical::require_canonical(bytes, &record.bytes)?;
        Ok(record)
    }

    pub fn document(&self) -> &RecordDocument {
        &self.document
    }

    /// The canonical bytes.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The record's identity: the content key of its canonical bytes.
    pub fn content_key(&self) -> ContentKey {
        self.key
    }

    pub fn image(&self) -> &ImageName {
        &self.document.image
    }

    pub fn architecture(&self) -> Architecture {
        self.document.architecture
    }

    pub fn artifacts(&self) -> &BTreeMap<ArtifactRole, ProducedArtifact> {
        &self.document.artifacts
    }

    pub fn artifact(&self, role: ArtifactRole) -> Option<&ProducedArtifact> {
        self.document.artifacts.get(&role)
    }

    /// One digest over the toolchain: every tool's name, version, content key and length.
    pub fn toolchain_digest(&self) -> Digest {
        let toolchain = &self.document.inputs.toolchain;
        toolchain
            .iter()
            .fold(
                DigestBuilder::new(TOOLCHAIN_DOMAIN).u64(toolchain.len() as u64),
                |builder, tool| {
                    builder
                        .str(tool.name.as_str())
                        .str(tool.version.as_str())
                        .digest(tool.content_key.digest())
                        .u64(tool.length_bytes)
                },
            )
            .finish()
    }

    /// One digest over the configuration inputs: the architecture, the source date, the
    /// kernel configuration, the upstream sources and the package lock.
    pub fn configuration_digest(&self) -> Digest {
        let inputs = &self.document.inputs;
        let builder = DigestBuilder::new(CONFIGURATION_DOMAIN)
            .str(self.document.architecture.tag())
            .u64(inputs.source_date_epoch.get())
            .digest(inputs.kernel_configuration.content_key.digest())
            .u64(inputs.kernel_configuration.length_bytes)
            .u64(inputs.sources.len() as u64);
        let builder = inputs.sources.iter().fold(builder, |builder, source| {
            builder
                .str(source.name.as_str())
                .digest(source.content_key.digest())
                .u64(source.length_bytes)
        });
        inputs
            .packages
            .iter()
            .fold(
                builder.u64(inputs.packages.len() as u64),
                |builder, package| {
                    builder
                        .str(package.name.as_str())
                        .str(package.version.as_str())
                        .digest(package.content_key.digest())
                        .u64(package.length_bytes)
                },
            )
            .finish()
    }

    /// One digest over the build commands: every step's name, program, arguments and
    /// environment, in order.
    pub fn builder_digest(&self) -> Digest {
        let steps = &self.document.steps;
        steps
            .iter()
            .fold(
                DigestBuilder::new(BUILDER_DOMAIN).u64(steps.len() as u64),
                |builder, step| {
                    let builder = step
                        .arguments
                        .iter()
                        .fold(
                            builder
                                .str(step.name.as_str())
                                .str(step.program.as_str())
                                .u64(step.arguments.len() as u64),
                            |builder, argument| builder.str(argument.as_str()),
                        )
                        .u64(step.environment.len() as u64);
                    step.environment
                        .iter()
                        .fold(builder, |builder, (name, value)| {
                            builder.str(name.as_str()).str(value.as_str())
                        })
                },
            )
            .finish()
    }

    /// The build inputs a pinned configuration row carries for every guest component
    /// this build produced (VM-W46).
    pub fn build_inputs(&self) -> BuildInputs {
        BuildInputs {
            source: self.document.inputs.repository.clone(),
            toolchain: self.toolchain_digest(),
            configuration: self.configuration_digest(),
            builder: self.builder_digest(),
        }
    }
}

impl Serialize for BuildRecord {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.document.serialize(serializer)
    }
}

/// Sorts `entries` by name and refuses a list over `max` or with a name twice.
fn sort_unique<T>(
    entries: &mut [T],
    list: RecordList,
    max: usize,
    name: impl Fn(&T) -> &InputName,
) -> Result<(), RecordError> {
    if entries.len() > max {
        return Err(RecordError::TooMany { list, max });
    }
    entries.sort_by(|left, right| name(left).cmp(name(right)));
    match entries
        .windows(2)
        .find(|pair| name(&pair[0]) == name(&pair[1]))
    {
        Some(pair) => Err(RecordError::Duplicate {
            list,
            name: name(&pair[0]).clone(),
        }),
        None => Ok(()),
    }
}

fn check_steps(steps: &[BuildStep], toolchain: &[ToolInput]) -> Result<(), RecordError> {
    if steps.is_empty() {
        return Err(RecordError::NoSteps);
    }
    if steps.len() > MAX_STEPS {
        return Err(RecordError::TooMany {
            list: RecordList::Steps,
            max: MAX_STEPS,
        });
    }
    let tools: BTreeSet<&InputName> = toolchain.iter().map(|tool| &tool.name).collect();
    let mut names = BTreeSet::new();
    for step in steps {
        if !names.insert(&step.name) {
            return Err(RecordError::Duplicate {
                list: RecordList::Steps,
                name: step.name.clone(),
            });
        }
        if !tools.contains(&step.program) {
            return Err(RecordError::UnknownProgram {
                step: step.name.clone(),
                program: step.program.clone(),
            });
        }
        if step.arguments.len() > MAX_STEP_ARGUMENTS
            || step.environment.len() > MAX_STEP_ENVIRONMENT
        {
            return Err(RecordError::StepTooLarge {
                step: step.name.clone(),
            });
        }
    }
    Ok(())
}
