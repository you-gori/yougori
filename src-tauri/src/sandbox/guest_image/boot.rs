//! What the host hands the hypervisor and what it booted, against the selected manifest
//! (§8.3, line 2453: "Bind the exact opened artifact to the verified identity to avoid
//! replacement between verification and launch"; VM-CP-05, line 3155: host corroboration
//! "the booted root image digest and the kernel build record ... match the signed
//! manifest"; VM-CP-17, line 3167: "the next generation boots the signed base whose
//! digest the host verifies at launch"; VM-CP-23, line 3173: a one-byte change in the
//! root image and a mixed-version component set "are refused at the launch boundary").
//!
//! A [`HostArtifact`] is the host's own computation of one artifact's content key and
//! length: from bytes it holds, from a stream it reads, or from a key the host computed
//! or the catalog checked. It has no `Deserialize`, so nothing a guest sends becomes
//! one. A [`BootSet`] is the artifacts of one boot by role.
//!
//! - [`SelectedImage::admit_boot`]: the launch boundary. The set must be exactly the
//!   manifest's artifacts, role by role and byte for byte; a missing, extra or different
//!   artifact is refused, so a one-byte change, an artifact of another release or any
//!   artifact the manifest does not list never boots.
//! - [`SelectedImage::check_boot`]: the booted-image check, an observation rather than a
//!   gate: every role compared, nothing refused.
//! - [`SelectedImage::host_corroboration`]: V15's `HostCorroboration` of what was booted.
//!   The kernel build record bound to the booted kernel is the manifest's when the
//!   booted kernel is the manifest's kernel; for any other kernel the host knows no
//!   option, so the record lists none and every option is unknown.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Read;

use serde::Serialize;

use super::record::ArtifactRole;
use super::select::SelectedImage;
use crate::foundation::ids::{ContentHasher, ContentKey, ContentLengthError};
use crate::sandbox_contract::confinement::{
    HostCorroboration, KernelBuildRecord, KernelOption, KernelSetting, OptionState,
};

/// The read size of [`HostArtifact::read`].
const READ_CHUNK_BYTES: usize = 64 * 1024;

/// The host's own computation of one artifact's identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct HostArtifact {
    content_key: ContentKey,
    length_bytes: u64,
}

/// Why the host could not compute an artifact's identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum ReadError {
    /// The stream ended before, or ran past, the length given.
    Length {
        declared: u64,
        seen: u64,
    },
    Unreadable {
        detail: String,
    },
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length { declared, seen } => write!(
                f,
                "the artifact was given as {declared} bytes and {seen} were read"
            ),
            Self::Unreadable { detail } => write!(f, "the artifact could not be read: {detail}"),
        }
    }
}

impl std::error::Error for ReadError {}

impl From<ContentLengthError> for ReadError {
    fn from(error: ContentLengthError) -> Self {
        Self::Length {
            declared: error.declared,
            seen: error.seen,
        }
    }
}

impl HostArtifact {
    /// A key and length the host computed itself, or read from the catalog, which
    /// checks every byte against the key. Only host code calls this.
    pub const fn host_observed(content_key: ContentKey, length_bytes: u64) -> Self {
        Self {
            content_key,
            length_bytes,
        }
    }

    /// The identity of `bytes`.
    pub fn of_bytes(bytes: &[u8]) -> Self {
        Self {
            content_key: ContentKey::of(bytes),
            length_bytes: bytes.len() as u64,
        }
    }

    /// Reads `reader` to its end as an artifact of `length_bytes` (the file's length as
    /// the host found it), hashing as it reads; a longer stream is refused as soon as it
    /// passes the length, a shorter one at its end.
    pub fn read(reader: &mut dyn Read, length_bytes: u64) -> Result<Self, ReadError> {
        let mut hasher = ContentHasher::new(length_bytes);
        let mut chunk = vec![0u8; READ_CHUNK_BYTES];
        loop {
            let count = match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(count) => count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    return Err(ReadError::Unreadable {
                        detail: error.to_string(),
                    })
                }
            };
            hasher.update(chunk.get(..count).unwrap_or_default())?;
        }
        Ok(Self {
            content_key: hasher.finish()?,
            length_bytes,
        })
    }

    pub const fn content_key(&self) -> ContentKey {
        self.content_key
    }

    pub const fn length_bytes(&self) -> u64 {
        self.length_bytes
    }
}

/// The artifacts of one boot, by role, as the host computed them.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct BootSet {
    artifacts: BTreeMap<ArtifactRole, HostArtifact>,
}

impl BootSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// The set with `artifact` in `role`, replacing what was there.
    pub fn with(mut self, role: ArtifactRole, artifact: HostArtifact) -> Self {
        self.artifacts.insert(role, artifact);
        self
    }

    pub fn artifact(&self, role: ArtifactRole) -> Option<&HostArtifact> {
        self.artifacts.get(&role)
    }

    pub fn artifacts(&self) -> &BTreeMap<ArtifactRole, HostArtifact> {
        &self.artifacts
    }
}

/// Why a boot set was refused at the launch boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum BootRefusal {
    /// The set has no artifact in a role the manifest lists.
    Missing { role: ArtifactRole },
    /// The set's artifact in this role is not the manifest's: other bytes or another
    /// length.
    Differs {
        role: ArtifactRole,
        expected: ContentKey,
        expected_bytes: u64,
        found: ContentKey,
        found_bytes: u64,
    },
    /// The set has an artifact in a role the manifest does not list.
    Unexpected { role: ArtifactRole },
}

impl fmt::Display for BootRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing { role } => write!(f, "the boot set has no {role}"),
            Self::Differs {
                role,
                expected,
                expected_bytes,
                found,
                found_bytes,
            } => write!(
                f,
                "the boot set's {role} is {found} ({found_bytes} bytes), not the signed \
                 {expected} ({expected_bytes} bytes)"
            ),
            Self::Unexpected { role } => {
                write!(f, "the boot set has a {role} the manifest does not list")
            }
        }
    }
}

impl std::error::Error for BootRefusal {}

/// One role of a booted-image check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum RoleCheck {
    Matches,
    Differs {
        expected: ContentKey,
        observed: ContentKey,
    },
    /// The manifest lists the role and the host observed nothing in it.
    NotObserved {
        expected: ContentKey,
    },
    /// The host observed an artifact in a role the manifest does not list.
    Unexpected {
        observed: ContentKey,
    },
}

/// The booted-image check of one boot: every role of the manifest or the boot, compared.
/// Serialize only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BootCheck {
    pub manifest: ContentKey,
    pub roles: BTreeMap<ArtifactRole, RoleCheck>,
}

impl BootCheck {
    /// Whether every role matched.
    pub fn matches(&self) -> bool {
        self.roles
            .values()
            .all(|check| matches!(check, RoleCheck::Matches))
    }
}

/// A boot set admitted at the launch boundary for one selected image. Built only by
/// [`SelectedImage::admit_boot`]; Serialize only, as the launch's record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AdmittedBoot {
    selected: SelectedImage,
    artifacts: BTreeMap<ArtifactRole, HostArtifact>,
}

impl AdmittedBoot {
    pub fn selected(&self) -> &SelectedImage {
        &self.selected
    }

    pub fn artifacts(&self) -> &BTreeMap<ArtifactRole, HostArtifact> {
        &self.artifacts
    }
}

fn identity(artifact: &HostArtifact) -> (ContentKey, u64) {
    (artifact.content_key, artifact.length_bytes)
}

impl SelectedImage {
    /// Admits `boot` for this image if it holds exactly the manifest's artifacts, or
    /// refuses with the first difference in role order. The selection is consumed: one
    /// selection admits one boot.
    pub fn admit_boot(self, boot: &BootSet) -> Result<AdmittedBoot, BootRefusal> {
        let listed = self.verified().manifest().artifacts();
        for role in ArtifactRole::ALL {
            match (listed.get(&role), boot.artifact(role)) {
                (None, None) => {}
                (Some(_), None) => return Err(BootRefusal::Missing { role }),
                (None, Some(_)) => return Err(BootRefusal::Unexpected { role }),
                (Some(expected), Some(found)) => {
                    if (expected.content_key, expected.length_bytes) != identity(found) {
                        return Err(BootRefusal::Differs {
                            role,
                            expected: expected.content_key,
                            expected_bytes: expected.length_bytes,
                            found: found.content_key,
                            found_bytes: found.length_bytes,
                        });
                    }
                }
            }
        }
        Ok(AdmittedBoot {
            artifacts: boot.artifacts.clone(),
            selected: self,
        })
    }

    /// Compares what the host observed it booted with the manifest, role by role.
    pub fn check_boot(&self, booted: &BootSet) -> BootCheck {
        let listed = self.verified().manifest().artifacts();
        let roles = ArtifactRole::ALL
            .into_iter()
            .filter_map(|role| {
                let check = match (listed.get(&role), booted.artifact(role)) {
                    (None, None) => return None,
                    (Some(expected), None) => RoleCheck::NotObserved {
                        expected: expected.content_key,
                    },
                    (None, Some(found)) => RoleCheck::Unexpected {
                        observed: found.content_key,
                    },
                    (Some(expected), Some(found)) => {
                        if (expected.content_key, expected.length_bytes) == identity(found) {
                            RoleCheck::Matches
                        } else {
                            RoleCheck::Differs {
                                expected: expected.content_key,
                                observed: found.content_key,
                            }
                        }
                    }
                };
                Some((role, check))
            })
            .collect();
        BootCheck {
            manifest: self.manifest(),
            roles,
        }
    }

    /// V15's host corroboration of `booted`, with the kernel settings the host configured
    /// as boot arguments (recorded there, never accepted as enforced). `None` when the
    /// host observed no root image or no kernel, since there is nothing to corroborate.
    pub fn host_corroboration(
        &self,
        booted: &BootSet,
        boot_arguments: impl IntoIterator<Item = KernelSetting>,
    ) -> Option<HostCorroboration> {
        let root = booted.artifact(ArtifactRole::RootImage)?;
        let kernel = booted.artifact(ArtifactRole::Kernel)?;
        let manifest = self.verified().manifest();
        let signed_kernel = manifest.artifact(ArtifactRole::Kernel);
        let record = match signed_kernel {
            Some(expected) if (expected.content_key, expected.length_bytes) == identity(kernel) => {
                manifest.kernel().clone()
            }
            _ => KernelBuildRecord::new(
                *kernel.content_key.digest(),
                Vec::<(KernelOption, OptionState)>::new(),
            )
            .ok()?,
        };
        Some(HostCorroboration::host_observed(
            *root.content_key.digest(),
            record,
            boot_arguments,
        ))
    }
}
