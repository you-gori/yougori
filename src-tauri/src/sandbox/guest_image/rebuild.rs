//! Reproducibility differences between two builds (VM-W05, line 2590: acceptance
//! "reproducibility differences recorded"; §8.3, line 2459: reproducibility improves
//! provenance and proves no absence of malicious code).
//!
//! [`compare_rebuild`] lists every input part that differs and every artifact that a
//! rebuild produced differently, missed or added. Only a rebuild from the same inputs
//! tests reproducibility: when an input differs the report says so
//! ([`RebuildReport::same_inputs`]) and its artifact differences are expected, not a
//! finding.

use serde::Serialize;

use super::record::{ArtifactRole, BuildRecord, ProducedArtifact};
use crate::foundation::ids::ContentKey;

/// One part of a build's inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InputPart {
    Image,
    Architecture,
    Repository,
    SourceDateEpoch,
    Sources,
    Toolchain,
    KernelConfiguration,
    Packages,
    Steps,
}

/// One difference between a build and its rebuild.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "difference", rename_all = "snake_case")]
pub enum RebuildDifference {
    /// The rebuild ran with other inputs in this part.
    Input { part: InputPart },
    /// The rebuild produced other bytes or another version in this role.
    Artifact {
        role: ArtifactRole,
        original: ProducedArtifact,
        rebuilt: ProducedArtifact,
    },
    /// The rebuild produced nothing in a role the original produced.
    ArtifactMissing { role: ArtifactRole },
    /// The rebuild produced an artifact in a role the original did not.
    ArtifactAdded { role: ArtifactRole },
}

/// What a rebuild reproduced. Serialize only: it is computed, never read back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RebuildReport {
    pub original: ContentKey,
    pub rebuilt: ContentKey,
    pub differences: Vec<RebuildDifference>,
}

impl RebuildReport {
    /// Whether the rebuild ran with the same inputs, so that it tests reproducibility.
    pub fn same_inputs(&self) -> bool {
        !self
            .differences
            .iter()
            .any(|difference| matches!(difference, RebuildDifference::Input { .. }))
    }

    /// Whether the rebuild ran with the same inputs and produced the same artifacts.
    pub fn reproduced(&self) -> bool {
        self.differences.is_empty()
    }
}

/// Compares a build with a rebuild: inputs part by part, then artifacts role by role.
pub fn compare_rebuild(original: &BuildRecord, rebuilt: &BuildRecord) -> RebuildReport {
    let (left, right) = (original.document(), rebuilt.document());
    let (inputs, again) = (&left.inputs, &right.inputs);
    let parts = [
        (InputPart::Image, left.image == right.image),
        (
            InputPart::Architecture,
            left.architecture == right.architecture,
        ),
        (InputPart::Repository, inputs.repository == again.repository),
        (
            InputPart::SourceDateEpoch,
            inputs.source_date_epoch == again.source_date_epoch,
        ),
        (InputPart::Sources, inputs.sources == again.sources),
        (InputPart::Toolchain, inputs.toolchain == again.toolchain),
        (
            InputPart::KernelConfiguration,
            inputs.kernel_configuration == again.kernel_configuration,
        ),
        (InputPart::Packages, inputs.packages == again.packages),
        (InputPart::Steps, left.steps == right.steps),
    ];
    let mut differences: Vec<RebuildDifference> = parts
        .into_iter()
        .filter(|(_, same)| !same)
        .map(|(part, _)| RebuildDifference::Input { part })
        .collect();
    for role in ArtifactRole::ALL {
        match (original.artifact(role), rebuilt.artifact(role)) {
            (Some(first), Some(second)) if first != second => {
                differences.push(RebuildDifference::Artifact {
                    role,
                    original: first.clone(),
                    rebuilt: second.clone(),
                });
            }
            (Some(_), None) => differences.push(RebuildDifference::ArtifactMissing { role }),
            (None, Some(_)) => differences.push(RebuildDifference::ArtifactAdded { role }),
            _ => {}
        }
    }
    RebuildReport {
        original: original.content_key(),
        rebuilt: rebuilt.content_key(),
        differences,
    }
}
