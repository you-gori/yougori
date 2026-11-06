//! One launch's components from one release, exactly as its pinned row pins them
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md: §8.3 line 2453, "Pin
//! guest/kernel/hypervisor/helper builds and verify signed artifact metadata before
//! execution"; VM-W45, line 2668, "mixed-component updates rejected"; VM-W46, line 2669,
//! "Tests run against exact builds"; the update threat-model paragraph, line 2677,
//! "mix-and-match attacks"; VM-P23, line 2798, "mixed-version components fail verification
//! at the actual execution boundary"; M18D in docs/combined-plan-leftover-tasks.md, line
//! 292, from S08's note in `f0d2da4`, line 82).
//!
//! The update client verifies one target at a time. A launch takes several: the runtime,
//! jailer, guest kernel, guest image, firmware and helper its row of the
//! [`ConfigurationMatrix`] pins. Each can be verified and unrevoked while the set still
//! mixes releases (a kernel verified before a targets update and an image after it) or
//! leaves the row (a component it does not pin, or other bytes than it pins).
//! [`check_launch_set`] takes the row the launch selected and the [`VerifiedTarget`] of each
//! component, and admits the set only if:
//!
//! - the row is a valid pinned configuration ([`PinnedConfiguration::check`], as the matrix
//!   checked it when it was pinned);
//! - every component the row pins is presented exactly once, and nothing it does not pin;
//! - each target's content key and length are the row's pin for its kind;
//! - every target was verified under signed metadata, all of them under one snapshot version
//!   and one targets version, as the client wrote them from its trusted state into
//!   [`VerificationBasis::Signed`] at verification;
//! - none is among the revoked releases the caller passes (the client's now, so a release
//!   revoked since its verification is refused);
//! - all were verified under one assurance profile.
//!
//! The admission ([`LaunchSetAdmission`]) names the row's key and CORE-01 fingerprint, the
//! versions, the profile and each component's content key. A refusal lists every problem
//! found, each typed ([`LaunchSetProblem`]), in a fixed order: missing and duplicated kinds
//! in kind order, then each presented component's problems in the order presented, then
//! mixed versions, then mixed profiles.
//!
//! [`PersistedUpdateClient::admit_launch_set`] is the execution boundary for a whole launch.
//! At one time on the trust clock and against one trusted state it verifies every component
//! through the client, runs the check with every release the persisted client holds revoked
//! (those a list that no longer verifies keeps revoked included), opens each component's
//! bytes as its verified target, admits each through
//! [`UpdateClient::admit_launch`](crate::sandbox::trust::UpdateClient::admit_launch), and
//! registers the admissions together under the execution in [`RunningLaunches`], so a
//! revocation of any component names the launch. Any refusal registers nothing.
//! [`PersistedUpdateClient::end_launch_set`] removes them when the launch ends.
//!
//! Limits, by design:
//!
//! - **Versions, not files.** [`VerificationBasis::Signed`] carries metadata versions, not
//!   the files. The client accepts a timestamp that references a snapshot at the version it
//!   already trusts with other bytes, and a snapshot that references targets at the trusted
//!   version with other bytes, so two targets verified at different times can name equal
//!   versions from different files. The pin check still binds every component to the row's
//!   bytes, and inside [`PersistedUpdateClient::admit_launch_set`] the binding is exact, as
//!   every component is verified against one state. For targets verified apart, an exact
//!   binding needs `sandbox::trust` to carry the references (version, length and digest) of
//!   the snapshot and targets files it trusted into [`VerificationBasis::Signed`].
//! - **Root and timestamp versions are not compared.** A root rotation that keeps the online
//!   keys, or a fresh timestamp over the same snapshot, serves the same release.
//! - **No developer build in a set.** An unsigned developer build
//!   ([`VerificationBasis::DeveloperUnsigned`]) was verified under no targets metadata, so a
//!   set holding one is refused; it stays on the single-artifact path
//!   ([`PersistedUpdateClient::admit_launch`]).
//! - **Names and classes are the caller's.** Which target carries a component kind, and as
//!   which artifact class it is opened, is the release layout's; nothing here maps a kind to
//!   a target. The pin's component version and the target's release label are different
//!   names and are not compared; the content key and length are.
//!
//! [`ConfigurationMatrix`]: crate::sandbox::trust::ConfigurationMatrix
//! [`RunningLaunches`]: super::RunningLaunches

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Serialize;

use super::persisted::{Halt, PersistedUpdateClient};
use crate::foundation::catalog::ArtifactClass;
use crate::foundation::evidence::{ConfigurationFingerprint, FingerprintError};
use crate::foundation::ids::{ContentKey, ExecutionId};
use crate::sandbox::trust::{
    AssuranceProfile, ComponentKind, ConfigurationKey, LaunchAdmission, MetadataVersion,
    OpenRefusal, OpenedArtifact, PinRefusal, PinnedConfiguration, TargetName, UpdateRefusal,
    VerificationBasis, VerifiedTarget,
};

/// The snapshot and targets versions a target was verified under.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct ReleaseBasis {
    pub snapshot_version: MetadataVersion,
    pub targets_version: MetadataVersion,
}

impl ReleaseBasis {
    /// The versions of a signed verification; `None` for an unsigned developer build.
    pub fn of(basis: &VerificationBasis) -> Option<Self> {
        match basis {
            VerificationBasis::Signed {
                snapshot_version,
                targets_version,
                ..
            } => Some(Self {
                snapshot_version: *snapshot_version,
                targets_version: *targets_version,
            }),
            VerificationBasis::DeveloperUnsigned => None,
        }
    }
}

impl fmt::Display for ReleaseBasis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "snapshot {} and targets {}",
            self.snapshot_version, self.targets_version
        )
    }
}

/// One component of a set that mixes versions, with the versions it was verified under.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ComponentBasis {
    pub kind: ComponentKind,
    pub name: TargetName,
    pub basis: ReleaseBasis,
}

/// One component of a set that mixes assurance profiles, with its profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ComponentProfile {
    pub kind: ComponentKind,
    pub name: TargetName,
    pub assurance: AssuranceProfile,
}

/// One reason a launch's components are not one release of its pinned row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum LaunchSetProblem {
    /// The row pins this component and the launch presents none.
    Missing { kind: ComponentKind },
    /// The launch presents this component more than once.
    Duplicate {
        kind: ComponentKind,
        names: Vec<TargetName>,
    },
    /// The row pins no component of this kind.
    Unpinned {
        kind: ComponentKind,
        name: TargetName,
    },
    /// The target's bytes are not the ones the row pins for its kind.
    PinMismatch {
        kind: ComponentKind,
        name: TargetName,
        pinned_content_key: ContentKey,
        pinned_length_bytes: u64,
        verified_content_key: ContentKey,
        verified_length_bytes: u64,
    },
    /// An unsigned developer build, verified under no targets metadata.
    Unsigned {
        kind: ComponentKind,
        name: TargetName,
    },
    /// The release is revoked, though it may have been verified before the revocation.
    Revoked {
        kind: ComponentKind,
        name: TargetName,
        content_key: ContentKey,
        reason: String,
    },
    /// The signed components were not all verified under one snapshot and one targets
    /// version: each of them, as presented, with its versions.
    MixedVersions { components: Vec<ComponentBasis> },
    /// The components were not all verified under one assurance profile: each of them, as
    /// presented, with its profile.
    MixedProfile { components: Vec<ComponentProfile> },
}

impl fmt::Display for LaunchSetProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing { kind } => {
                write!(f, "the row pins a {kind} and the launch presents none")
            }
            Self::Duplicate { kind, names } => {
                let names: Vec<&str> = names.iter().map(TargetName::as_str).collect();
                write!(
                    f,
                    "the launch presents {} {kind} components ({})",
                    names.len(),
                    names.join(", ")
                )
            }
            Self::Unpinned { kind, name } => write!(
                f,
                "target {name} is presented as the {kind}, which the row does not pin"
            ),
            Self::PinMismatch {
                kind,
                name,
                pinned_content_key,
                pinned_length_bytes,
                verified_content_key,
                verified_length_bytes,
            } => write!(
                f,
                "target {name} is {verified_length_bytes} bytes with content key {verified_content_key}; the row pins its {kind} as {pinned_length_bytes} bytes with content key {pinned_content_key}"
            ),
            Self::Unsigned { kind, name } => write!(
                f,
                "target {name} ({kind}) is an unsigned developer build, verified under no targets metadata"
            ),
            Self::Revoked {
                kind,
                name,
                content_key,
                reason,
            } => write!(
                f,
                "target {name} ({kind}) is release {content_key}, which is revoked: {reason}"
            ),
            Self::MixedVersions { components } => {
                let each: Vec<String> = components
                    .iter()
                    .map(|component| {
                        format!(
                            "{} {} under {}",
                            component.kind, component.name, component.basis
                        )
                    })
                    .collect();
                write!(
                    f,
                    "the components were verified under different release metadata: {}",
                    each.join(", ")
                )
            }
            Self::MixedProfile { components } => {
                let each: Vec<String> = components
                    .iter()
                    .map(|component| {
                        format!(
                            "{} {} under {}",
                            component.kind, component.name, component.assurance
                        )
                    })
                    .collect();
                write!(
                    f,
                    "the components were verified under different assurance profiles: {}",
                    each.join(", ")
                )
            }
        }
    }
}

/// Why a launch's components were not admitted as one release of its pinned row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LaunchSetRefusal {
    /// The row is not a valid pinned configuration; the matrix refuses it as well.
    Row { refusal: PinRefusal },
    /// The row's CORE-01 fingerprint could not be computed.
    Fingerprint { error: FingerprintError },
    /// The components are not one release of the row: every problem found, in the order
    /// the module documentation gives.
    Components {
        configuration: ConfigurationKey,
        problems: Vec<LaunchSetProblem>,
    },
}

impl fmt::Display for LaunchSetRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Row { refusal } => write!(f, "the pinned row is not valid: {refusal}"),
            Self::Fingerprint { error } => {
                write!(f, "the pinned row has no fingerprint: {error}")
            }
            Self::Components {
                configuration,
                problems,
            } => {
                let each: Vec<String> = problems.iter().map(ToString::to_string).collect();
                write!(
                    f,
                    "the launch's components are not one release of configuration {configuration}: {}",
                    each.join("; ")
                )
            }
        }
    }
}

impl std::error::Error for LaunchSetRefusal {}

/// A launch's components admitted as one release of its pinned row. Built only by
/// [`check_launch_set`]; serialize only, never read back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LaunchSetAdmission {
    configuration: ConfigurationKey,
    fingerprint: ConfigurationFingerprint,
    basis: ReleaseBasis,
    assurance: AssuranceProfile,
    components: BTreeMap<ComponentKind, ContentKey>,
}

impl LaunchSetAdmission {
    /// The key of the row the launch selected.
    pub fn configuration(&self) -> ConfigurationKey {
        self.configuration
    }

    /// The row's CORE-01 fingerprint, which evidence about this launch binds to.
    pub fn fingerprint(&self) -> ConfigurationFingerprint {
        self.fingerprint
    }

    /// The one snapshot and targets version every component was verified under.
    pub fn basis(&self) -> ReleaseBasis {
        self.basis
    }

    /// The one assurance profile every component was verified under.
    pub fn assurance(&self) -> AssuranceProfile {
        self.assurance
    }

    /// Each component's content key, by kind: exactly the kinds the row pins.
    pub fn components(&self) -> &BTreeMap<ComponentKind, ContentKey> {
        &self.components
    }
}

/// Admits `components`, each presented under the kind of `row` it stands for, as one
/// release of `row`, or refuses with every problem found. `revoked` is the revoked releases
/// in force now, by content key with the reason, such as
/// [`PersistedUpdateClient::revoked`] gives.
pub fn check_launch_set(
    row: &PinnedConfiguration,
    components: &[(ComponentKind, VerifiedTarget)],
    revoked: &BTreeMap<ContentKey, String>,
) -> Result<LaunchSetAdmission, LaunchSetRefusal> {
    row.check()
        .map_err(|refusal| LaunchSetRefusal::Row { refusal })?;
    let fingerprint = row
        .fingerprint()
        .map_err(|error| LaunchSetRefusal::Fingerprint { error })?;
    let mut problems = Vec::new();

    let mut presented: BTreeMap<ComponentKind, Vec<TargetName>> = BTreeMap::new();
    for (kind, target) in components {
        presented
            .entry(*kind)
            .or_default()
            .push(target.name().clone());
    }
    for kind in row.components.keys() {
        if !presented.contains_key(kind) {
            problems.push(LaunchSetProblem::Missing { kind: *kind });
        }
    }
    for (kind, names) in &presented {
        if names.len() > 1 {
            problems.push(LaunchSetProblem::Duplicate {
                kind: *kind,
                names: names.clone(),
            });
        }
    }

    for (kind, target) in components {
        let kind = *kind;
        let name = target.name().clone();
        match row.component(kind) {
            None => problems.push(LaunchSetProblem::Unpinned {
                kind,
                name: name.clone(),
            }),
            Some(pin) => {
                if pin.content_key != target.content_key()
                    || pin.length_bytes != target.length_bytes()
                {
                    problems.push(LaunchSetProblem::PinMismatch {
                        kind,
                        name: name.clone(),
                        pinned_content_key: pin.content_key,
                        pinned_length_bytes: pin.length_bytes,
                        verified_content_key: target.content_key(),
                        verified_length_bytes: target.length_bytes(),
                    });
                }
            }
        }
        if ReleaseBasis::of(target.basis()).is_none() {
            problems.push(LaunchSetProblem::Unsigned {
                kind,
                name: name.clone(),
            });
        }
        if let Some(reason) = revoked.get(&target.content_key()) {
            problems.push(LaunchSetProblem::Revoked {
                kind,
                name,
                content_key: target.content_key(),
                reason: reason.clone(),
            });
        }
    }

    let signed: Vec<ComponentBasis> = components
        .iter()
        .filter_map(|(kind, target)| {
            ReleaseBasis::of(target.basis()).map(|basis| ComponentBasis {
                kind: *kind,
                name: target.name().clone(),
                basis,
            })
        })
        .collect();
    let bases: BTreeSet<ReleaseBasis> = signed.iter().map(|component| component.basis).collect();
    if bases.len() > 1 {
        problems.push(LaunchSetProblem::MixedVersions { components: signed });
    }

    let profiles: BTreeSet<AssuranceProfile> = components
        .iter()
        .map(|(_, target)| target.assurance())
        .collect();
    if profiles.len() > 1 {
        problems.push(LaunchSetProblem::MixedProfile {
            components: components
                .iter()
                .map(|(kind, target)| ComponentProfile {
                    kind: *kind,
                    name: target.name().clone(),
                    assurance: target.assurance(),
                })
                .collect(),
        });
    }

    // With no problem, every pinned kind is presented once (a valid row pins at least the
    // runtime, kernel and image), all signed, under one basis and one profile.
    match (
        problems.is_empty(),
        bases.first().copied(),
        profiles.first().copied(),
    ) {
        (true, Some(basis), Some(assurance)) => Ok(LaunchSetAdmission {
            configuration: row.key,
            fingerprint,
            basis,
            assurance,
            components: components
                .iter()
                .map(|(kind, target)| (*kind, target.content_key()))
                .collect(),
        }),
        _ => Err(LaunchSetRefusal::Components {
            configuration: row.key,
            problems,
        }),
    }
}

/// One component a launch asks for: the kind of its pinned row it stands for, the target
/// that carries it in the release metadata, the class it is opened as, and its bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct LaunchComponent {
    pub kind: ComponentKind,
    pub name: TargetName,
    pub class: ArtifactClass,
    pub bytes: Vec<u8>,
}

impl fmt::Debug for LaunchComponent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LaunchComponent")
            .field("kind", &self.kind)
            .field("name", &self.name)
            .field("class", &self.class)
            .field("length_bytes", &self.bytes.len())
            .finish()
    }
}

/// A launch admitted through the persisted client as one release of its pinned row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmittedLaunchSet {
    pub execution: ExecutionId,
    /// The set's admission.
    pub admission: LaunchSetAdmission,
    /// The client's admission of each component at the execution boundary, by kind: what
    /// [`RunningLaunches`](super::RunningLaunches) holds for the execution, in this order.
    pub components: BTreeMap<ComponentKind, LaunchAdmission>,
    /// The verified bytes the launch takes, by kind.
    pub opened: BTreeMap<ComponentKind, OpenedArtifact>,
}

/// Why the persisted client did not admit a launch's components. Nothing was registered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LaunchSetError {
    /// The execution already has a running launch registered.
    AlreadyRunning { execution: ExecutionId },
    /// A reload failed, so the client is trusted for nothing.
    Halted { halt: Halt },
    /// The client refused a component's target, at verification or at the execution
    /// boundary.
    Component {
        kind: ComponentKind,
        name: TargetName,
        reason: UpdateRefusal,
    },
    /// The verified components are not one release of the pinned row.
    Set { refusal: LaunchSetRefusal },
    /// The bytes presented for a component are not its verified bytes.
    Open {
        kind: ComponentKind,
        name: TargetName,
        refusal: OpenRefusal,
    },
}

impl fmt::Display for LaunchSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyRunning { execution } => {
                write!(f, "execution {execution} already has a running launch")
            }
            Self::Halted { halt } => write!(f, "{halt}"),
            Self::Component { kind, name, reason } => {
                write!(f, "the {kind} (target {name}) was refused: {reason}")
            }
            Self::Set { refusal } => write!(f, "{refusal}"),
            Self::Open {
                kind,
                name,
                refusal,
            } => write!(f, "the {kind} (target {name}) did not open: {refusal}"),
        }
    }
}

impl std::error::Error for LaunchSetError {}

impl PersistedUpdateClient {
    /// Admits the launch of `execution` from `components`, which stand for the components
    /// of `row`, as one release of it, and registers the admission of every component under
    /// the execution until [`Self::end_launch_set`]. At one time and against one trusted
    /// state it verifies each component's target through the client, runs
    /// [`check_launch_set`] with every release held revoked ([`Self::revoked`]), opens each
    /// component's bytes as its verified target and admits each through the client. Refused
    /// while a reload has failed, as [`Self::admit_launch`] is; an execution has one running
    /// launch at a time; any refusal registers nothing.
    pub fn admit_launch_set(
        &mut self,
        execution: ExecutionId,
        row: &PinnedConfiguration,
        components: Vec<LaunchComponent>,
    ) -> Result<AdmittedLaunchSet, LaunchSetError> {
        if let Some(halt @ Halt::ReloadFailed { .. }) = self.halt() {
            return Err(LaunchSetError::Halted { halt: halt.clone() });
        }
        if !self.running().admissions(&execution).is_empty() {
            return Err(LaunchSetError::AlreadyRunning { execution });
        }
        let now = self.now();
        let revoked = self.revoked();
        let client = self.client();

        let mut verified = Vec::with_capacity(components.len());
        for component in &components {
            let target = client
                .verify_target(&component.name, component.class, now)
                .map_err(|reason| LaunchSetError::Component {
                    kind: component.kind,
                    name: component.name.clone(),
                    reason,
                })?;
            verified.push((component.kind, target));
        }
        let admission = check_launch_set(row, &verified, &revoked)
            .map_err(|refusal| LaunchSetError::Set { refusal })?;

        let mut admitted = BTreeMap::new();
        let mut opened = BTreeMap::new();
        for ((kind, target), component) in verified.into_iter().zip(components) {
            let artifact =
                target
                    .open(component.bytes)
                    .map_err(|refusal| LaunchSetError::Open {
                        kind,
                        name: component.name.clone(),
                        refusal,
                    })?;
            let launch = client.admit_launch(&artifact, now).map_err(|reason| {
                LaunchSetError::Component {
                    kind,
                    name: component.name,
                    reason,
                }
            })?;
            admitted.insert(kind, launch);
            opened.insert(kind, artifact);
        }

        self.running_mut()
            .register_all(execution.clone(), admitted.values().cloned().collect())
            .map_err(|refused| LaunchSetError::AlreadyRunning {
                execution: refused.execution,
            })?;
        Ok(AdmittedLaunchSet {
            execution,
            admission,
            components: admitted,
            opened,
        })
    }

    /// Removes the launch of `execution`, which ended, and returns every admission it held.
    pub fn end_launch_set(&mut self, execution: &ExecutionId) -> Vec<LaunchAdmission> {
        self.running_mut().end_all(execution)
    }
}
